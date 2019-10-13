/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2019, Caleb St. John
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h> /* for exit() */
#include <string.h> /* for strlcpy */
#include <pcap.h> /* pcap functions */
#include <pthread.h> /* pthread library */
#include "eap_proxy.h" /* boilerplate structure */ 

#define BUFFER 9000 /* max bytes to capture for 1 packet */ 
#define PROMISCOUS 0 /* set promiscous mode for given interface */
#define TIMEOUT 10 /* read timeout in milliseconds */
#define LOOPFOREVER -1 /* loop forever in pcap_loop */

/* pcap_compile is not thread safe on openBSD because
 * of the version of libpcap that comes by default
 * so define a lock variable to be used when compiling
 * the filter to be applied to the pcap handle
 */
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void pkt_injection(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet_data);
void *pkt_capture(void *arg);

int main(int argc, char *argv[]) {

	struct data_list stuff; /* defined in eap_proxy.h */

	/* initialize stuff struct with zeros */
	memset(&stuff, 0, sizeof(stuff));

	/* ONT port settings */
	strlcpy(stuff.ifaces.ont.ont_dev, "vlan0", sizeof(stuff.ifaces.ont.ont_dev));
	strlcpy(stuff.ifaces.ont.uplink_dev, "em1", sizeof(stuff.ifaces.ont.uplink_dev));
	strlcpy(stuff.ifaces.ont.filter, "ether proto 0x888e", sizeof(stuff.ifaces.ont.filter));
	stuff.ifaces.ont.is_uplink = 0;

	/* create the thread for ONT port */
	if ((pthread_create(&stuff.threads.capture_loop_thread1, NULL,
			    &pkt_capture, &stuff.ifaces.ont)) != 0) {
		fprintf(stderr, "failed to create pthread for ont port\n");
		exit(1);
	}

	/* uplink port settings */
	strlcpy(stuff.ifaces.uplink.ont_dev, "em0", sizeof(stuff.ifaces.ont.ont_dev));
	strlcpy(stuff.ifaces.uplink.uplink_dev, "em1", sizeof(stuff.ifaces.ont.uplink_dev));
	strlcpy(stuff.ifaces.uplink.filter, "ether proto 0x888e", sizeof(stuff.ifaces.ont.filter));
	stuff.ifaces.uplink.is_uplink = 1;

	/* create the thread for uplink port */
	if ((pthread_create(&stuff.threads.capture_loop_thread2, NULL,
			    &pkt_capture, &stuff.ifaces.uplink)) != 0) {
		fprintf(stderr, "failed to create pthread for uplink port\n");
		exit(1);
	}

	/* wait for threads to exit */
	pthread_join(stuff.threads.capture_loop_thread1, NULL);
	pthread_join(stuff.threads.capture_loop_thread2, NULL);

	return 0;
}

void *pkt_capture(void *arg) {

	struct int_settings *ints = (struct int_settings* ) arg;
	struct bpf_program filter;
	pcap_t *pkt_handle;
	char err_buf[PCAP_ERRBUF_SIZE];
	char *capture_interface;
	char *inject_interface;

	if (ints->is_uplink == 1) {
		capture_interface = ints->uplink_dev;
		inject_interface = ints->ont_dev;
	}
	else if (ints->is_uplink == 0) {
		capture_interface = ints->ont_dev;
		inject_interface = ints->uplink_dev;
	}
	else {
		fprintf(stderr, "ints.is_uplink has incorrect value %d\n", ints->is_uplink);
		exit(1);
	}

	/* open em0 interface for live capture */
	if ((pkt_handle = pcap_open_live(capture_interface, BUFFER, PROMISCOUS, TIMEOUT, err_buf)) == NULL) {
		fprintf(stderr, "failed to open device with error %s\n", err_buf);
		exit(2);
	}
	/* only interested in inbound packets */
	if ((pcap_setdirection(pkt_handle, PCAP_D_IN)) == -1) {
		fprintf(stderr, "could not set direction on capture device.\n");
		pcap_close(pkt_handle);
		exit(2);
	}
	/* compile the filter to be applied to pcap_t handle */
	pthread_mutex_lock(&lock);
	if (pcap_compile(pkt_handle, &filter, ints->filter, 1, ints->ip) == -1) {
		fprintf(stderr, "invalid filter: %s\n", pcap_geterr(pkt_handle)); 
		pcap_close(pkt_handle);
		exit(2);
	}
	pthread_mutex_unlock(&lock);
	/* set filter */
	if ((pcap_setfilter(pkt_handle, &filter)) == -1) {
		fprintf(stderr, "failed to set filter with error: %s\n", pcap_geterr(pkt_handle));
		pcap_close(pkt_handle);
		exit(2);
	}

	/* process packets and then send them out other interface */
	pcap_loop(pkt_handle, LOOPFOREVER, pkt_injection, inject_interface);

	pcap_close(pkt_handle);
	return NULL;
}

void pkt_injection(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {

	char *inject_interface = user;
	char err_buf[PCAP_ERRBUF_SIZE];
	pcap_t *inject_handle;
	int res;

	/* setup the device to inject packets to */
	if ((inject_handle = pcap_open_live(inject_interface, BUFFER, PROMISCOUS, TIMEOUT, err_buf)) == NULL) {
		fprintf(stderr, "could not open device with error %s\n", err_buf);
		exit(2);
	}

	/* send our packets out */
	if ((res = pcap_inject(inject_handle, packet_data, packet_header->len) == -1)) {
		fprintf(stderr, "failed to write packet on interface\n");
		pcap_close(inject_handle);
		exit(2);
	}

}
