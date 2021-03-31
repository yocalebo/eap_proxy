/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2021, Caleb St. John
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
#include <stdio.h> /* STDOUT/IN/ERR */
#include <string.h> /* for strlcpy */
#include <unistd.h> /* fork/exec/close and friends */
#include <sys/stat.h> /* for umask */
#include <pcap.h> /* pcap api */
#include "logging.h" /*for log_* functions */

#define BUFFER 9000 /* max bytes to capture for 1 packet */ 
#define PROMISCOUS 1 /* set promiscous mode for given interface */
#define TIMEOUT 10 /* read timeout in milliseconds */
#define LOOPFOREVER -1 /* loop forever in pcap_loop */
#define FILTER "ether proto 0x888e" /* only care about EAPoL pkts */

void child_setup();
void pkt_injection(u_char *user, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data);
void pkt_capture(char *capture_int, char *inj_int);

int main(int argc, char *argv[]) {

	pid_t to_ont, to_att;

	/* fork 2 children (1 for each inteface) */
	(to_ont = fork()) && (to_att = fork());

	if ((to_ont < 0) || (to_att < 0)) {
		log_err("fork() failed");
		exit(EXIT_FAILURE);
	}
	else if (to_ont == 0) {
		/* name the child */
		strlcpy(argv[0], "TO_ATT", sizeof(argv[0]));
		child_setup();
		pkt_capture("em1", "vlan0");
	}
	else if (to_att == 0) {
		/* name the child */
		strlcpy(argv[0], "TO_ONT", sizeof(argv[0]));
		child_setup();
		pkt_capture("vlan0", "em1");
	}
	else {
		/* parent */
		exit(EXIT_SUCCESS);
	}

	return EXIT_SUCCESS;

}

void child_setup() {

	umask(0);

	if (setsid() < 0) {
		log_err("setsid() failed");
		exit(EXIT_FAILURE);
	}

	close(STDOUT_FILENO);
	close(STDIN_FILENO);
	close(STDERR_FILENO);
}

void pkt_capture(char *capture_int, char *inj_int) {

	struct bpf_program filter;
	bpf_u_int32 ip;
	pcap_t *pkt_handle = NULL;
	char err_buf[PCAP_ERRBUF_SIZE];

	/* open interface for live capture */
	if ((pkt_handle = pcap_open_live(capture_int, BUFFER, PROMISCOUS, TIMEOUT, err_buf)) == NULL) {
		log_err("failed to open device %s with error %s", capture_int, err_buf);
		exit(EXIT_FAILURE);
	}
	/* only interested in inbound packets */
	if ((pcap_setdirection(pkt_handle, PCAP_D_IN)) == -1) {
		log_err("could not set direction on capture device.");
		pcap_close(pkt_handle);
		exit(EXIT_FAILURE);
	}
	/* compile bpf filter */
	if (pcap_compile(pkt_handle, &filter, FILTER, 1, ip) == -1) {
		log_err("invalid filter: %s", pcap_geterr(pkt_handle)); 
		pcap_close(pkt_handle);
		exit(EXIT_FAILURE);
	}

	/* set bpf filter */
	if ((pcap_setfilter(pkt_handle, &filter)) == -1) {
		log_err("failed to set filter with error: %s", pcap_geterr(pkt_handle));
		pcap_close(pkt_handle);
		exit(EXIT_FAILURE);
	}

	/* process packets and then send them out other interface */
	pcap_loop(pkt_handle, LOOPFOREVER, pkt_injection, inj_int);
	pcap_close(pkt_handle);

}

void pkt_injection(u_char *user, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data) {

	char err_buf[PCAP_ERRBUF_SIZE];
	pcap_t *inj_handle = NULL;
	int res;

	/* setup the device to inject packets to */
	if ((inj_handle = pcap_open_live(user, BUFFER, PROMISCOUS, TIMEOUT, err_buf)) == NULL) {
		log_err("could not open device with error %s", err_buf);
		exit(EXIT_FAILURE);
	}

	/* send our packets out */
	if ((res = pcap_inject(inj_handle, pkt_data, pkt_hdr->len) == -1)) {
		log_err("failed to write packet on interface %s", user);
		pcap_close(inj_handle);
		exit(EXIT_FAILURE);
	}

}
