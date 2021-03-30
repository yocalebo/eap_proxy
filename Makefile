eapproxyd: eap_proxy.c logging.c logging.h
	cc -g eap_proxy.c logging.c -o eapproxyd -lpcap
