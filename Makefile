eap_proxy: eap_proxy.c eap_proxy.h logging.c logging.h
	cc -g eap_proxy.c logging.c -o eap_proxy -lpcap -lpthread
