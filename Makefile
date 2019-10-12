eap_proxy: eap_proxy.c eap_proxy.h
	cc -g eap_proxy.c -o eap_proxy -lpcap -lpthread
