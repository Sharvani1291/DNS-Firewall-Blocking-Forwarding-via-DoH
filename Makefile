all:
	gcc -g -o dns_forwarder dns_forwarder.c -lcurl -lssl -lcrypto