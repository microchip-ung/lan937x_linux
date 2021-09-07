CC = gcc

.PHONY: clean

all:
	$(CC) -o tsn_talker tsn_talker.c
	$(CC) -o tsn_listener tsn_listener.c
	$(CC) -o pkt_io pkt_io.c -lpthread
	$(CC) -o dsa_ver dsa_ver.c

clean:
	rm tsn_talker
