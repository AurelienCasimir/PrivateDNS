all: dns_answer.o xpir_proxy.o dns_answer.o add_db_entry
	gcc -Wall -o xpir_proxy xpir_proxy.o dns_answer.o -lnfnetlink -lnetfilter_queue -lnet

xpir_proxy.o : xpir_proxy.c
		gcc -Wall -c xpir_proxy.c -lnfnetlink -lnetfilter_queue

dns_answer.o : dns_answer.c
		gcc -Wall -c dns_answer.c -lnet

add_db_entry : add_db_entry.c
		gcc -Wall -o add_db_entry add_db_entry.c
