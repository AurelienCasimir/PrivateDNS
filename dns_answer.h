#ifndef DNS_ANSWER
#define DNS_ANSWER

#if (HAVE_CONFIG_H)
#include "./include/config.h"
#endif
#include "libnet_test.h"
#ifdef __WIN32__
#include "./include/win32/getopt.h"
#endif

u_long dotToLong(char *ip);

u_long arrayToLong(char *ip);

int send_answer(char *dst_ip_array, char *src_ip_array, int dport, int sport, int dns_id, char *url, char *ip, int logfd);

#endif
