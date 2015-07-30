#include "dns_answer.h"

u_long dotToLong(char *ip)
{
	unsigned long value = 0; /* Total Value */
	unsigned char octet = 0; /* Octet Value */
	int i = strlen(ip) - 1; /* Index in ip */
	int m = 1; /* octet multiplier */
	int j;
	for (j=3; j >=0; j--){
		while ( ip[i] != '.' && ip[i] != '\0' ){
			octet += m * (ip[i] - '0');
			m *= 10;
			i--;
		}
		value += (octet << (8 * j));
		octet = 0;
		m = 1;
		i--;
	}
	return value;	
}

u_long arrayToLong(char *ip)
{
	unsigned long value = 0; /* Total Value */
	int j;
	for (j=3; j >=0; j--){
		value += (ip[j] << (8 * j));
	}
	return value;	
}

int send_answer(char *dst_ip_array, char *src_ip_array, int dport, int sport, int dns_id, char *query, char *req_ip, int logfd)
{
    char c;
    u_long src_ip = arrayToLong(src_ip_array), dst_ip = arrayToLong(dst_ip_array), requested_ip_long=dotToLong(req_ip);
    char requested_ip[4];
    u_short type = LIBNET_UDP_DNSV4_H;
    libnet_t *l;

    libnet_ptag_t ip;
    libnet_ptag_t ptag4; /* TCP or UDP ptag */
    libnet_ptag_t dns;
    
    char errbuf[LIBNET_ERRBUF_SIZE];
    char payload[1024];
    u_short payload_s;
    char log_buffer[500];
    int length = 0;

    /*
     *  Initialize the library.  Root priviledges are required.
     */
    l = libnet_init(
            LIBNET_RAW4,                            /* injection type */
            NULL,                                   /* network interface */
            errbuf);                                /* error buffer */
  
    if (!l)
    {
        length += sprintf(log_buffer + length, "\tlibnet_init: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    /* 
     * build dns payload 
     */
    requested_ip[0]=requested_ip_long/(256*256*256);
    requested_ip_long=requested_ip_long%(256*256*256);
    requested_ip[1]=requested_ip_long/(256*256);
    requested_ip_long=requested_ip_long%(256*256);
    requested_ip[2]=requested_ip_long/256;
    requested_ip_long=requested_ip_long%256;
    requested_ip[3]=requested_ip_long;

    payload_s = snprintf(payload, sizeof payload, "%c%s%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c", 
			 (char)(strlen(query)&0xff), query, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0d, 0xe0, 0x00, 0x04, requested_ip[0], requested_ip[1], requested_ip[2], requested_ip[3]);

    /* 
     * build packet
     */
    dns = libnet_build_dnsv4(
	type,          /* TCP or UDP */
	dns_id,        /* id */
	0x8100,        /* request */
	1,             /* num_q */
	1,             /* num_anws_rr */
	0,             /* num_auth_rr */
	0,             /* num_addi_rr */
	payload,
	payload_s,
	l,
	0
	);
   
    if (dns == -1)
    {
        length += sprintf(log_buffer + length, "\tCan't build  DNS packet: %s\n", libnet_geterror(l));
        goto bad;
    }

	ptag4 = libnet_build_udp(
	    sport,                                /* source port */
	    dport,                                    /* destination port */
	    LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + payload_s, /* packet length */
	    0,                                      /* checksum */
	    NULL,                                   /* payload */
	    0,                                      /* payload size */
	    l,                                      /* libnet handle */
	    0);                                     /* libnet id */

	if (ptag4 == -1)
	{
	    length += sprintf(log_buffer + length, "\tCan't build UDP header: %s\n", libnet_geterror(l));
	    goto bad;
	}


	ip = libnet_build_ipv4(
	    LIBNET_IPV4_H + LIBNET_UDP_H + type + payload_s,/* length */
	    0,                                          /* TOS */
	    242,                                        /* IP ID */
	    0,                                          /* IP Frag */
	    64,                                         /* TTL */
	    IPPROTO_UDP,                                /* protocol */
	    0,                                          /* checksum */
	    src_ip,                                     /* source IP */
	    dst_ip,                                     /* destination IP */
	    NULL,                                       /* payload */
	    0,                                          /* payload size */
	    l,                                          /* libnet handle */
	    0);                                         /* libnet id */

	if (ip == -1)
	{
	    length += sprintf(log_buffer + length, "\tCan't build IP header: %s\n", libnet_geterror(l));
	    exit(EXIT_FAILURE);
	}
    

    /*
     * write to the wire
     */
    c = libnet_write(l);
    if (c == -1)
    {
        length += sprintf(log_buffer + length, "\tWrite error: %s\n", libnet_geterror(l));
        goto bad;
    }
    else
    {
        length += sprintf(log_buffer + length, "\tWrote %d byte DNS packet; check the wire.\n", c);
    }
    length = strlen(log_buffer);
    write(logfd, log_buffer, length); // Write to the log.
    libnet_destroy(l);
    return (EXIT_SUCCESS);
  bad:
    length = strlen(log_buffer);
    write(logfd, log_buffer, length); // Write to the log.
    libnet_destroy(l);
    return (EXIT_FAILURE);
}
