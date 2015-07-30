#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <signal.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close

#define LOGFILE "./proxy.log"

int logfd; // Global file descriptor for the log file to close it in the signal handler
void timestamp(int); //Writes a timestamp to the open file descriptor
char command_global[200];

void signal_handler(int signal)
{
	char command[200] = "iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0";
	system(command);
	timestamp(logfd);
	write(logfd, "\n--------------------Shutting down XPIR DNS Proxy--------------------\n", 70);
	close(logfd);
	exit(0);
}

/* returns packet id and all information needed about the packet */
static u_int32_t get_info_pkt (struct nfq_data *tb,unsigned char *ipSrc, unsigned char *ipDst, unsigned char *sport, unsigned char *dport, unsigned char *dnsId, char *url)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) 
	{
		int i;
		int j;
		int k = 0;
		//IP
		for(i=12; i<=15; i++)
		{ 
			ipSrc[k]=data[i];
			k++;
		}
		k=0;
		for(i=16; i<=19; i++)
		{ 
			ipDst[k]=data[i];
			k++;
		}
		//UDP
		sport[0]=data[20];
		sport[1]=data[21];
		dport[0]=data[22];
		dport[1]=data[23];
		//DNS
		dnsId[0]=data[28];
		dnsId[1]=data[29];
		i=40;
		k=0;
		int longueur = data[i];
		for (j = 0; j < longueur; j++) 
		{
			i++;
			url[k] = data[i];
			k++;
		}
		i++;
		while (data[i] != 0) 
		{
			url[k] = '.';
			k++;
			longueur = data[i];
			for (j = 0; j < longueur; j++) 
			{
				i++;
				url[k] = data[i];
				k++;
			}
			i++;
			
		}
		url[k] = '\0';
	}

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	char log_buffer[1000];
	int length = 0;
	printf("entering callback\n");
	char url[100];
	char request[100];
	char command[200];
	char filePath[200] = "reception/";
	unsigned char ipDst[4];
	unsigned char ipSrc[4];
	unsigned char dport[2];
	unsigned char sport[2];
	unsigned char dnsId[2];
	
	//get the different information from the packet
	u_int32_t id = get_info_pkt(nfa, ipSrc, ipDst, sport, dport, dnsId, url);
	length += sprintf(log_buffer, "\tRequested url is %s\n", url);

	//get the hash of the url
	uint16_t hash, i;
	for(hash = i = 0; i < strlen(url); ++i)
	{
		hash += url[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	length += sprintf(log_buffer + length, "\tCorresponding hash is %" PRIu16 "\n",hash);

	//launch the client with the requested hash
	sprintf(request, "%" PRIu16 , hash);
	strcpy(command, command_global);
	strcat(command, request);
	system(command);
length += sprintf(log_buffer + length, "\t%s\n",command);

	//Open the downloaded file and get the correct @IP
	char url2[100], ip[16], requestedIP[16];
	*requestedIP = 0;
	int success = 0;
	FILE * fp = NULL;
	strcat(filePath, request);
	length += sprintf(log_buffer + length, "\tOpen the file %s\n", filePath);
  	fp = fopen (filePath, "r");
   	if (fp != NULL) 
	{
		length += sprintf(log_buffer + length, "\tReading downloaded file\n");
		while(!success && (fscanf(fp, "%s %s", url2, ip)==2)) //Stop reading if success or fail reading 2 arguments
		{
			length += sprintf(log_buffer + length, "\tRead %s %s\n", url2, ip);
			if(!strcmp(url, url2))
			{
				success = 1;
				strcpy(requestedIP, ip);
			}
		}
	   	fclose(fp);
	}
	else 
	{
		length += sprintf(log_buffer + length, "\tError while opening file\n");
	}
	remove(filePath); //Delete the file sent by the server
	
	if(success)
	{
		length += sprintf(log_buffer + length, "\tRequested IP is %s\n", requestedIP);
		
		//Send the DNS answer
		/*sprintf(request2, "%d.%d.%d.%d %d.%d.%d.%d %d %d %d %s %s", ipSrc[0], ipSrc[1], ipSrc[2], ipSrc[3], ipDst[0], ipDst[1], ipDst[2], ipDst[3], sport[0]*256+sport[1], dport[0]*256+dport[1], dnsId[0]*256+dnsId[1],  url, ip);
		strcat(command2, request2);
		printf("%s\n", command2);
		system(command2);*/
		length = strlen(log_buffer);
		write(logfd, log_buffer, length); // Write to the log.	
		send_answer(ipSrc, ipDst, sport[0]*256+sport[1], dport[0]*256+dport[1], dnsId[0]*256+dnsId[1],  url, ip, logfd);
	}
	else
	{
		length += sprintf(log_buffer + length, "\t%s is not in the DB\n", url);
		length = strlen(log_buffer);
		write(logfd, log_buffer, length); // Write to the log.	
	}

	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	char log_buffer[500];
	int length = 0;


	strcpy(command_global, argv[1]);
	strcat(command_global, "/client/build/PIRClient -i ");
	strcat(command_global, argv[2]);
	if (argc == 4) 
	{
		strcat(command_global, " -p ");
		strcat(command_global, argv[3]); 
	}
	strcat(command_global, " -c --autochoice-value ");
	logfd = open(LOGFILE, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
	if (logfd == -1) 
	{
		fprintf(stderr, "error opening log file\n");
		exit(1);
	}

	printf("Starting XPIR DNS Proxy.\n");
	if(daemon(1, 0) == -1) // Fork to a background daemon process.
		fprintf(stderr, "forking to daemon process");
	signal(SIGTERM, signal_handler); // Call signal_handler when killed.
	signal(SIGINT, signal_handler); // Call signal_handler when interrupted.
	timestamp(logfd);
	length += sprintf(log_buffer, "\n--------------------Starting up XPIR DNS Proxy--------------------\n");

	length += sprintf(log_buffer + length, "opening library handle\n");
	h = nfq_open();
	if (!h) 
	{
		length += sprintf(log_buffer + length, "error during nfq_open()\n");
		exit(1);
	}

	length += sprintf(log_buffer + length, "unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) 
	{
		length += sprintf(log_buffer + length, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	length += sprintf(log_buffer + length, "binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) 
	{
		length += sprintf(log_buffer + length, "error during nfq_bind_pf()\n");
		exit(1);
	}

	length += sprintf(log_buffer + length, "binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) 
	{
		length += sprintf(log_buffer + length, "error during nfq_create_queue()\n");
		exit(1);
	}

	length += sprintf(log_buffer + length, "setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) 
	{
		length += sprintf(log_buffer + length, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	length = strlen(log_buffer);
	write(logfd, log_buffer, length); // Write to the log.

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			timestamp(logfd);
			write(logfd, "Pkt received\n", 14);
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			write(logfd, "Losing packets!\n", 17);
			continue;
		}
		perror("Recv failed");
		break;
	}

	write(logfd, "Unbinding from queue 0\n", 24);
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	write(logfd, "Unbinding from AF_INET\n", 24);
	nfq_unbind_pf(h, AF_INET);
#endif

	write(logfd, "\n--------------------Closing library handle--------------------\n", 64);
	nfq_close(h);

	exit(0);
}

/* This function writes a timestamp string to the open file descriptor
* passed to it.
*/
void timestamp(fd) 
{
	time_t now;
	struct tm *time_struct;
	int length;
	char time_buffer[40];
	time(&now); // Get number of seconds since epoch.
	time_struct = localtime((const time_t *)&now); // Convert to tm struct.
	length = strftime(time_buffer, 40, "%m/%d/%Y %H:%M:%S> ", time_struct);
	write(fd, time_buffer, length); // Write timestamp string to log.
}
