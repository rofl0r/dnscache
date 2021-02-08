/*
   DNS cache daemon

   Copyright (C) 2021 rofl0r.

   a tiny DNS cache and forwarder.

*/

#define _GNU_SOURCE
#include <unistd.h>
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <errno.h>
#include <spawn.h>
#include <fcntl.h>
#include <limits.h>
#include "udpserver.h"
#include "hsearch.h"

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

static struct htab *ip_lookup_table;
static const struct server* server;
static char *nameserver, *script;
static unsigned timeout;

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
#define dolog(...) dprintf(2, __VA_ARGS__)
#else
static void dolog(const char* fmt, ...) { }
#endif

static int my_inet_aton(char* ipstring, unsigned char* fourbytesptr) {
	char* start = ipstring;
	size_t outbyte = 0;
	while(outbyte < 4) {
		if(*ipstring == '.' || !*ipstring) {
			fourbytesptr[outbyte] = atoi(start);
			start = ipstring + 1;
			outbyte++;
		}
		if(!*ipstring && outbyte < 4) return 0;
		ipstring++;
	}
	return 1;
}

static char* my_inet_ntoa(unsigned char *ip_buf_4_bytes, char *outbuf_16_bytes) {
	unsigned char *p;
	char *o = outbuf_16_bytes;
	unsigned char n;
	for(p = ip_buf_4_bytes; p < ip_buf_4_bytes + 4; p++) {
		n = *p;
		if(*p >= 100) {
			if(*p >= 200)
				*(o++) = '2';
			else
				*(o++) = '1';
			n %= 100;
		}
		if(*p >= 10) {
			*(o++) = (n / 10) + '0';
			n %= 10;
		}
		*(o++) = n + '0';
		*(o++) = '.';
	}
	o[-1] = 0;
	return outbuf_16_bytes;
}

/* buf needs to be long enough for an ipv6 addr, i.e. INET6_ADDRSTRLEN + 1 */
static char* ipstr(union sockaddr_union *su, char* buf) {
	int af = SOCKADDR_UNION_AF(su);
	void *ipdata = SOCKADDR_UNION_ADDRESS(su);
	inet_ntop(af, ipdata, buf, INET6_ADDRSTRLEN+1);
	char portbuf[7];
	snprintf(portbuf, sizeof portbuf, ":%u", (unsigned) ntohs(SOCKADDR_UNION_PORT(su)));
	strcat(buf, portbuf);
	return buf;
}

static uint32_t get_cached_ip(char* hn) {
	htab_value *v = htab_find(ip_lookup_table, hn);
	if(v) return v->n;
	return -1;
}

static int forward_packet(unsigned char *packet, size_t plen, int count) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in srva = {.sin_family = AF_INET, .sin_port = htons(53)};
	inet_pton(AF_INET, nameserver, &srva.sin_addr);
	int i;
	for(i=0; i<count; ++i) {
		sendto(fd, packet, plen, 0, (void*)&srva, sizeof(srva));
		if(count > 1) usleep(100);
	}
	return fd;
}

static int saferead(unsigned char *packet, size_t plen, void *out, size_t n, size_t *off)
{
	if(plen < *off + n) return 0;
	memcpy(out, packet + *off, n);
	*off += n;
	return 1;
}

struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qs;
	uint16_t ansrr;
	uint16_t authrr;
	uint16_t addrr;
};
struct dns_footer {
	uint16_t type;
	uint16_t class;
};
struct dns_answer {
	uint16_t magic;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t datalen;
} __attribute__((packed));

static int parse_dns_packet(unsigned char *packet, size_t plen, char* name, size_t nlen, uint16_t *id)
{
	struct dns_header h;
	struct dns_footer f;
	size_t off = 0;
	if(!saferead(packet, plen, &h.id, 2, &off)) return 0;
	if(!saferead(packet, plen, &h.flags, 2, &off)) return 0;
	if(!saferead(packet, plen, &h.qs, 2, &off)) return 0;
	if(!saferead(packet, plen, &h.ansrr, 2, &off)) return 0;
	if(!saferead(packet, plen, &h.authrr, 2, &off)) return 0;
	if(!saferead(packet, plen, &h.addrr, 2, &off)) return 0;
	if(ntohs(h.flags) != 0x100 || ntohs(h.qs) != 1 || h.ansrr != 0 || h.authrr != 0 || h.addrr != 0) {
	oops:;
		return 0;
	}
	size_t nameleft = nlen;
	char *p = name;
	while(1) {
		if(plen < off+1) return 0;
		unsigned char l = packet[off++];
		if(!l) break;
		if(plen < off+l) return 0;
		if(l >= nameleft) return 0;
		memcpy(p, packet+off, l);
		off += l;
		p += l;
		nameleft -= l+1;
		*(p++) = '.';
	}
	if(p > name) *(p-1) = 0;
	else *p = 0;
	if(!saferead(packet, plen, &f.type, 2, &off)) return 0;
	if(!saferead(packet, plen, &f.class, 2, &off)) return 0;
	if(ntohs(f.class) != 1) goto oops;
	*id = h.id;
	return ntohs(f.type);
}

static size_t get_footer_offset(char *hn) {
	return sizeof(struct dns_header) +1 + strlen(hn) +1;
}

static uint32_t get_new_ip(char* hn, unsigned char *packet, size_t plen) {
#if 0
	union sockaddr_union su;
	if(resolve_sa(hn, 80, &su)) return -1;
	if(SOCKADDR_UNION_AF(&su) != AF_INET) return -2;
	int32_t ip;
	memcpy(&ip, SOCKADDR_UNION_ADDRESS(&su), 4);
#endif
	size_t fo = get_footer_offset(hn), w = fo+sizeof(struct dns_footer);
	/* make packet an A-type request (might have been AAAA) */
	memcpy(packet+fo+offsetof(struct dns_footer, class), "\x00\x01", 2);

	int fd = forward_packet(packet, plen, 3);
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval){.tv_usec=timeout*1000}, sizeof(struct timeval));
	char rcvbuf[1024];

	ssize_t n = recvfrom(fd, rcvbuf, sizeof rcvbuf, 0, (void*)0, (void*)0);
	close(fd);
	int passed_check = 0;
	if(n < 0) return 0;
	while(1) {
		if(n < w+sizeof(struct dns_answer)+4) return 0;
		struct dns_answer a;
		memcpy(&a, rcvbuf+w, sizeof(a));
		if(!passed_check) {
			if(a.magic != htons(0xc00c)) return 0;
			passed_check = 1;
		} else {
			if(ntohs(a.magic) >> 8 != 0xc0)
				return 0;
		}
		if(ntohs(a.type) == 5 /* CNAME */) {
			w += sizeof(struct dns_answer) + ntohs(a.datalen);
			continue;
		}
		if(ntohs(a.type) != 1 && a.datalen != htons(4)) return 0;
		uint32_t ip;
		memcpy(&ip, rcvbuf+sizeof(struct dns_answer)+w, 4);
		char *new = strdup(hn);
		if(!new) return 0;
		if(!htab_insert(ip_lookup_table, new, HTV_N(ip))) {
			free(new);
		}
		return ip;
	}
}

static void parse_list(char *fn) {
	FILE *f = fopen(fn, "r");
	if(!f) {
		perror("fopen");
		exit(1);
	}
	char buf[512], *p;
	while(fgets(buf, sizeof buf, f)) {
		if(*buf == '#') continue;
		p = buf;
		while(isspace(*p)) ++p;
		if(!*p) continue;
		char *q = p;
		while(!isspace(*q)) ++q;
		*q = 0;
		struct sockaddr_in addr = {.sin_family = AF_INET};
		if(!inet_pton(AF_INET, p, &addr.sin_addr)) continue;
		p = q+1;
		while(isspace(*p)) ++p;
		q = p;
		while(!isspace(*q)) ++q;
		*q = 0;
		char *new = strdup(p);
		if(!new) return;
		if(!htab_insert(ip_lookup_table, new, HTV_N(addr.sin_addr.s_addr))) {
			free(new);
		}
	}
	fclose(f);
}

static union sockaddr_union *ip_to_su(uint32_t ip, union sockaddr_union *su) {
	*su = (union sockaddr_union){
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = ip,
	};
	return su;
}

struct process {
	pid_t pid;
	int fds[3];
	posix_spawn_file_actions_t fa;
};

int process_open(struct process *p, char* const argv[]) {
	extern char** environ;
	int pipes[3][2] = {0}, i,j;

	errno = posix_spawn_file_actions_init(&p->fa);
	if(errno) goto spawn_error;

	for(i=0; i<3; ++i) {
		errno = posix_spawn_file_actions_addclose(&p->fa, i);
		if(errno) goto spawn_error;
	}

	for(i=0; i<3; ++i) if(pipe(pipes[i])) goto spawn_error;

	static const unsigned char pipeends[3] = {0,1,1};

	for(i=0; i<3; ++i) p->fds[i] = pipes[i][!pipeends[i]];

	for(i=0; i<3; ++i) {
		errno = posix_spawn_file_actions_adddup2(&p->fa, pipes[i][pipeends[i]], i);
		if(errno) goto spawn_error;
	}
	for(i=0; i<3; ++i) for(j=0; j<2; ++j) {
		errno = posix_spawn_file_actions_addclose(&p->fa, pipes[i][j]);
		if(errno) goto spawn_error;
	}

	errno = posix_spawnp(&p->pid, argv[0], &p->fa, NULL, argv, environ);
	if(errno) {
		spawn_error:
		for(i=0; i<3; ++i) for(j=0; j<2; ++j)
			if(pipes[i][j]) close(pipes[i][j]);
		posix_spawn_file_actions_destroy(&p->fa);
		return -1;
	}

	for(i=0; i<3; ++i)
		close(pipes[i][pipeends[i]]);

	return 0;
}

#include <sys/wait.h>
int process_close(struct process *p) {
	int i, retval;
	for(i=0; i<3; ++i) close(p->fds[i]);
	waitpid(p->pid, &retval, 0);
	posix_spawn_file_actions_destroy(&p->fa);
	return WEXITSTATUS(retval);
}

static int run_script(char *hn, uint32_t *ip) {
	struct process p;
	if(process_open(&p, (char* const[]){script, hn, 0L})) {
		perror("process_open");
		return 0;
	}
	char buf[20];
	unsigned char ipc[4];
	ssize_t n = read(p.fds[1], buf, sizeof buf);
	if(!process_close(&p) && n > 6 && my_inet_aton(buf, ipc)) {
		memcpy(ip, ipc, 4);
		return 1;
	}
	return 0;
}

static int usage(char *a0) {
	dprintf(2,
		"dnscache daemon\n"
		"---------------\n"
		"usage: %s [-i listenip -p port -n nameserver -l list -t timeout -s script]\n"
		"all arguments are optional.\n\n"
		"if nameserver is provided, it needs to be a numeric ipv4.\n\n"
		"list is a textfile containing ipv4/name tuples like /etc/hosts that will\n"
		"be added to the cache on load.\n"
		"however only ip4 addresses are processed.\n\n"
		"timeout in milliseconds: how long to wait for upstream nameserver.\n\n"
		"script is an executable file that gets passed the dns name as argument\n"
		"and can either return error exit status, in which case normal DNS lookup\n"
		"is done, or print a numeric ipv4 address and return success, in which case\n"
		"that ip is added to the cache (it will only be called once per dns name).\n"
		"\n"
		"by default listenip is 127.0.0.1, port 2053, nameserver 8.8.8.8.\n\n", a0
	);
	return 1;
}

int main(int argc, char** argv) {
	int ch;
	const char *listenip = "127.0.0.1";
	unsigned port = 2053;
	ip_lookup_table = htab_create(64);
	timeout = 200;

	while((ch = getopt(argc, argv, ":i:p:n:l:t:s:")) != -1) {
		switch(ch) {
			case 's':
				script = optarg;
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			case 'n':
				nameserver = optarg;
				break;
			case 'i':
				listenip = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'l':
				parse_list(optarg);
				break;
			case ':':
				dprintf(2, "error: option -%c requires an operand\n", optopt);
				/* fall through */
			case '?':
				return usage(argv[0]);
		}
	}
	if(!nameserver) nameserver = "8.8.8.8";
	signal(SIGPIPE, SIG_IGN);
	struct server s;
	if(server_setup(&s, listenip, port)) {
		perror("server_setup");
		return 1;
	}
	server = &s;

	while(1) {
		struct client c;
		char ipstr_buf[INET6_ADDRSTRLEN+6+1];
		char hnbuf[512+1];
		unsigned char msgbuf[1024];
		size_t msgl = sizeof(msgbuf);
		int failed = 0;
		uint16_t id;
		int type;

#define FAIL() do { failed=1; goto sendresp; } while(0)
		if(server_waitclient(&s, &c, msgbuf, &msgl)) continue;
		dolog("%s:", ipstr(&c.addr, ipstr_buf));
		if(!(type = parse_dns_packet(msgbuf, msgl, hnbuf, sizeof(hnbuf), &id))
		   || !(type == 1 /* A */ || type == 0x1c /* AAAA */)) {
			// fixme: actually this works only with raw socket
			dolog("error: unknown contents, forwarding\n");
			close(forward_packet(msgbuf, msgl, 1));
			continue;
		}
		dolog(" %s ", hnbuf);
		uint32_t ip = 0;
		{
			char* p = hnbuf;
			int dotc = 0;
			while(*p) if(*(p++) == '.') dotc++;
			/* in case the name to look up contains no dot, we redirect to
			   to localhost. it's been noticed that android devices send
			   randomly looking strings to 8.8.8.8 (google's dns), which
			   probably contain some encoded information about the user,
			   data on the device, etc. */
			if(dotc < 1) memcpy(&ip, "\x7f\0\0\1", 4);
			else if((ip = get_cached_ip(hnbuf)) == -1) {
				if(script && run_script(hnbuf, &ip)) ;
				else {
					ip = get_new_ip(hnbuf, msgbuf, msgl);
						if(!ip) {
						dolog("FAILED\n");
						continue;
					}
				}
			}
		}
		dolog("-> %s\n", ipstr(ip_to_su(ip, &(union sockaddr_union){0}), ipstr_buf));
		struct dns_header h = {
			.id = id,
			.flags = htons(0x8180),
			.qs = htons(1),
			.ansrr = htons(1),
			.authrr = 0,
			.addrr = 0,
		};
		struct dns_footer f = {
			.type = htons(1),
			.class = htons(1),
		};
		unsigned char response_buf[1024];
		size_t off = 0, n = sizeof(h);
		memcpy(response_buf+off, &h, n);
		off += n;
		n =  strlen(hnbuf)+2;
		memcpy(response_buf+off, msgbuf+off, n);
		off += n;
		n = sizeof(f);
		memcpy(response_buf+off, &f, n);
		off += n;
		struct dns_answer a = {
			.magic = htons(0xc00c),
			.type = htons(1),
			.class = htons(1),
			.ttl = htonl(135),
			.datalen = type == 1 ? htons(4) : htons(16),
		};
		n = sizeof(a);
		memcpy(response_buf+off, &a, n);
		off += n;
		if(type != 1) {
			memcpy(response_buf+off, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
			off += 12;
		}
		memcpy(response_buf+off, &ip, 4);
		off += 4;
	sendresp:;
		sendto(server->fd, response_buf, off, 0, (void*) &c.addr, SOCKADDR_UNION_LENGTH(&c.addr));
	}
}
