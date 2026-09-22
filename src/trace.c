#include "ft_traceroute.h"

/*
 * trace_loop: the heart of ft_traceroute.
 *   [A] open sockets
 *   [B] TTL loop sending probes (UDP by default, ICMP with -I)
 *   [C] receive ICMP replies, match our probe, measure RTT
 */

// standard internet checksum, reused from ft_ping (needed for ICMP probes)
static unsigned short	icmp_checksum(const void *data, size_t len)
{
	const unsigned short	*w;
	unsigned long			sum;

	w = data;
	sum = 0;
	while (len > 1)
	{
		sum += *w++;
		len -= 2;
	}
	if (len == 1)
		sum += *(const unsigned char *)w;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (~sum);
}

// [A] open the UDP send socket and the raw ICMP receive socket
static int	trace_setup(t_trace *p)
{
	p->send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (p->send_sock < 0)
		return (-1);
	p->recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (p->recv_sock < 0)
		return (-1);
	return (0);
}

// the socket that carries our probes (and thus the per-hop TTL)
static int	send_fd(t_trace *p)
{
	if (p->mode == MODE_ICMP)
		return (p->recv_sock);
	return (p->send_sock);
}

// UDP probe: destination port encodes the sequence (base_port + seq)
static void	send_udp_probe(t_trace *p, int seq)
{
	struct sockaddr_in	dst;
	char				payload[PROBE_DATALEN];

	memset(payload, 0, sizeof(payload));
	dst = p->dest;
	dst.sin_port = htons(p->base_port + seq);
	sendto(p->send_sock, payload, sizeof(payload), 0,
		(struct sockaddr *)&dst, sizeof(dst));
}

// ICMP probe: an echo request carrying our id + seq (like ping)
static void	send_icmp_probe(t_trace *p, int seq)
{
	unsigned char	pkt[8 + PROBE_DATALEN];
	struct icmp		*ic;

	memset(pkt, 0, sizeof(pkt));
	ic = (struct icmp *)pkt;
	ic->icmp_type = ICMP_ECHO;
	ic->icmp_code = 0;
	ic->icmp_id = htons(p->id);
	ic->icmp_seq = htons(seq);
	ic->icmp_cksum = icmp_checksum(pkt, sizeof(pkt));
	sendto(p->recv_sock, pkt, sizeof(pkt), 0,
		(struct sockaddr *)&p->dest, sizeof(p->dest));
}

static void	send_probe(t_trace *p, int seq)
{
	if (p->mode == MODE_ICMP)
		send_icmp_probe(p, seq);
	else
		send_udp_probe(p, seq);
}

// [C] UDP mode: the reply embeds our original IP + UDP header;
// the embedded destination port (base_port+seq) identifies our probe.
static int	match_udp(t_trace *p, unsigned char *buf, ssize_t n, int seq, int *done)
{
    struct ip       *ip;
	struct icmp		*icmp;
	struct ip		*oip;
	size_t			hlen;
	size_t			ohlen;
	unsigned char	*oudp;

	ip = (struct ip *)buf;
	hlen = (size_t)ip->ip_hl << 2;
	if (n < (ssize_t)(hlen + ICMP_MINLEN + sizeof(struct ip) + 8))
		return (0);

	icmp = (struct icmp *)(buf + hlen);
	if (icmp->icmp_type != ICMP_TIMXCEED && icmp->icmp_type != ICMP_UNREACH)
		return (0);

	oip = (struct ip *)(buf + hlen + ICMP_MINLEN);
	ohlen = (size_t)oip->ip_hl << 2;
    // check protocol
	if (oip->ip_p != IPPROTO_UDP || n < (ssize_t)(hlen + ICMP_MINLEN + ohlen + 4))
		return (0);

    // check source ip
    if (oip->ip_dst.s_addr != p->dest.sin_addr.s_addr)
        return (0);

    // check port number
	oudp = (unsigned char *)oip + ohlen;
	if (((oudp[2] << 8) | oudp[3]) != p->base_port + seq)
		return (0);

	if (icmp->icmp_type == ICMP_UNREACH)
	{
		if (icmp->icmp_code == ICMP_UNREACH_PORT && ip->ip_src.s_addr == p->dest.sin_addr.s_addr)
		{
			*done = 1;
			return (1); 
		}
		return (0);
	}
    *done = 0;
	return (1);
}

// [C] ICMP mode: transit hops send Time Exceeded embedding our echo header;
// the destination sends an Echo Reply carrying our id + seq directly.
static int	match_icmp(t_trace *p, unsigned char *buf, ssize_t n, int seq, int *done)
{
	struct ip	*ip;
	struct icmp	*icmp;
	struct ip	*oip;
	struct icmp	*oic;
	size_t		hlen;
	size_t		ohlen;

	ip = (struct ip *)buf;
	hlen = (size_t)ip->ip_hl << 2;
	if (n < (ssize_t)(hlen + ICMP_MINLEN))
		return (0);

	icmp = (struct icmp *)(buf + hlen);
	if (icmp->icmp_type == ICMP_ECHOREPLY)
	{
		*done = 1;
		return (ntohs(icmp->icmp_id) == p->id && ntohs(icmp->icmp_seq) == seq);
	}
	if (icmp->icmp_type != ICMP_TIMXCEED
		|| n < (ssize_t)(hlen + ICMP_MINLEN + sizeof(struct ip) + 8))
		return (0);

	oip = (struct ip *)(buf + hlen + ICMP_MINLEN);
	ohlen = (size_t)oip->ip_hl << 2;
	if (oip->ip_p != IPPROTO_ICMP || n < (ssize_t)(hlen + ICMP_MINLEN + ohlen + 8))
		return (0);

	oic = (struct icmp *)((unsigned char *)oip + ohlen);
	*done = 0;
	return (ntohs(oic->icmp_id) == p->id && ntohs(oic->icmp_seq) == seq);
}

// print one probe result on the current hop line, tracking IP changes
static void	print_probe(t_reply *r, int got, struct in_addr *last)
{
	char	            ipbuf[INET_ADDRSTRLEN];
    char                hostbuf[NI_MAXHOST];
    struct sockaddr_in  sa;

	if (!got)
	{
		printf(" *");
		return ;
	}
	if (last->s_addr != r->from.s_addr)
	{
		inet_ntop(AF_INET, &r->from, ipbuf, sizeof(ipbuf));
        // Reserve DNS lookup
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr = r->from;
        if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), 
                        hostbuf, sizeof(hostbuf), NULL, 0, 0) == 0)
            printf(" %s (%s)", hostbuf, ipbuf);
		else
            printf(" %s (%s)", ipbuf, ipbuf);
		*last = r->from;
	}
	printf("  %.3f ms", r->rtt);
}

int	trace_loop(t_trace *p)
{
	t_hop			hops[MAX_HOPS_LIMIT + 1];
	struct in_addr	last;
	struct timeval	now;
	int				send_ttl = p->first_ttl;
	int				send_probe_idx = 0;
	int				print_ttl = p->first_ttl;
	int				printed_probes = 0;
	int				header_printed = 0;
	unsigned long   active_queries = 0;
	int				target_reached = 0;

	if (trace_setup(p) != 0)
		return (fprintf(stderr, "ft_traceroute: socket: %s\n",
				strerror(errno)), 1);

	printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
		p->host, p->ip_str, p->max_hops, 20 + 8 + PROBE_DATALEN);
	fflush(stdout);

	memset(hops, 0, sizeof(hops));

	while (print_ttl <= p->max_hops && (!target_reached || print_ttl <= target_reached))
	{
        // 1. Send probes in fixed limit by -N (p->nqueries)
		while (active_queries < p->nqueries && send_ttl <= p->max_hops && 
		        (!target_reached || send_ttl <= target_reached))
		{
			t_hop *h = &hops[send_ttl];
			h->ttl = send_ttl;

			setsockopt(send_fd(p), IPPROTO_IP, IP_TTL, &send_ttl, sizeof(send_ttl));

			gettimeofday(&h->probes[send_probe_idx].send_time, NULL);
			
			// TTL과 프로브 인덱스를 조합하여 고유한 시퀀스 생성
			// 예: TTL이 1이고 인덱스가 0이면 seq는 0
			//     TTL이 5이고 인덱스가 2면 seq는 (4 * 3) + 2 = 14
			int current_seq = ((send_ttl - 1) * p->nprobes) + send_probe_idx;
			
			h->probes[send_probe_idx].seq = current_seq;
			h->probes[send_probe_idx].sent = 1;

			send_probe(p, current_seq);

			active_queries++;
			send_probe_idx++;

			if (send_probe_idx == p->nprobes)
			{
				send_probe_idx = 0;
				send_ttl++;
			}
		}

        // 2. Receive the responds (select with timeout shorter than 10 ms)
		fd_set rset;
		FD_ZERO(&rset);
		FD_SET(p->recv_sock, &rset);
		struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 };

		if (select(p->recv_sock + 1, &rset, NULL, NULL, &tv) > 0)
		{
			unsigned char buf[512];
			struct sockaddr_in from;
			socklen_t flen = sizeof(from);
			ssize_t n = recvfrom(p->recv_sock, buf, sizeof(buf), 0,
					(struct sockaddr *)&from, &flen);
            //printf("n:%ld", n);
            //printf("buf: %s", buf);
			if (n > 0)
			{
				for (int t = p->first_ttl; t <= send_ttl && t <= p->max_hops; t++)
				{
					for (int pb = 0; pb < p->nprobes; pb++)
					{
						t_probe *pr = &hops[t].probes[pb];
						if (pr->sent && pr->got == 0)
						{
                            //printf("seq:%d\n", pr->seq);
							int done = 0;
							int match = (p->mode == MODE_ICMP)
								? match_icmp(p, buf, n, pr->seq, &done)
								: match_udp(p, buf, n, pr->seq, &done);

							if (match)
							{
								gettimeofday(&now, NULL);
								pr->reply.rtt = (now.tv_sec - pr->send_time.tv_sec) * 1000.0
									+ (now.tv_usec - pr->send_time.tv_usec) / 1000.0;
                                
                                struct ip *ip = (struct ip *)buf;
								pr->reply.from = ip->ip_src;
								pr->reply.done = done;
								pr->got = 1;
								active_queries--;

								if (done && (!target_reached || t < target_reached))
									target_reached = t;
                                break;
							}
						}
					}
				}
			}
		}

        // 3. timeouts management for the probes without responds
		gettimeofday(&now, NULL);
		for (int t = p->first_ttl; t <= send_ttl && t <= p->max_hops; t++)
		{
			for (int pb = 0; pb < p->nprobes; pb++)
			{
				t_probe *pr = &hops[t].probes[pb];
				if (pr->sent && pr->got == 0)
				{
					double diff = (now.tv_sec - pr->send_time.tv_sec)
						+ (now.tv_usec - pr->send_time.tv_usec) / 1000000.0;
					if (diff >= PROBE_TIMEOUT)
					{
						pr->got = -1; // expired
						active_queries--;
					}
				}
			}
		}
        // 4. progressive probe by probe display for print_ttl
		while (print_ttl <= p->max_hops)
		{
			t_hop *h = &hops[print_ttl];

            int hop_ready = 1;
            for (int pb = 0; pb < p->nprobes; pb++)
            {
                if (h->probes[pb].got == 0)
                {
                    hop_ready = 0;
                    break;
                }
            }
            if (!hop_ready)
                break;

			if (!header_printed)
			{
				printf("%2d ", print_ttl);
				fflush(stdout);
				header_printed = 1;
				last.s_addr = 0;
			}

			while (printed_probes < p->nprobes)
			{
				t_probe *pr = &h->probes[printed_probes];
				if (pr->got == 0)
					break ; // wait for the respond or the next probe timeout
				print_probe(&pr->reply, (pr->got == 1), &last);
				fflush(stdout);
				printed_probes++;
			}

			if (printed_probes == p->nprobes)
			{
				printf("\n");
				fflush(stdout);
				header_printed = 0;
				printed_probes = 0;

				if (target_reached && print_ttl >= target_reached)
				{
					print_ttl = p->max_hops + 1;
					break ;
				}
				print_ttl++;
			}
			else
				break ;
		}
	}

	close(p->send_sock);
	close(p->recv_sock);
	return (0);
}