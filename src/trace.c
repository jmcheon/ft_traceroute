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
static int	match_udp(t_trace *p, unsigned char *buf, ssize_t n, int seq,
				int *done)
{
	struct ip		*ip;
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
	if (oip->ip_p != IPPROTO_UDP
		|| n < (ssize_t)(hlen + ICMP_MINLEN + ohlen + 4))
		return (0);
	oudp = (unsigned char *)oip + ohlen;
	if (((oudp[2] << 8) | oudp[3]) != p->base_port + seq)
		return (0);
	*done = (icmp->icmp_type == ICMP_UNREACH);
	return (1);
}

// [C] ICMP mode: transit hops send Time Exceeded embedding our echo header;
// the destination sends an Echo Reply carrying our id + seq directly.
static int	match_icmp(t_trace *p, unsigned char *buf, ssize_t n, int seq,
				int *done)
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
	if (oip->ip_p != IPPROTO_ICMP
		|| n < (ssize_t)(hlen + ICMP_MINLEN + ohlen + 8))
		return (0);
	oic = (struct icmp *)((unsigned char *)oip + ohlen);
	*done = 0;
	return (ntohs(oic->icmp_id) == p->id && ntohs(oic->icmp_seq) == seq);
}

// wait up to PROBE_TIMEOUT for the reply to probe `seq`; fill hop/rtt/done
static int	wait_reply(t_trace *p, int seq, struct timeval *sent, t_reply *r)
{
	unsigned char		buf[512];
	struct sockaddr_in	from;
	socklen_t			flen;
	struct timeval		tv;
	struct timeval		now;
	fd_set				rset;
	ssize_t				n;
	int					matched;
	int					done;

	tv.tv_sec = PROBE_TIMEOUT;
	tv.tv_usec = 0;
	while (1)
	{
		FD_ZERO(&rset);
		FD_SET(p->recv_sock, &rset);
		if (select(p->recv_sock + 1, &rset, NULL, NULL, &tv) <= 0)
			return (0);
		flen = sizeof(from);
		n = recvfrom(p->recv_sock, buf, sizeof(buf), 0,
				(struct sockaddr *)&from, &flen);
		if (n < 0)
			continue;
		done = 0;
		if (p->mode == MODE_ICMP)
			matched = match_icmp(p, buf, n, seq, &done);
		else
			matched = match_udp(p, buf, n, seq, &done);
		if (!matched)
			continue;
		gettimeofday(&now, NULL);
		r->rtt = (now.tv_sec - sent->tv_sec) * 1000.0
			+ (now.tv_usec - sent->tv_usec) / 1000.0;
		r->from = from.sin_addr;
		r->done = done;
		return (1);
	}
}

// print one probe result on the current hop line, tracking IP changes
static void	print_probe(t_reply *r, int got, struct in_addr *last)
{
	char	ipbuf[INET_ADDRSTRLEN];

	if (!got)
	{
		printf("  *");
		return ;
	}
	if (last->s_addr != r->from.s_addr)
	{
		inet_ntop(AF_INET, &r->from, ipbuf, sizeof(ipbuf));
		printf(" %s", ipbuf);
		*last = r->from;
	}
	printf("  %.3f ms", r->rtt);
}

int	trace_loop(t_trace *p)
{
	struct timeval	sent;
	struct in_addr	last;
	t_reply			r;
	int				ttl;
	int				probe;
	int				seq;
	int				reached;
	int				got;

	if (trace_setup(p) != 0)
		return (fprintf(stderr, "ft_traceroute: socket: %s\n",
				strerror(errno)), 1);
	printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
		p->host, p->ip_str, p->max_hops, 20 + 8 + PROBE_DATALEN);
	seq = 0;
	reached = 0;
	ttl = p->first_ttl;
	while (ttl <= p->max_hops && !reached)
	{
		setsockopt(send_fd(p), IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
		printf("%2d ", ttl);
		last.s_addr = 0;
		probe = 0;
		while (probe < p->nprobes)
		{
			gettimeofday(&sent, NULL);
			send_probe(p, seq);
			got = wait_reply(p, seq, &sent, &r);
			print_probe(&r, got, &last);
			if (got && r.done)
				reached = 1;
			seq++;
			probe++;
		}
		printf("\n");
		ttl++;
	}
	close(p->send_sock);
	close(p->recv_sock);
	return (0);
}
