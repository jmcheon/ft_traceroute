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
	{
		close(p->send_sock);
		return (-1);
	}
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
static int	send_udp_probe(t_trace *p, int seq)
{
	struct sockaddr_in	dst;
	char				payload[PROBE_DATALEN];

	memset(payload, 0, sizeof(payload));
	dst = p->dest;
	dst.sin_port = htons(p->base_port + seq);
	if (sendto(p->send_sock, payload, sizeof(payload), 0,
			(struct sockaddr *)&dst, sizeof(dst)) < 0)
		return (-1);
	return (0);
}

// ICMP probe: an echo request carrying our id + seq (like ping)
static int	send_icmp_probe(t_trace *p, int seq)
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
	if (sendto(p->recv_sock, pkt, sizeof(pkt), 0,
			(struct sockaddr *)&p->dest, sizeof(p->dest)) < 0)
		return (-1);
	return (0);
}

static int	send_probe(t_trace *p, int seq)
{
	if (p->mode == MODE_ICMP)
		return (send_icmp_probe(p, seq));
	return (send_udp_probe(p, seq));
}

// [C] UDP mode: the reply embeds our original IP + UDP header;
// the embedded destination port (base_port+seq) identifies our probe.
static int	match_udp(t_trace *p, unsigned char *buf, ssize_t n, int seq, int *done)
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
		|| n < (ssize_t)(hlen + ICMP_MINLEN + ohlen + 8))
		return (0);
	if (oip->ip_dst.s_addr != p->dest.sin_addr.s_addr)
		return (0);
	oudp = (unsigned char *)oip + ohlen;
	if (((oudp[2] << 8) | oudp[3]) != p->base_port + seq)
		return (0);
	if (icmp->icmp_type == ICMP_UNREACH)
	{
		if (icmp->icmp_code == ICMP_UNREACH_PORT
			&& ip->ip_src.s_addr == p->dest.sin_addr.s_addr)
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
		if (ntohs(icmp->icmp_id) == p->id
			&& ntohs(icmp->icmp_seq) == seq)
		{
			*done = 1;
			return (1);
		}
		return (0);
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
	return (ntohs(oic->icmp_id) == p->id
		&& ntohs(oic->icmp_seq) == seq);
}

// print one probe result on the current hop line, tracking IP changes
static void	print_probe(t_reply *r, int got, struct in_addr *last)
{
	char			ipbuf[INET_ADDRSTRLEN];
	char			hostbuf[NI_MAXHOST];
	struct sockaddr_in	sa;

	if (!got)
	{
		printf(" *");
		return ;
	}
	if (last->s_addr != r->from.s_addr)
	{
		inet_ntop(AF_INET, &r->from, ipbuf, sizeof(ipbuf));
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

// Wait for exactly one reply matching the probe that was just sent.
static int	wait_for_reply(t_trace *p, t_probe *pr)
{
	struct timeval	start;

	gettimeofday(&start, NULL);
	while (1)
	{
		struct timeval	now;
		struct timeval	left;
		long			elapsed_ms;
		fd_set			fds;
		int			ret;

		gettimeofday(&now, NULL);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L
			+ (now.tv_usec - start.tv_usec) / 1000L;
		if (elapsed_ms >= PROBE_TIMEOUT * 1000L)
			return (0);
		{
			long remaining_ms;

			remaining_ms = PROBE_TIMEOUT * 1000L - elapsed_ms;
			left.tv_sec = remaining_ms / 1000L;
			left.tv_usec = (remaining_ms % 1000L) * 1000L;
		}
		FD_ZERO(&fds);
		FD_SET(p->recv_sock, &fds);
		ret = select(p->recv_sock + 1, &fds, NULL, NULL, &left);
		if (ret < 0)
		{
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (ret == 0)
			return (0);
		if (FD_ISSET(p->recv_sock, &fds))
		{
			unsigned char	buf[512];
			struct sockaddr_in	from;
			socklen_t		flen;
			ssize_t			n;
			int				done;
			int				matched;

			flen = sizeof(from);
			n = recvfrom(p->recv_sock, buf, sizeof(buf), 0,
				(struct sockaddr *)&from, &flen);
			if (n <= 0)
				continue;
			done = 0;
			if (p->mode == MODE_ICMP)
				matched = match_icmp(p, buf, n, pr->seq, &done);
			else
				matched = match_udp(p, buf, n, pr->seq, &done);
			if (!matched)
				continue;
			gettimeofday(&now, NULL);
			pr->reply.from = from.sin_addr;
			pr->reply.rtt = (now.tv_sec - pr->send_time.tv_sec) * 1000.0
				+ (now.tv_usec - pr->send_time.tv_usec) / 1000.0;
			pr->reply.done = done;
			pr->got = 1;
			return (1);
		}
	}
}

int	trace_loop(t_trace *p)
{
	int		ttl;
	int		target_reached;
	int		seq;

	if (trace_setup(p) != 0)
	{
		perror("ft_traceroute: socket");
		return (1);
	}
	ttl = p->first_ttl;
	target_reached = 0;
	seq = 0;
	while (ttl <= p->max_hops && !target_reached)
	{
		t_hop	hop;
		struct in_addr	last;
		int		pb;

		memset(&hop, 0, sizeof(hop));
		hop.ttl = ttl;
		last.s_addr = 0;
		if (setsockopt(send_fd(p), IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
		{
			perror("setsockopt IP_TTL");
			break;
		}
		printf("%2d ", ttl);
		fflush(stdout);
		pb = 0;
		while (pb < p->nprobes)
		{
			t_probe	*pr;
			int		wait_ret;

			pr = &hop.probes[pb];
			pr->seq = seq++;
			pr->sent = 1;
			gettimeofday(&pr->send_time, NULL);
			if (send_probe(p, pr->seq) != 0)
			{
				pr->got = -1;
				print_probe(&pr->reply, 0, &last);
				pb++;
				continue;
			}
			// Sequential mode: do not send the next probe until this one finishes.
			wait_ret = wait_for_reply(p, pr);
			if (wait_ret == 1)
			{
				print_probe(&pr->reply, 1, &last);
				if (pr->reply.done)
				{
					target_reached = 1;
					hop.done = 1;
				}
			}
			else
			{
				pr->got = -1;
				print_probe(&pr->reply, 0, &last);
			}
			fflush(stdout);
			pb++;
			if (target_reached)
				break;
		}
		printf("\n");
		fflush(stdout);
		ttl++;
	}
	close(p->recv_sock);
	close(p->send_sock);
	return (0);
}
