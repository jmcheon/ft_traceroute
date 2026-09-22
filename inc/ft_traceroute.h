#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <errno.h>
# include <unistd.h>
# include <netdb.h>
# include <sys/time.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/select.h>
# include <netinet/in.h>
# include <netinet/in_systm.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/udp.h>
# include <arpa/inet.h>

# define MAX_HOPS       30      // stop after this TTL (real traceroute default)
# define PROBES_PER_HOP 3       // probes sent per hop -> 3 RTTs per line
# define BASE_PORT      33434   // classic UDP traceroute base destination port
# define PROBE_TIMEOUT  3       // seconds to wait for a reply before "*"
# define PROBE_DATALEN  32      // payload; 20 (IP) + 8 (UDP/ICMP) + 32 = 60 bytes

# define MODE_UDP       0       // default: UDP probes to high ports
# define MODE_ICMP      1       // -I bonus: ICMP ECHO probes (like ping)

// one probe's reply: where it came from, round-trip time, is-it-the-destination
typedef struct s_reply
{
	struct in_addr	from;	// hop that answered
	double			rtt;	// round-trip time in ms
	int				done;	// 1 if this reply is from the destination -> stop
}	t_reply;

typedef struct s_trace
{
	const char			*host;		// target exactly as typed on the cmd line
	char				ip_str[INET_ADDRSTRLEN];
	struct sockaddr_in	dest;		// resolved destination address
	int					send_sock;	// UDP socket, TTL set per hop via IP_TTL
	int					recv_sock;	// raw ICMP socket, catches the replies
	int					max_hops;	// -m bonus, default MAX_HOPS
	int					nprobes;	// -q bonus, default PROBES_PER_HOP
	int					first_ttl;	// -f bonus, default 1
	int					base_port;	// -p bonus, default BASE_PORT
	int					mode;		// -I bonus: MODE_UDP or MODE_ICMP
	unsigned short		id;			// our pid, marks our probes among the noise
}	t_trace;

int			trace_loop(t_trace *p);
void		usage(int status);
const char	*icmp_error_str(int type, int code);

#endif
