#include "ft_traceroute.h"

void	usage(int status)
{
	printf("Usage: ft_traceroute [OPTION...] HOST\n"
		"Print the route packets trace to a network host.\n"
		"\n"
		"  -f N           start from the Nth hop (first TTL, default 1)\n"
		"  -I             use ICMP ECHO probes instead of UDP\n"
		"  -m N           max number of hops (default 30)\n"
		"  -p N           base UDP destination port (default 33434)\n"
		"  -q N           probe packets per hop (default 3)\n"
		"  -h, --help     give this help list\n");
	exit(status);
}

// Human-readable ICMP reason, reused from ft_ping.
// Used to annotate unreachable hops (e.g. !H, !N in real traceroute).
const char	*icmp_error_str(int type, int code)
{
	static char	unknown[64];

	if (type == ICMP_UNREACH)
	{
		if (code == ICMP_UNREACH_NET)
			return ("Destination net unreachable");
		if (code == ICMP_UNREACH_HOST)
			return ("Destination host unreachable");
		if (code == ICMP_UNREACH_PROTOCOL)
			return ("Destination protocol unreachable");
		if (code == ICMP_UNREACH_PORT)
			return ("Destination port unreachable");
		if (code == ICMP_UNREACH_NEEDFRAG)
			return ("Fragmentation needed and DF set");
		return ("Destination unreachable");
	}
	if (type == ICMP_TIMXCEED)
	{
		if (code == ICMP_TIMXCEED_REASS)
			return ("Frag reassembly time exceeded");
		return ("Time to live exceeded");
	}
	if (type == ICMP_REDIRECT)
		return ("Redirect (change route)");
	if (type == ICMP_PARAMPROB)
		return ("Parameter problem");
	snprintf(unknown, sizeof(unknown),
		"Unknown ICMP type %d code %d", type, code);
	return (unknown);
}
