#include "ft_traceroute.h"

// read the value that follows a "-x N" option and advance the index past it
static int	int_opt(int argc, char **argv, int *i, int *out)
{
	if (*i + 1 >= argc)
		return (fprintf(stderr, "ft_traceroute: option '%s' needs a value\n",
				argv[*i]), -1);
	*out = atoi(argv[*i + 1]);
	*i += 1;
	return (0);
}

// map a "-x" flag to the struct field it fills, or NULL if not one of them
static int	*opt_target(t_trace *p, const char *arg)
{
	if (!strcmp(arg, "-m"))
		return (&p->max_hops);
	if (!strcmp(arg, "-q"))
		return (&p->nprobes);
	if (!strcmp(arg, "-f"))
		return (&p->first_ttl);
	if (!strcmp(arg, "-p"))
		return (&p->base_port);
	return (NULL);
}

// reject nonsensical option values before we start tracing
static int	validate_opts(t_trace *p)
{
	if (p->max_hops < 1 || p->max_hops > 255)
		return (fprintf(stderr, "ft_traceroute: first hop out of range\n"), -1);
	if (p->max_hops > 255)
		return (fprintf(stderr, "ft_traceroute: max hops cannot be more than 255\n"), -1);
	if (p->nprobes < 1)
		return (fprintf(stderr, "ft_traceroute: nprobes must be >= 1\n"), -1);
	if (p->first_ttl < 1 || p->first_ttl > p->max_hops)
		return (fprintf(stderr, "ft_traceroute: first ttl must be 1..max\n"), -1);
	if (p->base_port < 1 || p->base_port > 65535)
		return (fprintf(stderr, "ft_traceroute: port must be 1..65535\n"), -1);
	return (0);
}

// --help + single host (mandatory), plus -m -q -f -p value options (bonus)
static int	parse_args(t_trace *p, int argc, char **argv)
{
	int	i;
	int	*tgt;

	i = 1;
	while (i < argc)
	{
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h") || !strcmp(argv[i], "-?"))
			usage(0);
		else if (!strcmp(argv[i], "-I"))
			p->mode = MODE_ICMP;
		else if ((tgt = opt_target(p, argv[i])) != NULL)
		{
			if (int_opt(argc, argv, &i, tgt) != 0)
				return (-1);
		}
		else if (argv[i][0] == '-' && argv[i][1] != '\0')
			return (fprintf(stderr, "ft_traceroute: invalid option '%s'\n",
					argv[i]), -1);
		else if (p->host == NULL)
			p->host = argv[i];
		else
			return (fprintf(stderr, "ft_traceroute: extra operand '%s'\n",
					argv[i]), -1);
		i++;
	}
	if (p->host == NULL)
		return (fprintf(stderr, "ft_traceroute: missing host operand\n"), -1);
	return (validate_opts(p));
}

// resolve the target to an IPv4 address
static int	resolve(t_trace *p)
{
	struct addrinfo	hints;
	struct addrinfo	*res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	if (getaddrinfo(p->host, NULL, &hints, &res) != 0)
		return (-1);
	p->dest = *(struct sockaddr_in *)res->ai_addr;
	inet_ntop(AF_INET, &p->dest.sin_addr, p->ip_str, sizeof(p->ip_str));
	freeaddrinfo(res);
	return (0);
}

int	main(int argc, char **argv)
{
	t_trace	p;

	memset(&p, 0, sizeof(p));
	p.max_hops = MAX_HOPS;
	p.nprobes = PROBES_PER_HOP;
	p.first_ttl = 1;
	p.base_port = BASE_PORT;
	if (parse_args(&p, argc, argv) != 0)
		return (64);
	if (resolve(&p) != 0)
	{
		fprintf(stderr, "ft_traceroute: Name or service not known %s\n", p.host);
		return (1);
	}
	p.id = getpid() & 0xffff;
	printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
		p.host, p.ip_str, p.max_hops,
		20 + 8 + PROBE_DATALEN);
	return (trace_loop(&p));
}
