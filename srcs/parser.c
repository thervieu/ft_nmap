#include "ft_nmap.h"

int		display_help(char *prog_name)
{
	printf("Help Screen\n\
%s [OPTIONS]\n\
--help Print this help screen\n\
--src_port port to scan with (eg: 80 by default, 4242)\n\
--dst_port ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n\
--ip ip addresses to scan in dot format\n\
--file File name containing IP addresses to scan,\n\
--scan SYN/NULL/FIN/XMAS/ACK/MAIMON/UDP\n\
--ttl [1-255] number of time-to-live in ip header\n\
--host_timeout [500 min] time in ms to wait for host response\n\
--pkt_buf_timeout [100 min] interval to read the packet buffer\
(see pcap_open_live)\n", prog_name);
	return (-1);
}

static int		display_no_val(char *prog_name, char *opt)
{
	printf("%s: %s needs a value.\n\
Use %s --help to display help\n", prog_name, opt, prog_name);
	return (-1);
}

static int		display_unknown(char *prog_name, char *unknown)
{
	printf("%s: unknown option: %s\n\
Use %s --help to display help\n", prog_name, unknown, prog_name);
	return (-1);
}

static int		display_scan_unknown(char *unknown)
{
	printf("Unknown scan type: %s\n", unknown);
	return (-1);
}

static int		is_valid_opt(char *opt)
{
	static char		valid_opt[NB_OPT][22] = {
		"src_port",
		"dst_port",
		"ip",
		"file",
		"speedup",
		"scan",
		"ttl",
		"host_timeout",
		"pkt_buf_timeout",
		"help"
	};

	for (int i = 0; i < NB_OPT; i++) {
		if (strcmp(valid_opt[i], opt + 2) == 0)
			return (i);
	}
	return (-1);
}

void			print_parser(t_pars *data)
{
	printf("src_port = %s\n", data->s_port);
	printf("dst_port = %s\n", data->d_port);
	printf("ip = %s\n", data->ip);
	printf("file = %s\n", data->file);
	printf("speedup = %s\n", data->speedup);
	printf("scan = %s\n", data->scan);
}

static int		is_digit(char c)
{
	if (c >= '0' && c <= '9')
		return (1);
	return (0);
}

static int		count_port(char *port_string)
{
	int			i;
	int			ret;
	int			actual_port = 0;

	i = 0;
	if (port_string && is_digit(port_string[0]) == 1)
		g_env.nb_port = 1;
	else
		return (-1);
	while (port_string[i]) {
		if (is_digit(port_string[i]) == 1)
			;
		else if (port_string[i] == ',' && i != 0) {
			if (port_string[i + 1] && is_digit(port_string[i + 1]) == 1)
				g_env.nb_port++;
			else
				return (-1);
			actual_port = i + 1;
		}
		else if (port_string[i] == '-' && i != 0 && actual_port != -1) {
			if (port_string[i + 1] && is_digit(port_string[i + 1]) == 1) {
				if ((ret = atoi(port_string + i + 1) - atoi(port_string + actual_port)) > 0)
					g_env.nb_port += ret;
				else
					return (-1);
				actual_port = -1;
			}
			else
				return (-1);
		}
		else
			return (-1);
		i++;
	}
	if (g_env.nb_port > 1024) {
		error_exit("too many ports", 1024);
	}
	return (0);
}

static int		format_host_timeout(char *host_timeout)
{
	int		i = 0;

	if (!host_timeout)
		return (0);
	while (host_timeout[i]) {
		if (is_digit(host_timeout[i]) == 0) {
			printf("%s isn't a valid parameter for --host_timeout. 500ms or more only.\n", host_timeout);
			return (-1);
		}
		i++;
	}
	if ((g_env.host_timeout = atoi(host_timeout)) < 500) {
		printf("%d is too small for host_timeout. 500ms or more only.\n", g_env.host_timeout);
		return (-1);
	}
	g_env.host_timeout *= 1000;
	return (0);
}

static int		format_packet_buffer_timeout(char *pbt)
{
	int		i = 0;

	if (!pbt)
		return (0);
	while (pbt[i]) {
		if (is_digit(pbt[i]) == 0) {
			printf("%s isn't a valid parameter for --packet_buffer_timeout. 100ms or more only.\n", pbt);
			return (-1);
		}
		i++;
	}
	if ((g_env.packet_buffer_timeout = atoi(pbt)) < 100) {
		printf("%d is too small for packet_buffer_timeout. 100ms or more only.\n", g_env.packet_buffer_timeout);
		return (-1);
	}
	return (0);
}

static int		format_src_port(char *s_port)
{
	int		i = 0;

	if (!s_port)
		return (0);
	while (s_port[i]) {
		if (is_digit(s_port[i]) == 0) {
			printf("%s isn't a valid parameter for --src_port. 0 to 65535 only.\n", s_port);
			return (-1);
		}
		i++;
	}
	if ((g_env.s_port = atoi(s_port)) > 65535) {
		printf("%d is too big for src_port. 0 to 65535 only.\n", g_env.s_port);
		return (-1);
	}
	return (0);
}

static int		format_dst_port(char *port_string)
{
	int			i;
	int			ret;
	int			val;
	int			port_idx = 1;

	if (count_port(port_string) == -1) {
		printf("Error occured in %s\n", port_string);
		return (-1);
	}
	if (!(g_env.port = (int*)malloc(sizeof(int) * g_env.nb_port)))
		return (-1);
	i = 0;
	g_env.port[0] = atoi(port_string);
	while (port_idx < g_env.nb_port) {
		if (is_digit(port_string[i]) == 1) {
			val = atoi(port_string + i);
			while (is_digit(port_string[i]) == 1)
				i++;
		}
		else if (port_string[i] == ',' && i != 0) {
			i++;
			val = atoi(port_string + i);
			g_env.port[port_idx] = val;
			port_idx++;
			while (is_digit(port_string[i]) == 1)
				i++;
		}
		else if (port_string[i] == '-' && i != 0) {
			if (port_string[i + 1] && is_digit(port_string[i + 1]) == 1) {
				ret = atoi(port_string + i + 1) - val;
				for (int j = 1; j <= ret; j++) {
					g_env.port[port_idx] = val + j;
					port_idx++;
				}
				i++;
				while (is_digit(port_string[i]) == 1)
					i++;
			}
			else
				return (-1);
		}
	}
	return (0);
}

static int		format_speedup(char *speedup)
{
	int		i = 0;

	if (!speedup)
		return (0);
	while (speedup[i]) {
		if (is_digit(speedup[i]) == 0) {
			printf("%s isn't a valid parameter for --speedup. 0 to 250 only.\n", speedup);
			return (-1);
		}
		i++;
	}
	if ((g_env.nb_threads = atoi(speedup)) > 250) {
		printf("%d is too big for speedup. 0 to 250 only.\n", g_env.nb_threads);
		return (-1);
	}
	return (0);
}

void			print_scan(int scan)
{
	static char		known_scan[NB_SCAN][7] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "MAIMON", "UDP"};
	static int		value_scan[NB_SCAN] = {SYN, NUL, FIN, XMS, ACK, MMN, UDP};

	for (int i = 0; i < NB_SCAN; i++) {
		if ((scan & value_scan[i]) == value_scan[i])
			printf("%s ", known_scan[i]);
	}
	printf("\n");
}

static int		format_scan(char *scan)
{
	int				i = 0;
	bool			found;
	char			**scan_split;
	static char		known_scan[NB_SCAN][7] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "MAIMON", "UDP"};
	static int		value_scan[NB_SCAN] = {SYN, NUL, FIN, XMS, ACK, MMN, UDP};

	if (!scan)
		return (0);
	g_env.scan = 0;
	scan_split = ft_strsplit(scan, '/');
	while (scan_split[i]) {
		found = false;
		for (int j = 0; j < NB_SCAN; j++) {
				if (strcmp(scan_split[i], known_scan[j]) == 0) {
					g_env.scan |= value_scan[j];
					found = true;
				}
		}
		if (!found) {
			display_scan_unknown(scan_split[i]);
			while (scan_split[i]) {
				free(scan_split[i]);
				i++;
			}
			free(scan_split);
			return (-1);
		}
		free(scan_split[i]);
		i++;
	}
	free(scan_split);
	return (0);
}

static char		*read_file(int fd)
{
	int		len;
	int		content_sz = 0;
	char	buf[512];
	char	*content = NULL;

	while ((len = read(fd, &buf, 512)) > 0) {
		content = realloc(content, content_sz + len);
		for (int i = 0; i < len; i++)
			content[content_sz + i] = buf[i];
		content_sz += len;
	}
	return (content);
}

static int		format_file(char *file)
{
	int		fd;
	char	*content;
	char	**hosts;

	if (g_env.nb_ips != 0)
		return (-1);
	if ((fd = open(file, O_RDONLY)) < 0)
	{
		printf("An error occured while openning %s\n", file);
		return (-1);
	}
	content = read_file(fd);
	hosts = ft_strsplit(content, '\n');
	if (!hosts)
	{
		free(content);
		printf("%s is empty\n", file);
		return (-1);
	}
	g_env.nb_ips = 0;
	while (hosts[g_env.nb_ips])
		g_env.nb_ips++;
	g_env.ip_and_hosts = (t_network *)malloc(sizeof(t_network) * g_env.nb_ips);
	if (g_env.ip_and_hosts == NULL) {
		free(content);
		error_exit("malloc ip_and_hosts failed", 1);
	}
	for (int i = 0; i < g_env.nb_ips; i++)
	{
		g_env.ip_and_hosts[i].hostname = hosts[i];
		g_env.ip_and_hosts[i].unknown = false;
		if (get_ip_addr(hosts[i], i) == -1) {
			g_env.ip_and_hosts[i].unknown = true;
		}
	}
	free(content);
	free(hosts);
	return (0);
}

static int		format_ip(char *ip)
{
	if (g_env.nb_ips != 0)
		return (-1);
	g_env.nb_ips = 1;
	g_env.ip_and_hosts = (t_network *)malloc(sizeof(t_network) * g_env.nb_ips);
	if (get_ip_addr(ip, 0) == -1)
		return (-1);
	g_env.ip_and_hosts[0].hostname = ft_strdup(ip);
	g_env.ip_and_hosts[0].unknown = false;
	return (0);
}


static int		format_ttl(char *ttl)
{
	int		i = 0;

	if (!ttl)
		return (0);
	while (ttl[i]) {
		if (is_digit(ttl[i]) == 0) {
			printf("%s isn't a valid parameter for --src_port. 1 to 65535 only.\n", ttl);
			return (-1);
		}
		i++;
	}
	if ((g_env.ttl = atoi(ttl)) < 1) {
		printf("%d is too low for ttl. 1 to 255 only.\n", g_env.ttl);
		return (-1);
	}
	if ((g_env.ttl = atoi(ttl)) > 255) {
		printf("%d is too low for ttl. 1 to 255 only.\n", g_env.ttl);
		return (-1);
	}
	return (0);
}

static int		format_opt(t_pars *data)
{
	//{"ports", "ip", "file", "speedup", "scan", "help"};
	if (data->s_port && format_src_port(data->s_port) == -1)
		return (-1);
	if (data->d_port && format_dst_port(data->d_port) == -1)
		return (-1);
	if (data->ip && format_ip(data->ip) == -1)
		return (-1);
	if (data->file && format_file(data->file) == -1)
		return (-1);
	if (data->speedup && format_speedup(data->speedup) == -1)
		return (-1);
	if (data->scan && format_scan(data->scan) == -1)
		return (-1);
	if (data->ttl && format_ttl(data->ttl) == -1)
		return (-1);
	if (data->host_timeout && format_host_timeout(data->host_timeout) == -1)
		return (-1);
	if (data->pbt && format_packet_buffer_timeout(data->pbt) == -1)
		return (-1);
	if (data->file==NULL && data->ip==NULL) {
		printf("ft_nmap: parsing error: no ip/host was specified\n");
		return (-1);
	}
	if ((g_env.host_timeout/1000) - g_env.packet_buffer_timeout < 200) {
		printf("ft_nmap: parsing error: host timeout %d is too close to pkt_buf_timeout %d. \
At least 200ms difference is required.\n", (g_env.host_timeout/1000), g_env.packet_buffer_timeout);
		return (-1);
	}
	return (0);
}

int				parser(int ac, char **av, t_pars *data)
{
	int			opt_off;
	long		addr = (long)data;

	for (int i = 1; i < ac; i++) {
		if (strncmp(av[i], "--", 2) == 0) {
			//is_valid_opt returns -1 in case the opt doesn't exist
			if ((opt_off = is_valid_opt(av[i])) == -1)
				return (display_unknown(av[0], av[i]));
			if (opt_off == NB_OPT - 1)
					return (display_help(av[0]));
			else {
				if (i + 1 == ac)
					return (display_no_val(av[0], av[i]));
				i++;
				memcpy((void *)(addr + opt_off * 8), &av[i], 8);
			}
		} else {
			printf("ft_nmap: parsing error: unrecognized argument %s\n", av[i]);
			return (-1);
		}
	}
	return (format_opt(data));
}
