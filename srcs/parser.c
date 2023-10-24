#include "../incs/ft_nmap.h"

# define DEBUG_PARS 1

static int		display_help(char *prog_name)
{
	printf("Help Screen\n\
%s [OPTIONS]\n\
--help Print this help screen\n\
--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n\
--ip ip addresses to scan in dot format\n\
--file File name containing IP addresses to scan,\n\
--speedup [250 max] number of parallel threads to use\n\
--scan SYN/NULL/FIN/XMAS/ACK/UDP\n", prog_name);
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

static int		is_valid_opt(char *opt)
{
	static char		valid_opt[NB_OPT][8] = {"ports", "ip", "file", "speedup", "scan", "help"};

	for (int i = 0; i < NB_OPT; i++) {
		if (strcmp(valid_opt[i], opt + 2) == 0)
			return (i);
	}
	return (-1);
}

void			print_parser(t_pars *data)
{
	printf("port = %s\n", data->port);
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
	return (0);
}

static int		format_port(char *port_string)
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
		if (is_digit(port_string[i]) == 1)
		{
			val = atoi(port_string + i);
			while (is_digit(port_string[i]) == 1)
				i++;
		}
		else if (port_string[i] == ',' && i != 0) {
			i++;
			val = atoi(port_string + i);
			g_env.port[port_idx] = val;
			port_idx++;
			actual_port = i;
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

static int		format_opt(t_pars *data)
{
	if (format_port(data->port) == -1)
		return (-1);
	for (int i = 0; i < g_env.nb_port; i++) {
		printf("port[%d] = %d\n", i, g_env.port[i]);
	}
	return (0);
}

int				parser(int ac, char **av, t_pars *data)
{
	int			opt_off;
	long		addr = (long)data;

	for (int i = 1; i < ac; i++) {
		if (DEBUG_PARS)
			printf("\nworking on %s\n",  av[i]);
		if (strncmp(av[i], "--", 2) == 0) {
			//is_valid_opt returns -1 in case the opt doesn't exist
			if ((opt_off = is_valid_opt(av[i])) == -1)
				return (display_unknown(av[0], av[i]));
			if (opt_off == 5)
				return (display_help(av[0]));
			else {
				if (i + 1 == ac)
					return (display_no_val(av[0], av[i]));
				i++;
				if (DEBUG_PARS) {
					printf("value found %s pour %d\n", av[i], opt_off);
					printf("---------------------------------------------\n\n");
				}
				memcpy(addr + opt_off * 8, &av[i], 8);
			}
		}
	}
	return (format_opt(data));
	print_parser(data);
	return (0);
}
