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

	for (int i = 0; i < NB_OPT; i++)
	{
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

int				parser(int ac, char **av, t_pars *data)
{
	int			opt_off;
	long		addr = (long)data;

	for (int i = 1; i < ac; i++)
	{
		if (DEBUG_PARS)
			printf("\nworking on %s\n",  av[i]);
		if (strncmp(av[i], "--", 2) == 0)
		{
			//is_valid_opt returns -1 in case the opt doesn't exist
			if ((opt_off = is_valid_opt(av[i])) == -1)
				return (display_unknown(av[0], av[i]));
			if (opt_off == 5)
				return (display_help(av[0]));
			else
			{
				if (i + 1 == ac)
					return (display_no_val(av[0], av[i]));
				i++;
				if (DEBUG_PARS) {
					printf("value found %s pour %d\n", av[i], opt_off);
					printf("---------------------------------------------\n\n");
				}
				memcpy(addr + opt_off * 8, &av[i], 8);
				//*(data + i * 8) = av[i];
				/*switch (opt_off) {
					case 1:
					{
						data->port = av[i];
						break ;
					}
					case 2:
					{
						data->ip = av[i];
						break ;
					}
					case 3:
					{
						data->file = av[i];
						break ;
					}
					case 4:
					{
						data->speedup = av[i];
						break ;
					}
					case 5:
					{
						data->scan = av[i];
						break ;
					}
				}*/
			}
		}
	}
	print_parser(data);
	return (0);
}
