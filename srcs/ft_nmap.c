#include "ft_nmap.h"

void error_exit(char *err, int code) {
    if (err != NULL) {
        printf("ft_nmap: %s\n", err);
    }
    exit(code);
}


int get_interface(void) {
    char errbuf[PCAP_ERRBUF_SIZE];  // Error buffer
    pcap_if_t *alldevs;

    // Retrieve the list of available network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding network devices: %s\n", errbuf);
        return 1;
    }
    g_env.device = ft_strdup(alldevs->name);

    // Free the list of network devices
    pcap_freealldevs(alldevs);

    return 0;
}

void init_global(void) {
    g_env.timeout = 1;
    g_env.ttl = 64;
    g_env.s_port = 80;
    g_env.nb_port = 0;

    g_env.nb_threads = 0;

    g_env.nb_ips = 0;

    g_env.scan = 0b1111111;
    if (get_interface() == 1) {
        error_exit("Could not find interface to open for pcap", 1);
    }
}

void free_global(void) {
    if (g_env.port)
	    free(g_env.port);
    if (g_env.device)
	    free(g_env.device);
    if (g_env.pcap_thread)
	    free(g_env.pcap_thread);
    if (g_env.scan_bit_to_index)
	    free(g_env.scan_bit_to_index);

    for (int i = 0; i < g_env.nb_ips; i++) {
        if (g_env.ip_and_hosts[i].hostname)
            free(g_env.ip_and_hosts[i].hostname);
    }
    if (g_env.ip_and_hosts)
	    free(g_env.ip_and_hosts);
    if (g_env.threads_availability)
        free(g_env.threads_availability);

    if (g_env.nb_threads && g_env.scanner_threads)
        free(g_env.scanner_threads);
    if (!g_env.results) {
        return;
    }
	for (int i = 0; i < g_env.nb_ips; i++) {
        if (!g_env.results[i].ports_result) break;
		for (int j = 0; j < g_env.nb_port; j++) {
            if (!g_env.results[i].ports_result[j].scan_results) break;
			free(g_env.results[i].ports_result[j].scan_results);
		}
		free(g_env.results[i].ports_result);
	}
	free(g_env.results);
}

void init_scan_result(int it_ip, int it_port) {
    g_env.results[it_ip].ports_result[it_port].scan_results = (t_scan_result*)malloc(sizeof(t_scan_result)*(g_env.nb_scans));
    if (g_env.results[it_ip].ports_result[it_port].scan_results == NULL) {
        error_exit("malloc failed scan_results array", 1);
    }
    for (int i = 0; i < NB_SCAN; i++) {
        if ((g_env.scan>>i & 1) == 0) {
            continue;
        }
        switch (i) {
            case 0:
                g_env.results[it_ip].ports_result[it_port].scan_results[g_env.scan_bit_to_index[i]].state = FILTERED;
                break ;
            case 1:
                g_env.results[it_ip].ports_result[it_port].scan_results[g_env.scan_bit_to_index[i]].state = OPEN | FILTERED;
                break ;
            case 2:
                g_env.results[it_ip].ports_result[it_port].scan_results[g_env.scan_bit_to_index[i]].state = UNFILTERED;
                break ;
            case 3:
                g_env.results[it_ip].ports_result[it_port].scan_results[g_env.scan_bit_to_index[i]].state = OPEN | FILTERED;
                break ;
            case 4:
                g_env.results[it_ip].ports_result[it_port].scan_results[g_env.scan_bit_to_index[i]].state = OPEN | FILTERED;
                break ;
            case 5:
                g_env.results[it_ip].ports_result[it_port].scan_results[g_env.scan_bit_to_index[i]].state = OPEN | FILTERED;
                break ;
            case 6:
                g_env.results[it_ip].ports_result[it_port].scan_results[g_env.scan_bit_to_index[i]].state = OPEN | FILTERED;
                break ;
        }
    }
}

void init_structs_global(void) {
	if (g_env.nb_port == 0) {
		g_env.nb_port = 1024;
		g_env.port = (int*)malloc(sizeof(int) * g_env.nb_port);
		if (g_env.port == NULL) 
			error_exit("ports malloc failed", 1);
		int port = 0;
		while (port < g_env.nb_port) {
			g_env.port[port] = port + 1;
			port++;
		}
	}

    int scan_length = 0;
    for (int i=0; i<NB_SCAN; i++) {
        if (g_env.scan>>i & 1) {
            scan_length++;
        }
    }
    g_env.nb_scans = scan_length;
    g_env.scan_bit_to_index = (int*)malloc(sizeof(int)*NB_SCAN);
    if (g_env.scan_bit_to_index == NULL) {
        error_exit("malloc failed scan_bit_to_index", 1);
    }

    int scan_index = 0;
    for (int i=0; i<NB_SCAN; i++) {
        if (g_env.scan>>i & 1) {
            g_env.scan_bit_to_index[i] = scan_index;
            scan_index++;
        }
    }

    g_env.results = (t_result *)malloc(sizeof(t_result)*g_env.nb_ips);
    if (g_env.results == NULL) {
        error_exit("malloc failed results array", 1);
    }
    int i = 0;
    while (i < g_env.nb_ips) {
        g_env.results[i].ports_result = (t_port_result*)malloc(sizeof(t_port_result)*(g_env.nb_port));
        if (g_env.results[i].ports_result == NULL) {
            error_exit("malloc failed ports_result array", 1);
        }
        int index_port = 0;
        while (index_port < g_env.nb_port) {
            g_env.results[i].ports_result[index_port].port = g_env.port[index_port];
            init_scan_result(i, index_port);
            index_port++;
        }
        i++;
    }
    g_env.pcap_thread = (pthread_t*)malloc(sizeof(pthread_t));
    if (g_env.pcap_thread == NULL) {
        error_exit("malloc failed scanner_threads array", 1);
    }
    if (g_env.nb_threads == 0) {
        return ;
    }
    g_env.threads_availability = (bool *)malloc(sizeof(bool)*g_env.nb_threads);
    if (g_env.threads_availability == NULL) {
        error_exit("malloc failed threads_availability array", 1);
    }
    for (int i = 0; i < g_env.nb_threads; i++) {
        g_env.threads_availability[i] = true;
    }

    if (g_env.nb_threads==0) return;
    g_env.scanner_threads = (pthread_t *)malloc(sizeof(pthread_t)*g_env.nb_threads);
    if (g_env.scanner_threads == NULL) {
        error_exit("malloc failed scanner_threads array", 1);
    }
    printf("init struct ok\n");
}

t_env g_env;

static void		display_ips(void)
{
	for (int i = 0; i < g_env.nb_ips; i++) {
        if (g_env.ip_and_hosts[i].unknown==false) {
		    printf("%s ", inet_ntoa(g_env.ip_and_hosts[i].ip));
        }
	}
	printf("\n");
}

void			display_nmap(void) {
	printf("Scan Configurations\n");
    printf("Target Ip-Address : ");
	display_ips();
	printf("N° of Ports to scan : %d\n", g_env.nb_port);
	printf("Scans to be performed : ");
	print_scan(g_env.scan);
	printf("Scanning with port %d\n", g_env.s_port);
	printf("Scanning with ttl of %d\n", g_env.ttl);
	printf("N° of threads : %d\n\n", g_env.nb_threads);
	printf("Scanning ...\n\n");
}

size_t ft_stlren(char *str) {
    size_t len = 0;
    while (str[len]) {
        len++;
    }
    return len;
}


int			display_ports(bool openness) {
    int openness_ports = 0;

	printf("%s ports:\n\
 Port       Service Name        Results                              Conclusion\n", openness ? "Open" : "Closed");
	for (int i = 0; i < 90; i++)
		printf("-");
	printf("\n");

    char *states[7] = {
        "U",
        "O",
        "C",
        "",
        "F",
        "O|F",
        "C|F",
    };
	for (int i = 0; i < g_env.nb_port; i++) {
		int		is_opened = false;

		//printf("Processing %d\n", g_env.results[g_env.ite_ip].ports_result[i].port);
		for (int j = 0; j < g_env.nb_scans; j++) {
			if (g_env.results[g_env.ite_ip].ports_result[i].scan_results[j].state == OPEN)
				is_opened = true;//printf("Port %d is open\n", g_env.results[g_env.ite_ip].ports_result[i].port);
		}
		if (is_opened==openness) {
            openness_ports++;
			struct servent *serv;
			serv = getservbyport(htons(g_env.results[g_env.ite_ip].ports_result[i].port), NULL);
            int printed = 0;
			printf("%*d%*s        ", 5, g_env.results[g_env.ite_ip].ports_result[i].port, 19, serv ? serv->s_name : "Unassigned");
            int written = 0;
            for (int k = 0; k < NB_SCAN; k++) {
                if ((1<<k&g_env.scan)==0) continue;

                
                printed++;
                if (printed==5) {
                    printf("\n%*s", 32, "");
                    written = 0;
                }

                char *state = states[g_env.results[g_env.ite_ip].ports_result[i].scan_results[g_env.scan_bit_to_index[k]].state];

                written += 6;
                written += ft_stlren(state);
                switch (k) {
                    case 0:
                        printf("SYN(%s) ", state);
                        break;
                    case 1:
                        printf("NULL(%s) ", state);
                        written++;
                        break;
                    case 2:
                        printf("ACK(%s) ", state);
                        break;
                    case 3:
                        printf("FIN(%s) ", state);
                        break;
                    case 4:
                        printf("XMAS(%s) ", state);
                        written++;
                        break;
                    case 5:
                        printf("MAIMON(%s) ", state);
                        written += 3;
                        break;
                    case 6:
                        printf("UDP(%s) ", state);
                        break;
                }
            }
            printf("%*s\n", 47 - written, openness ? "Open" : "Closed");
		}
	}
	printf("\n");
    return openness_ports;
}


int main(int ac, char **av) {
    if (getuid() != 0) {
        display_help(av[0]);
        error_exit("Operation not permitted\nPlease retry with root rights", 1);
    }
	t_pars	data;
    if (ac < 2) {
        display_help(av[0]);
        error_exit(NULL, 1);
    }
	bzero(&data, sizeof(data));

    init_global();

	if (parser(ac, av, &data) == -1) {
        free_global();
		return(0);
    }
    (void)av;

    pthread_mutex_init(&(g_env.launch_thread_m), NULL);
    pthread_mutex_init(&(g_env.pcap_compile_m), NULL);
    init_structs_global();

    display_nmap();
    ip_loop();

	free_global();
    close(g_env.socket_fd);
    pthread_mutex_destroy(&(g_env.launch_thread_m));
    pthread_mutex_destroy(&(g_env.pcap_compile_m));

    return 0;
}
