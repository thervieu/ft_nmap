#include "ft_nmap.h"

void error_exit(char *err, int code) {
    if (err != NULL) {
        printf("ft_nmap: %s\n", err);
    }
    exit(code);
}

void usage(void) {
    printf("usage: ft_nmap [options] ip_to_scan\n");
}

void init_global(void) {
    g_env.nb_port = 1024;
    g_env.port = (int*)malloc(sizeof(int)*g_env.nb_port);
    if (g_env.port == NULL) {
        error_exit("ports malloc failed", 1);
    }
    int port = 0;
    while (port < g_env.nb_port) {
        g_env.port[port] = port+1;
        port++;
    }

    g_env.nb_threads = 1; // set to 1 when doing parsing

    g_env.nb_ips = 0;

    g_env.scan = 0b111111;
}


void init_structs_global(void) {
    int scan_length = 0;
    for (int i=0; i<6;i++) {
        if (g_env.scan>>i & 1) {
            scan_length++;
        }
    }
    g_env.nb_scans = scan_length;
    g_env.scan_bit_to_index = (int*)malloc(sizeof(int)*6);
    if (g_env.scan_bit_to_index == NULL) {
        error_exit("malloc failed scan_bit_to_index", 1);
    }
    int scan_index = 0;
    for (int i=0; i<6; i++) {
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
            g_env.results[i].ports_result[index_port].scan_results = (t_scan_result*)malloc(sizeof(t_scan_result)*(g_env.nb_scans));
            if (g_env.results[i].ports_result[index_port].scan_results == NULL) {
                error_exit("malloc failed scan_results array", 1);
            }
            for (int j = 0; j < g_env.nb_scans; j++) {
                g_env.results[i].ports_result[index_port].scan_results[j].change_me = false;
            }
            index_port++;
        }
        i++;
    }
    g_env.threads_availability = (bool *)malloc(sizeof(bool)*g_env.nb_threads);
    for (int i = 0; i < g_env.nb_threads; i++) {
        g_env.threads_availability[i] = true;
    }
    g_env.scanner_threads = (pthread_t *)malloc(sizeof(pthread_t)*g_env.nb_threads);
    printf("init struct ok\n");
}

t_env g_env;

int main(int ac, char **av) {
    if (getuid() != 0) {
        error_exit("Operation not permitted", 1);
    }
	t_pars	data;
    if (ac < 2) {
        usage();
        error_exit(NULL, 255);
    }
	bzero(&data, sizeof(data));
    //default values
    init_global();
	//parser returns -1 in case of error, 0 otherwise
	if (parser(ac, av, &data) == -1)
		return(0);
    (void)av;

    // init mutex(es) (at least one for global, maybe one for send/recv/pcap ?)
    pthread_mutex_init(&(g_env.launch_thread_m), NULL);
    init_structs_global();
    // Q: que faire quand on a pas de thread (speedup = 0) ? Faire une fonction à part semble plus simple
    // Q: nmap sort les ports dans l'ordre décroissant... Comment faire ça facilement avec la globale ?
    // -> on peut faire un g_env->result_ip[nb_ip]->result_ports[1024 ou taille de max_port - min_port]
    // parse_args();
    // display_header();
    ip_loop(); // (all threads creation/deletion should be done here)
    // display_results();
    // free_global();
    // free mutex(es)
}
