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

    g_env.nb_ips = 1;

    g_env.scan = 0b111111;
}

t_env g_env;

int main(int ac, char **av) {
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
    // init global
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
