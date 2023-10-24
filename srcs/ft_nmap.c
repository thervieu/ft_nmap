#include "../incs/ft_nmap.h"

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
    g_env.min_port = 80;
    g_env.max_port = 200;
    g_env.nb_threads = 30; // set to 1 when doing parsing

    g_env.nb_ips = 2; 

    g_env.nb_scans = 6;   
}

t_env g_env;

int main(int ac, char **av) {
    if (ac < 2) {
        usage();
        error_exit(NULL, 255);
    }
    (void)av;

    // init mutex(es) (at least one for global, maybe one for send/recv/pcap ?)
    pthread_mutex_init(&(g_env.launch_thread_m), NULL);
    // init global
    init_global();
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