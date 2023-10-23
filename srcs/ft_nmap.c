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

/*
    idea of loop function

    socket init
    gettimeofday(&g_env->tv_start);
    for loop range through ips/hosts {
        for loop range through ports {
            for loop range through scan types {

                if g_env->scan_types  {
                    init scanner_struct
                    if (can_create_thread() == false) {
                        wait_for_one_thread(); // possible ? sinon wait_for_all_threads
                    }
                    if ((ret = pthread_create(&(g_env->threads[thread_nb], scanner_struct, scanner_func)) != 0){
                        fprintf( stdout, "Fail %d %d", ret, errno );
                        exit(ret);
                    }
                    thread_nb++;
                    ite++;
                }
                else
                    ite++;
            }
        }
    }
    wait_for_all_threads
    gettimeofday(&g_env->tv_end);
    print time

*/

void init_global(void) {
    g_env.min_port = 80;
    g_env.max_port = 200;
    g_env.nb_threads = 30; // set to 1 when doing parsing

    g_env.nb_ips = 2; 

    g_env.nb_scans = 6;   
}

void init_structs_global(void) {
    g_env.results = (t_result *)malloc(sizeof(t_result)*g_env.nb_ips);
    if (g_env.results == NULL) {
        error_exit("malloc failed results array", 1);
    }
    int i = 0;
    while (i < g_env.nb_ips) {
        int nb_ports = g_env.max_port - g_env.min_port + 1;
        g_env.results[i].ports_result = (t_port_result*)malloc(sizeof(t_port_result)*(nb_ports));
        if (g_env.results[i].ports_result == NULL) {
            error_exit("malloc failed ports_result array", 1);
        }
        int port = 0;
        while (port < nb_ports) {
            g_env.results[i].ports_result[port].port = port+g_env.min_port;
            g_env.results[i].ports_result[port].scan_results = (t_scan_result*)malloc(sizeof(t_scan_result)*(g_env.nb_scans+1));
            if (g_env.results[i].ports_result[port].scan_results == NULL) {
                error_exit("malloc failed scan_results array", 1);
            }      
            for (int j = 0; j < g_env.nb_scans; j++) {
                g_env.results[i].ports_result[port].scan_results[j].change_me = false;
            }      
            port++;
        }
        i++;
    }
    g_env.threads_availability = (bool *)malloc(sizeof(bool)*g_env.nb_threads);
    for (int i = 0; i < g_env.nb_threads; i++) {
        g_env.threads_availability[i] = true;
    }
    g_env.scanner_threads = (pthread_t *)malloc(sizeof(pthread_t)*g_env.nb_threads);
}

int get_available_thread(void) {
    int available_thread = -1;
    while (true) {
        pthread_mutex_lock(&(g_env.launch_thread_m));
        for (int i = 0; i < g_env.nb_threads; i++) {
            if (g_env.threads_availability[i] == true) {
                available_thread = i;
                break ;
            }
        }
        pthread_mutex_unlock(&(g_env.launch_thread_m));
        if  (available_thread >= 0) {
            break ;
        }
    }
    printf("out get_available_thread thread = %d\n", available_thread);
    return available_thread;
}

t_scanner *init_scanner(int thread_id, int port, int scan_id) {
    t_scanner *scanner = (t_scanner*)malloc(sizeof(t_scanner*));
    scanner->thread_id = thread_id;
    scanner->port = port;
    scanner->scan_id = scan_id;
    // scanner->scan_type = get_scan_flag_from_id(scan_id);

    g_env.threads_availability[thread_id] = false;

    printf("init scanner, %d, %d, %d\n", scanner->thread_id, scanner->port, scanner->scan_id);
    return scanner;
}

void scan_thread(void *data) {
    t_scanner scanner = *(t_scanner *)data;
    g_env.results[g_env.ite_ip_host].ports_result[scanner.port].scan_results[scanner.scan_id].change_me = true;
    printf("thread id = %d changed %d %d\n", scanner.thread_id, scanner.port, scanner.scan_id);
    pthread_mutex_lock(&(g_env.launch_thread_m));
    g_env.threads_availability[scanner.thread_id] = true;
    pthread_mutex_unlock(&(g_env.launch_thread_m));
}

void scan_loop(int port/*, ip_str, socket*/) {
    int scan_id = 0;
    while (scan_id < g_env.nb_scans) {
        int thread_id = get_available_thread();
        t_scanner *scanner = init_scanner(thread_id, port, scan_id);
        printf("port %d scan %d launch %d\n", port, scan_id, thread_id);
        if (pthread_create(&(g_env.scanner_threads[thread_id]), NULL, (void*)&scan_thread, (void*)scanner) != 0) {
            printf("thread %d failed\n", thread_id);
            error_exit("pthread_create failed", 1);
        }
        scan_id++;
    }
}

void ports_loop(/*ip_str, socket*/) {
    int ite_port = 0;
    int max_iter = g_env.max_port-g_env.min_port+1;
    while (ite_port < max_iter) {
        scan_loop(ite_port+g_env.min_port/*, ip_str, socket*/);
        ite_port++;
    }
}

void wait_for_all_threads(void) {
    int nb_threads_free = 0;
    printf("in wait_for_all_threads\n");
    while (nb_threads_free != g_env.nb_threads) {
        nb_threads_free = 0;
        for (int i = 0; i < g_env.nb_threads; i++) {
            if (g_env.threads_availability[i] == true) {
                nb_threads_free++;
            }
        }
    }
    printf("out wait_for_all_threads\n");
}

void ip_loop(void) {
    init_structs_global();
    // gettimeofday();
    int ip_nb = 1;
    int port_nb = 0;
    int scan_nb = 0;
    printf("ip %d: port %d: scan %d: bool %d\n\n", ip_nb, port_nb+g_env.min_port, scan_nb, g_env.results[ip_nb].ports_result[port_nb].scan_results[scan_nb].change_me);
    
    // setup socket

    // for loop on ip/hosts
    g_env.ite_ip_host = 0;  
    while (g_env.ite_ip_host < g_env.nb_ips) {
        ports_loop(/*"ip_str", socket */);
        wait_for_all_threads();
        g_env.ite_ip_host++;
    }  
}

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