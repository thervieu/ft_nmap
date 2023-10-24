#include "../incs/ft_nmap.h"

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
                if (port==121) {
                    printf("%d\n", j);
                }
                g_env.results[i].ports_result[port].scan_results[j].change_me = false;
                if (port==121&&j%2 == 1) {
                    printf("%d %d %d\n", port+g_env.min_port, j, g_env.results[i].ports_result[port].scan_results[j].change_me);
                }
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
    return available_thread;
}

t_scanner *init_scanner(int thread_id, int port, int scan_id) {
    t_scanner *scanner = (t_scanner*)malloc(sizeof(t_scanner*));
    scanner->thread_id = thread_id;
    scanner->port = port;
    scanner->scan_id = scan_id;
    // scanner->scan_type = get_scan_flag_from_id(scan_id);

    g_env.threads_availability[thread_id] = false;

    return scanner;
}

void scan_thread(void *data) {
    t_scanner scanner = *(t_scanner *)data;
    g_env.results[g_env.ite_ip_host].ports_result[scanner.port].scan_results[scanner.scan_id].change_me = true;
    pthread_mutex_lock(&(g_env.launch_thread_m));
    g_env.threads_availability[scanner.thread_id] = true;
    pthread_mutex_unlock(&(g_env.launch_thread_m));
}

void scan_loop(int port/*, ip_str, socket*/) {
    int scan_id = 0;
    while (scan_id < g_env.nb_scans) {
        int thread_id = get_available_thread();
        t_scanner *scanner = init_scanner(thread_id, port, scan_id);
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
        scan_loop(ite_port/*, ip_str, socket*/);
        ite_port++;
    }
}

void wait_for_all_threads(void) {
    int nb_threads_free = 0;
    while (nb_threads_free != g_env.nb_threads) {
        nb_threads_free = 0;
        pthread_mutex_lock(&(g_env.launch_thread_m));
        for (int i = 0; i < g_env.nb_threads; i++) {
            if (g_env.threads_availability[i] == true) {
                nb_threads_free++;
            }
        }
        pthread_mutex_unlock(&(g_env.launch_thread_m));
    }
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
