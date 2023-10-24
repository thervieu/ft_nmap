#include "../incs/ft_nmap.h"

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

t_scanner *init_scanner(int thread_id, int port_index, int scan_bit) {
    t_scanner *scanner = (t_scanner*)malloc(sizeof(t_scanner*));
    scanner->thread_id = thread_id;
    scanner->port_index = port_index;
    scanner->port = g_env.port[port_index];
    scanner->scan_bit = scan_bit;
    scanner->scan_type = 1<<scan_bit;

    g_env.threads_availability[thread_id] = false;

    return scanner;
}

void scan_thread(void *data) {
    t_scanner scanner = *(t_scanner *)data;
    g_env.results[g_env.ite_ip_host].ports_result[scanner.port_index].scan_results[g_env.scan_bit_to_index[scanner.scan_bit]].change_me = true;
    pthread_mutex_lock(&(g_env.launch_thread_m));
    g_env.threads_availability[scanner.thread_id] = true;
    pthread_mutex_unlock(&(g_env.launch_thread_m));
}

void scan_loop(int port_index/*, ip_str, socket*/) {
    int scan_bit = 0;
    while (scan_bit < 6) {
        if (g_env.scan>>scan_bit & 1) {
            int thread_id = get_available_thread();
            t_scanner *scanner = init_scanner(thread_id, port_index, scan_bit);
            if (pthread_create(&(g_env.scanner_threads[thread_id]), NULL, (void*)&scan_thread, (void*)scanner) != 0) {
                printf("thread %d failed\n", thread_id);
                error_exit("pthread_create failed", 1);
            }
        }
        scan_bit++;
    }
}

void ports_loop(/*ip_str, socket*/) {
    int i = 0;
    while (i < g_env.nb_port) {
        scan_loop(i/*, ip_str, socket*/);
        i++;
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
    
    // setup socket

    // for loop on ip/hosts
    g_env.ite_ip_host = 0;  
    while (g_env.ite_ip_host < g_env.nb_ips) {
        ports_loop(/*"ip_str", socket */);
        wait_for_all_threads();
        g_env.ite_ip_host++;
    }
    printf("end of ip_loop\n");
}
