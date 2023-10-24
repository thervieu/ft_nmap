#include "../incs/ft_nmap.h"

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
        if (available_thread >= 0) {
            break ;
        }
    }
    return available_thread;
}

int scan_to_flags(int scan) {
    if (scan&SYN)
        return SYN_F;
    if (scan&NUL)
        return NULL_F;
    if (scan&ACK)
        return ACK_F;
    if (scan&FIN)
        return FIN_F;
    if (scan&XMS)
        return FIN_F|PSH_F|URG_F;
    return FIN_F|PSH_F|URG_F|SYN_F|RST_F;
}

t_scanner *init_scanner(int thread_id, int port_index, int scan_bit, char *ip) {
    t_scanner *scanner = (t_scanner*)malloc(sizeof(t_scanner));
    
    scanner->thread_id = thread_id;
    
    scanner->port_index = port_index;
    scanner->port = g_env.port[port_index];
    
    scanner->scan_bit = scan_bit;
    scanner->tcp_flags = scan_to_flags(scan_bit);
    scanner->scan_type = 1<<scan_bit;

    scanner->ip_str = ip;

    g_env.threads_availability[thread_id] = false;

    return scanner;
}

void scan_loop(int port_index, char *ip) {
    int scan_bit = 0;
    while (scan_bit < NB_SCAN) {
        if (g_env.scan>>scan_bit & 1) {
            int thread_id = get_available_thread();
            t_scanner *scanner = init_scanner(thread_id, port_index, scan_bit, ip);
            if (pthread_create(&(g_env.scanner_threads[thread_id]), NULL, (void*)&scan_thread, (void*)scanner) != 0) {
                printf("thread %d failed\n", thread_id);
                error_exit("pthread_create failed", 1);
            }
        }
        scan_bit++;
    }
}

void ports_loop(char *ip) {
    int i = 0;
    while (i < g_env.nb_port) {
        scan_loop(i, ip);
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
    // gettimeofday();
    
    configure_socket();
    // for loop on ip/hosts
    g_env.ite_ip = 0;  
    while (g_env.ite_ip < g_env.nb_ips) {
        ports_loop(g_env.ip_and_hosts[g_env.ite_ip].hostname/*, socket */);
        wait_for_all_threads();
        g_env.ite_ip++;
    }
    printf("end of ip_loop\n");
}
