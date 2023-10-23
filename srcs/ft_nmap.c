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

int main(int ac, char **av) {
    if (ac < 2) {
        usage();
        error_exit(NULL, 255);
    }
	//parser returns -1 in case of error, 0 otherwise
	if (parser(ac, av) == -1)
		return ;
    (void)av;
    // init mutex(es) (at least one for global, maybe one for send/recv/pcap ?)
    // init global
    // Q: que faire quand on a pas de thread (speedup = 0) ? Faire une fonction à part semble plus simple
    // Q: nmap sort les ports dans l'ordre décroissant... Comment faire ça facilement avec la globale ?
    // -> on peut faire un g_env->result_ip[nb_ip]->result_ports[1024 ou taille de max_port - min_port]
    // parse args
    // display header
    // loop (all threads creation/deletion should be done here)
    // display results
    // free global
    // free mutex(es)
}
