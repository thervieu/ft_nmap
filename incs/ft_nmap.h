#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <unistd.h>
# include <stdio.h>
# include <signal.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netdb.h>
# include <sys/time.h>
# include <stdbool.h>
# include <stdlib.h>
# include <float.h>
# include <math.h>

#include <pthread.h>

//#include <pcap.h>

# include <string.h>

# define NB_OPT 6

# define SYN 0x01
# define NUL 0x02
# define ACK 0x04
# define FIN 0x08
# define XMS 0x10
# define UDP 0x20

typedef struct	s_pars {
	char		*port;
	char		*ip;
	char		*file;
	char		*speedup;
	char		*scan;
}				t_pars;

typedef struct s_scan_result {
    bool change_me;
}   t_scan_result;

typedef struct s_port_result {
    int port;
    t_scan_result *scan_results;
}   t_port_result;

typedef struct s_result {
    t_port_result *ports_result;
    // char *ip_str;
}   t_result;

typedef struct s_env {
    /*
    ** args
    */
    int min_port;
    int max_port;
    int nb_threads;
	int			*port;
	int			nb_port;
    // t_list *ip_and_hosts; // can be array ?
    // t_list *scan_types; // can be array ?

    /*
    ** general storage structs for threads and results
    */
    // timeval *beginning;
    // timeval *avg_time;

    int ite_ip_host;
    int nb_ips;
    int nb_scans;
    pthread_t *scanner_threads;
    bool *threads_availability;
    t_result *results; // array of size len(ip/hosts)
    // -> will have an array of result_ports
    // -> result_ports will have an array / enum for each scan
    pthread_mutex_t launch_thread_m;


    /*
    ** structs and data for scanning
    */
    char *src_ip_str;
    char *dst_ip_str;
    // map of ptr to functions for different scan types
}               t_env;

typedef struct s_scanner {
    int thread_id;
    int port;
    int scan_id;
    int scan_type;
    // socket
    // char *ip_str;
    // char *buffer;
    // seq
    // ack_seq
    // sockaddr_in
}   t_scanner;

extern t_env g_env;

int			parser(int ac, char **av, t_pars *data);

#endif
