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
# include <fcntl.h>

#include <pthread.h>

//#include <pcap.h>

# include <string.h>

# define NB_OPT 6

# define NB_SCAN 6

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

typedef struct in_addr t_addr;

typedef struct	s_network {
	char		*hostname;
	t_addr		ip;
}				t_network;

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
    int nb_threads;

    int			*port;
    int			nb_port;
    char		*file;
    int			scan;
    t_network	 *ip_and_hosts; // can be array ?
    //t_list *scan_types; // can be array ?

    /*
    ** general storage structs for threads and results
    */
    // timeval *beginning;
    // timeval *avg_time;

    int ite_ip_host;
    int nb_ips;
    int nb_scans;
    int *scan_bit_to_index;
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
    int port_index;
    int scan_bit;
    int scan_type;
    // socket
    // char *ip_str;
    // char *buffer;
    // seq
    // ack_seq
    // sockaddr_in
}   t_scanner;

extern t_env g_env;

// ft_nmap.c
void error_exit(char *err, int code);

// parsing
int			parser(int ac, char **av, t_pars *data);
char		**ft_strsplit(char const *s, char c);
char	*ft_strsub(char const *s, unsigned int start, size_t len);

// loop.c
void ip_loop(void);

#endif
