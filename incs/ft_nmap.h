#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <unistd.h>
# include <stdio.h>
# include <signal.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
# include <netdb.h>
# include <sys/time.h>
# include <stdbool.h>
# include <stdlib.h>
# include <float.h>
# include <math.h>
# include <fcntl.h>

# include <pthread.h>

# include <pcap/pcap.h>

# include <ifaddrs.h>
# include <string.h>
# include <errno.h>
# include <stdint.h>
# include <sys/poll.h>

# define NB_OPT 6

# define NB_SCAN 6

// scans
# define SYN 0x01
# define NUL 0x02
# define ACK 0x04
# define FIN 0x08
# define XMS 0x10
# define UDP 0x20

// tcp flags
# define NULL_F 0x00
# define FIN_F 0x01
# define SYN_F 0x02
# define RST_F 0x04
# define PSH_F 0x08
# define ACK_F 0x10
# define URG_F 0x20

# define UNFILTERED 0x00 // can set this because UNFILTERED is always alone
# define OPEN 0x01
# define CLOSE 0x02
# define FILTERED 0x04

# define PACKET_BUFFER_SIZE 64

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
	char		*nameinfo;
	char		*canonname;
	t_addr		ip;
	struct sockaddr_in	dst_addr;
}				t_network;

typedef struct s_scan_result {
    uint8_t state;
    char *service;
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

    int			timeout;
    int			*port;
    int			nb_port;
    char		*file;
    int			scan;
    t_network	 *ip_and_hosts; // can be array ?
    //t_list *scan_types; // can be array ?

    /*
    ** general storage structs for threads and results
    */
    int src_port;
    int socket_fd;

    int ite_ip;
    int nb_ips;
    int nb_scans;
    int *scan_bit_to_index;
    char *device;
    pthread_t *scanner_threads;
    pthread_t *pcap_thread;
    pcap_t *handle;
    bool *threads_availability;
    t_result *results; // array of size len(ip/hosts)
    // -> will have an array of result_ports
    // -> result_ports will have an array / enum for each scan
    pthread_mutex_t launch_thread_m;
    pthread_mutex_t pcap_compile_m;


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
    int tcp_flags;
    int scan_bit;
    int scan_type;
    char *ip_str;
    char *filter_exp;
    // char *buffer;
    // seq
    // ack_seq
    // sockaddr_in
}   t_scanner;

extern t_env g_env;

// ft_nmap.c
void error_exit(char *err, int code);
char	*ft_strdup(const char *str);

// parsing
int			parser(int ac, char **av, t_pars *data);
char		**ft_strsplit(char const *s, char c);
char	*ft_strsub(char const *s, unsigned int start, size_t len);
void	print_scan(int scan);

// loop.c
void ip_loop(void);

// configure.c
void configure_socket(void);
struct ip *configure_ip(char *buffer, int scan_type);
struct tcphdr* configure_tcp_header(char *buffer, int dst_port, int tcp_flags);
struct udphdr* configure_udp_header(char *buffer, int dst_port);
char *get_working_interface_ip(void);

// scan.c
void scan_thread(void *data);

//ip.c
int			get_ip_addr(char *host, int ip_idx);

// pcap_thread.c
void setup_pcap(int *scan_bit);

#endif
