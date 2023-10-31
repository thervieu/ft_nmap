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

char	*ft_strcat(char *s1, const char *s2)
{
	int		i;
	int		i2;

	i = 0;
	i2 = 0;
	while (s1[i])
		i++;
	while (s2[i2])
	{
		s1[i] = s2[i2];
		i++;
		i2++;
	}
	s1[i] = '\0';
	return (s1);
}
static int		length(long nb)
{
	int		len;

	len = 0;
	if (nb == 0)
		return (1);
	if (nb < 0)
	{
		nb = nb * -1;
		len++;
	}
	while (nb > 0)
	{
		nb = nb / 10;
		len++;
	}
	return (len);
}

char			*ft_itoa(int nb)
{
	char	*str;
	long	n;
	int		len;

	n = nb;
	len = length(n);
	if (!(str = (char*)malloc(sizeof(char) * (len + 1))))
		return (NULL);
	str[len--] = '\0';
	if (n == 0)
	{
		str[0] = 48;
		return (str);
	}
	if (n < 0)
	{
		str[0] = '-';
		n = n * -1;
	}
	while (n > 0)
	{
		str[len--] = 48 + (n % 10);
		n = n / 10;
	}
	return (str);
}

char	*ft_strcpy(char *dst, const char *src)
{
	int		i;

	i = 0;
	while (src[i])
	{
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
	return (dst);
}

t_scanner *init_scanner(int thread_id, int port_index, int scan_bit) {
    t_scanner *scanner = (t_scanner*)malloc(sizeof(t_scanner));
    
    scanner->thread_id = thread_id;
    
    scanner->port_index = port_index;
    scanner->port = g_env.port[port_index];
    
    scanner->scan_bit = scan_bit;
    scanner->tcp_flags = scan_to_flags(1<<scan_bit);
    scanner->scan_type = 1<<scan_bit;

    scanner->ip_str = g_env.ip_and_hosts[g_env.ite_ip].hostname;

    g_env.threads_availability[thread_id] = false;

    return scanner;
}

void scan_loop(int port_index) {
    int scan_bit = 0;
    while (scan_bit < NB_SCAN) {
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


void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // This is the callback function that will be called for each captured packet.
    // You can process the packet data here.
    (void)packet;
    (void)user;
    printf("Packet captured, length: %d\n", pkthdr->len);
    // Add your packet processing code here
}

pcap_t *handle;

void	timeout_handler(int signal)
{
	pcap_breakloop(handle);
	printf("alarm %d donc pcap_breakloop\n", signal);
}

void ports_loop(void) {
    int i = 0;
    while (i < g_env.nb_port) {
        scan_loop(i);
        i++;
    }

    // proper function ??
    char *filter_exp = malloc(30);
    bzero(filter_exp, 30*sizeof(char));
    filter_exp = ft_strcat(filter_exp, "src host ");
    filter_exp = ft_strcat(filter_exp, inet_ntoa(g_env.ip_and_hosts[g_env.ite_ip].ip));

    char errbuf[100];
    bpf_u_int32 net;
    bpf_u_int32 mask;

    if (pcap_lookupnet(g_env.device, &net, &mask, errbuf) < 0) {
        error_exit("pcap_lookup: could not find network device", 1);
    }
    handle = pcap_open_live(g_env.device, BUFSIZ, 1, 1000, errbuf);
    if (handle==NULL) {
        error_exit("pcap_open_live: could not open device", 1);
    }
    struct bpf_program fp;
    /* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        error_exit("pcap_compile failed", 2);
    }
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        error_exit("pcap_setfilter failed", 2);
	}
	struct sigaction sa;

	sa.sa_handler = timeout_handler;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGALRM, &sa, NULL);
	alarm(g_env.timeout);

    void *a=NULL;
	// // https://cpp.hotexamples.com/fr/site/file?hash=0xcf42149af84f0b881f83b4cce88aca7e474429ea0e6df9b1ffddd94d9b46c087
    while (true) {
        printf("HERE\n");
	    int ret = pcap_dispatch(handle, -1, packet_handler, (unsigned char *)&a);
        printf("ret dispatch %d\n", ret);
        if (ret == -1) {
            error_exit("error: pcap_dispatch failed", 1);
        }
        if (ret == -2) {
            printf("BREAK LOOP\n");
            break ;
        }
    }
    // display
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
        ports_loop(/*, socket */);
        wait_for_all_threads();
        g_env.ite_ip++;
    }
    printf("end of ip_loop\n");
}
