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
	//printf("Port %d\n", scanner->port);
    
	scanner->scan_bit = scan_bit;
    scanner->tcp_flags = scan_to_flags(1<<scan_bit);
    scanner->scan_type = 1<<scan_bit;

    scanner->ip_str = g_env.ip_and_hosts[g_env.ite_ip].hostname;

    if (g_env.nb_threads)
        g_env.threads_availability[thread_id] = false;

    return scanner;
}

void port_loop(int scan_bit) {
    int i = 0;
    while (i < g_env.nb_port) {
        t_scanner *scanner = init_scanner(0, i, scan_bit);
        if (g_env.nb_threads == 0) {
            scan_thread((void*)scanner);
            i++;
            continue ;
        }
        int thread_id = get_available_thread();
        if (pthread_create(&(g_env.scanner_threads[thread_id]), NULL, (void*)&scan_thread, (void*)scanner) != 0) {
            printf("thread %d failed\n", thread_id);
            error_exit("pthread_create failed", 1);
        }
        i++;
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

void scan_loop(void) {
    int scan_bit = 0;
    while (scan_bit < NB_SCAN) {
        if (g_env.scan>>scan_bit & 1) {
			setup_pcap(&scan_bit);
            pthread_mutex_lock(&(g_env.pcap_compile_m));
            pthread_mutex_unlock(&(g_env.pcap_compile_m));
            printf("llop\n");
            port_loop(scan_bit);
            if (g_env.nb_threads)
                wait_for_all_threads();

            if (pthread_join(*g_env.pcap_thread, NULL) < 0) {
                error_exit("pthread_join failed", 1);
            }
        }
        scan_bit++;
    }
}

void ip_loop(void) {

    configure_socket();
    
    g_env.ite_ip = 0;
	struct timeval	tv1;
	struct timeval	tv2;
	gettimeofday(&tv1, NULL);
    while (g_env.ite_ip < g_env.nb_ips) {
        scan_loop();
        if (g_env.nb_threads)
            wait_for_all_threads();
        g_env.ite_ip++;
    }
	gettimeofday(&tv2, NULL);
	int		ret = tv2.tv_usec - tv1.tv_usec;
	printf("Total time: %ld.%d\n", tv2.tv_sec - tv1.tv_sec - (ret > 0 ? 0 : 1), (ret > 0 ? ret / 1000 : 1000 - ret / 1000));
}
