#include "../incs/ft_nmap.h"

int port_to_port_index(int port) {
    for (int i = 0; i < g_env.nb_port; i++) {
        if (port == g_env.port[i]) {
            return i;
        }
    }
    return -1;
}

void packet_handler_SYN(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    (void)user;
    (void)pkthdr;

	struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct sll_header));
   if (ip->protocol == IPPROTO_TCP) {
	    struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct sll_header) + sizeof(struct iphdr));
        int port_index = port_to_port_index(htons(tcp->th_sport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(tcp->th_sport);
        if (tcp->th_flags == (TH_SYN | TH_ACK)) {
            g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[0]].state = OPEN;
        }
        else if ((tcp->th_flags & TH_RST) == TH_RST) {
            g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[0]].state = CLOSE;
        }
   }

}

void packet_handler_NULL(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    (void)user;
    (void)pkthdr;

   struct iphdr *ip = (struct iphdr*)(packet+sizeof(struct sll_header));
   if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr*)(packet+sizeof(struct sll_header) + sizeof(struct iphdr));
        int port_index = port_to_port_index(htons(tcp->th_sport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(tcp->th_sport);
        if ((tcp->th_flags & TH_RST) == TH_RST)
	        g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[1]].state = CLOSE;
   }
   else if (ip->protocol == IPPROTO_ICMP) {
        struct tcphdr *tcp = (struct tcphdr*)(packet+sizeof(struct sll_header) + (2*sizeof(struct iphdr) + sizeof(struct icmphdr)));
        int port_index = port_to_port_index(htons(tcp->th_dport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(tcp->th_dport);
        g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[1]].state = FILTERED;
   }
}

void packet_handler_ACK(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    (void)user;
    (void)pkthdr;

   struct iphdr *ip = (struct iphdr*)(packet+sizeof(struct sll_header));
   if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr*)(packet+sizeof(struct sll_header) + sizeof(struct iphdr));
        int port_index = port_to_port_index(htons(tcp->th_sport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(tcp->th_sport);
        if ((tcp->th_flags & TH_RST) == TH_RST)
	        g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[2]].state = CLOSE;
   }
}

void packet_handler_FIN(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    (void)user;
    (void)pkthdr;

   struct iphdr *ip = (struct iphdr*)(packet+sizeof(struct sll_header));
   if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr*)(packet+sizeof(struct sll_header) + sizeof(struct iphdr));
        int port_index = port_to_port_index(htons(tcp->th_sport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(tcp->th_sport);
        if ((tcp->th_flags & TH_RST) == TH_RST)
	        g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[3]].state = CLOSE;
   }
   else if (ip->protocol == IPPROTO_ICMP) {
        struct tcphdr *tcp = (struct tcphdr*)(packet+sizeof(struct sll_header) + (2*sizeof(struct iphdr) + sizeof(struct icmphdr)));
        int port_index = port_to_port_index(htons(tcp->th_dport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(tcp->th_dport);
        g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[3]].state = FILTERED;
   }
}


void packet_handler_XMAS(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    (void)user;
    (void)pkthdr;

   struct iphdr *ip = (struct iphdr*)(packet+sizeof(struct sll_header));
   if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr*)(packet+sizeof(struct sll_header) + sizeof(struct iphdr));
        int port_index = port_to_port_index(htons(tcp->th_sport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(tcp->th_sport);
        if ((tcp->th_flags & TH_RST) == TH_RST)
	        g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[4]].state = CLOSE;
   }
   else if (ip->protocol == IPPROTO_ICMP) {
        struct tcphdr *tcp = (struct tcphdr*)(packet+sizeof(struct sll_header) + (2*sizeof(struct iphdr) + sizeof(struct icmphdr)));
        int port_index = port_to_port_index(htons(tcp->th_dport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(tcp->th_dport);
        g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[4]].state = FILTERED;
   }
}

void packet_handler_UDP(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    (void)user;
    (void)pkthdr;

   struct iphdr *ip = (struct iphdr*)(packet+sizeof(struct sll_header));
   if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr*)(ip + sizeof(struct iphdr));
        int port_index = port_to_port_index(htons(udp->uh_sport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(udp->uh_sport);
        g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[5]].state = OPEN;
   }
   else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr*)(ip + sizeof(struct iphdr));
        struct udphdr *udp = (struct udphdr*)(ip + (2*sizeof(struct iphdr) + sizeof(struct icmphdr)));
        int port_index = port_to_port_index(htons(udp->uh_dport));
	    g_env.results[g_env.ite_ip].ports_result[port_index].port = htons(udp->uh_dport);
        g_env.results[g_env.ite_ip].ports_result[port_index].scan_results[g_env.scan_bit_to_index[5]].state = (icmp->code == 3) ? CLOSE : FILTERED;
   }
}

void	timeout_handler(int signal)
{
    (void)signal;
	pcap_breakloop(g_env.handle);
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

void pcap_thread(void *data) {
    int scan_bit = *(int*)data;

    t_map_function map_function[NB_SCAN] = {
        {packet_handler_SYN},
        {packet_handler_NULL},
        {packet_handler_ACK},
        {packet_handler_FIN},
        {packet_handler_XMAS},
        {packet_handler_UDP}
    };

    char *filter_exp = malloc(60);
    if (filter_exp == NULL) {
        error_exit("malloc failed", 1);
    }
    bzero(filter_exp, 60*sizeof(char));
    filter_exp = ft_strcat(filter_exp, "src host ");
    filter_exp = ft_strcat(filter_exp, inet_ntoa(g_env.ip_and_hosts[g_env.ite_ip].ip));
    filter_exp = ft_strcat(filter_exp, (((scan_bit&5) != 5) ? " and (tcp or icmp)" : " and (udp or icmp)"));

    char errbuf[100];
    bpf_u_int32 net;
    bpf_u_int32 mask;

    if (pcap_lookupnet("any", &net, &mask, errbuf) < 0) {
        error_exit("pcap_lookup: could not find network device", 1);
    }
    g_env.handle = pcap_open_live("any", BUFSIZ, 1, 100, errbuf);
    if (g_env.handle==NULL) {
        error_exit("pcap_open_live: could not open device", 1);
    }
    struct bpf_program fp;
    /* Compile and apply the filter */
	if (pcap_compile(g_env.handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(g_env.handle));
        error_exit("pcap_compile failed", 2);
    }
	if (pcap_setfilter(g_env.handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(g_env.handle));
        error_exit("pcap_setfilter failed", 2);
	}
	struct sigaction sa;

	sa.sa_handler = timeout_handler;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGALRM, &sa, NULL);
	alarm(g_env.timeout);

    void *a=NULL;
	// // https://cpp.hotexamples.com/fr/site/file?hash=0xcf42149af84f0b881f83b4cce88aca7e474429ea0e6df9b1ffddd94d9b46c087
    pthread_mutex_unlock(&(g_env.pcap_compile_m));
    while (true) {
	    int ret = pcap_dispatch(g_env.handle, -1, map_function[scan_bit].callback_function, (unsigned char *)&a);
        // if (ret >= 0) {
        //     printf("ret dispatch %d\n", ret);
        // }
        if (ret == -1) {
            printf("error: %s\n", strerror(errno));
            error_exit("error: pcap_dispatch failed", 1);
        }
        if (ret == -2) {
			// printf("breakloop: No packets\n");
            break ;
        }
    }
}

void setup_pcap(int *scan_bit) {
    pthread_mutex_lock(&(g_env.pcap_compile_m));
   if (pthread_create(g_env.pcap_thread, NULL, (void*)&pcap_thread, (void*)scan_bit) != 0) {
        printf("pcap thread failed\n");
        error_exit("pthread_create failed", 1);
    }
}
