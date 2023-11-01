#include "../incs/ft_nmap.h"


void packet_handler_SYN(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // This is the callback function that will be called for each captured packet.
    // You can process the packet data here.
    (void)user;
    // (void)packet;
    (void)pkthdr;
    printf("SYN Packet captured, ip packet length: %ld\n", sizeof(packet));
    struct sll_header *sll = (struct sll_header *)packet;
    struct iphdr *ip = (struct iphdr*)(packet+sizeof(struct sll_header));
    printf("sll size %ld\n", sizeof(sll));
    printf("sll hatype 0x%x\n", ntohs(sll->sll_hatype));
    printf("sll halen 0x%x\n", ntohs(sll->sll_halen));
    printf("ip tot len 0x%x\n", ntohs(ip->tot_len));
    for (int i = 0; i < 60 ; i+=1) {
        printf("%02x ", packet[i]);
        if (i==0) {
            continue;
        }
        if ((i+2) % 8 == 0) {
            printf(" ");
        }
        if ((i+2) % 16 == 0) {
            printf("\n");
        } 
    }
    printf("\n");
    // Add your packet processing code here
}

void packet_handler_NULL(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // This is the callback function that will be called for each captured packet.
    // You can process the packet data here.
    (void)packet;
    (void)user;
    printf("NULL Packet captured, length: %d\n", pkthdr->len);
    // Add your packet processing code here
}

void packet_handler_ACK(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // This is the callback function that will be called for each captured packet.
    // You can process the packet data here.
    (void)packet;
    (void)user;
    printf("ACK Packet captured, length: %d\n", pkthdr->len);
    // Add your packet processing code here
}

void packet_handler_FIN(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // This is the callback function that will be called for each captured packet.
    // You can process the packet data here.
    (void)packet;
    (void)user;
    printf("FIN Packet captured, length: %d\n", pkthdr->len);
    // Add your packet processing code here
}


void packet_handler_XMAS(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // This is the callback function that will be called for each captured packet.
    // You can process the packet data here.
    (void)packet;
    (void)user;
    printf("XMAS Packet captured, length: %d\n", pkthdr->len);
    // Add your packet processing code here
}

void packet_handler_UDP(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // This is the callback function that will be called for each captured packet.
    // You can process the packet data here.
    (void)packet;
    (void)user;
    printf("UDP Packet captured, length: %d\n", pkthdr->len);
    // Add your packet processing code here
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
    g_env.handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
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
        if (ret >= 0) {
            printf("ret dispatch %d\n", ret);
        }
        if (ret == -1) {
            error_exit("error: pcap_dispatch failed", 1);
        }
        if (ret == -2) {
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
