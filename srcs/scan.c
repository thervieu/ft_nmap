#include "../incs/ft_nmap.h"

// void print_buffer_tcp()

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // This is the callback function that will be called for each captured packet.
    // You can process the packet data here.
    printf("packet_handler\n");
    (void)packet;
    t_scanner *scanner = (t_scanner*)user;
    printf("thread %d: port %d: scan type %d: Packet captured, length: %d\n", scanner->thread_id, scanner->port, scanner->scan_type, pkthdr->len);
    // Add your packet processing code here
}

// https://www.kaitotek.com/resources/documentation/concepts/packet-filter/pcap-filter-syntax#pcap_filter_syntax-primitives-host
void scan(char *buf, t_scanner scanner, struct ip *ip) {
    char errbuf[100];
    bpf_u_int32 net;
    bpf_u_int32 mask;

    pthread_mutex_lock(&(g_env.pcap_compile_m));
    if (pcap_lookupnet(g_env.device, &net, &mask, errbuf) < 0) {
        error_exit("pcap_lookup: could not find network device", 1);
    }
    pcap_t *handle = pcap_open_live(g_env.device, BUFSIZ, 1, 1000, errbuf);
    if (handle==NULL) {
        error_exit("pcap_open_live: could not open device", 1);
    }
    struct bpf_program fp;
    /* Compile and apply the filter */
	if (pcap_compile(handle, &fp, scanner.filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", scanner.filter_exp, pcap_geterr(handle));
        error_exit("pcap_compile", 2);
    }
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", scanner.filter_exp, pcap_geterr(handle));
        error_exit("pcap_setfilter", 2);
	}
    pthread_mutex_unlock(&(g_env.pcap_compile_m));

	struct sockaddr sin; 
    bzero(&sin, sizeof(struct sockaddr));

	sin.sa_family = AF_INET;
	// sin.dest_addr = AF_INET;

    printf("thread %d: port %d: scan type %d: sendto %d\n", scanner.thread_id, scanner.port, scanner.scan_type, ip->ip_len);
    int ret_sendto = sendto(g_env.socket_fd, buf, ip->ip_len, 0, &sin, sizeof(struct sockaddr));
    printf("thread %d: ret sendto = |%d|\n", scanner.thread_id, ret_sendto);
    if (ret_sendto < 0)
        printf("errno: %s\n", strerror(errno));
    // https://cpp.hotexamples.com/fr/site/file?hash=0xcf42149af84f0b881f83b4cce88aca7e474429ea0e6df9b1ffddd94d9b46c087
    int ret = pcap_dispatch(handle, 1, packet_handler, (unsigned char *)&scanner);
    printf("thread %d: ret pcap_dispatch = %d\n\n", scanner.thread_id, ret);
    if (ret==0) {
        // should do something here ??
    }
    // store result
    return;
}

void scan_thread(void *data) {
    t_scanner scanner = *(t_scanner *)data;

    char *buffer = (char*)malloc(PACKET_BUFFER_SIZE);
    if (buffer==NULL) {
        error_exit("malloc buffer configure_ip failed", 1);
    }
    
    bzero(buffer, PACKET_BUFFER_SIZE);

    struct ip *ip =  configure_ip(buffer, scanner.scan_type);
    if (scanner.scan_type^UDP) {
        configure_tcp_header(buffer, scanner.port, scanner.tcp_flags);
        // print_buffer_tcp(buffer);
    }
    else {
        configure_udp_header(buffer, scanner.port);
    }

    scan(buffer, scanner, ip);
    g_env.results[g_env.ite_ip].ports_result[scanner.port_index].scan_results[g_env.scan_bit_to_index[scanner.scan_bit]].change_me = true;
    pthread_mutex_lock(&(g_env.launch_thread_m));
    g_env.threads_availability[scanner.thread_id] = true;
    pthread_mutex_unlock(&(g_env.launch_thread_m));
}