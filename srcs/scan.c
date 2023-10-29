#include "../incs/ft_nmap.h"

// https://www.kaitotek.com/resources/documentation/concepts/packet-filter/pcap-filter-syntax#pcap_filter_syntax-primitives-host
// void scan(char *buf, t_scanner scanner) {
//     char *dev = get_working_interface();
//     char errbuf[100];
//     bpf_u_int32 net;
//     bpf_u_int32 mask;

//     if (pcap_lookupnet(dev, &net, &mask, errbuf) < 0) {
//         error_exit("pcap_lookup: could not find network device", 1);
//     }
//     pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
//     if (handle==NULL) {
//         error_exit("pcap_open_live: could not open device", 1);
//     }
//     struct bfp_program fp;
//     /* Compile and apply the filter */
// 	if (pcap_compile(handle, &fp, scanner.filter_exp, 0, net) == -1) {
// 		fprintf(stderr, "Couldn't parse filter %s: %s\n", scanner.filter_exp, pcap_geterr(handle));
//         error_exit("pcap_compile", 2);
//     }
// 	if (pcap_setfilter(handle, &fp) == -1) {
// 		fprintf(stderr, "Couldn't install filter %s: %s\n", scanner.filter_exp, pcap_geterr(handle));
//         error_exit("pcap_setfilter", 2);
// 	}


// // ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
// //                const struct sockaddr *dest_addr, socklen_t addrlen);
//     sendto(g_env.socket_fd, buf, BUFSIZ, MSG_CONFIRM, g_env.ip_and_hosts[g_env.ite_ip].ip);
//     // https://cpp.hotexamples.com/fr/site/file?hash=0xcf42149af84f0b881f83b4cce88aca7e474429ea0e6df9b1ffddd94d9b46c087
//     int ret = pcap_dispatch(handle, 1, process_packet, (unsigned char *)scanner);
//     if (ret==0) {
//         // should do something here ??
//     }
//     // store result
//     return;
// }

void scan_thread(void *data) {
    t_scanner scanner = *(t_scanner *)data;

    char *buffer = (char*)malloc(PACKET_BUFFER_SIZE);
    if (buffer==NULL) {
        error_exit("malloc buffer configure_ip failed", 1);
    }
    
    bzero(buffer, PACKET_BUFFER_SIZE);


    configure_ip(buffer, scanner.ip_str, scanner.scan_type);
    if (scanner.scan_type^UDP) {
        configure_tcp_header(buffer, scanner.port, scanner.tcp_flags);
    }
    else {
        configure_udp_header(buffer, scanner.port);
    }

    // scan(buffer, scanner);
    g_env.results[g_env.ite_ip].ports_result[scanner.port_index].scan_results[g_env.scan_bit_to_index[scanner.scan_bit]].change_me = true;
    pthread_mutex_lock(&(g_env.launch_thread_m));
    g_env.threads_availability[scanner.thread_id] = true;
    pthread_mutex_unlock(&(g_env.launch_thread_m));
}