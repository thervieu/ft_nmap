#include "../incs/ft_nmap.h"

// https://www.kaitotek.com/resources/documentation/concepts/packet-filter/pcap-filter-syntax#pcap_filter_syntax-primitives-host
// void scan(char *filter_exp, struct ip *ip, char *buf, t_scanner scanner) {
//     char *dev = "eth0";
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
//     sruct bfp_program fp;
//     /* Compile and apply the filter */
// 	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
// 		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
// 		return(2);
// 	}
// 	if (pcap_setfilter(handle, &fp) == -1) {
// 		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
// 		return(2);
// 	}
//     sendto(g_env.socket, )
//     // https://cpp.hotexamples.com/fr/site/file?hash=0xcf42149af84f0b881f83b4cce88aca7e474429ea0e6df9b1ffddd94d9b46c087
//     int ret = pcap_dispatch(handle, 1, process_packet, (unsigned char *)scanner);
//     if (ret==0) {
//         should do something here ??
//     }
//     // store result
//     return;
// }

void scan_thread(void *data) {
    t_scanner scanner = *(t_scanner *)data;

    struct ip *ip;
    // struct tcphdr *tcp;
    // struct udphdr *udp;

    char *buffer = (char*)malloc(PACKET_BUFFER_SIZE);
    if (buffer==NULL) {
        error_exit("malloc buffer configure_ip failed", 1);
    }
    
    bzero(buffer, PACKET_BUFFER_SIZE);


    ip = configure_ip(buffer, scanner.ip_str, scanner.scan_type);
    (void)ip;
    // if (scanner.scan_type^UDP) {
    //     tcp = configure_tcp(buffer, );
    // }
    // else {
    //     udp = configure_udp();
    // }

    // scan()
    g_env.results[g_env.ite_ip].ports_result[scanner.port_index].scan_results[g_env.scan_bit_to_index[scanner.scan_bit]].change_me = true;
    pthread_mutex_lock(&(g_env.launch_thread_m));
    g_env.threads_availability[scanner.thread_id] = true;
    pthread_mutex_unlock(&(g_env.launch_thread_m));
}