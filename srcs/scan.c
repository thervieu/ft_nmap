#include "../incs/ft_nmap.h"

// https://www.kaitotek.com/resources/documentation/concepts/packet-filter/pcap-filter-syntax#pcap_filter_syntax-primitives-host
void scan(char *buf, t_scanner scanner, struct ip *ip) {
	struct sockaddr sin; 
    bzero(&sin, sizeof(struct sockaddr));
	sin.sa_family = AF_INET;

    struct pollfd fds[1];
    memset(fds, 0 , sizeof(fds));
    fds[0].fd = g_env.socket_fd;
    fds[0].events = POLLOUT | POLLERR;

    int ret = 0;
    int ret_sendto = -1;
    while (true) {
        ret = poll(fds, 1, 1000);
        if (ret>0) {
            if (fds[0].revents & POLLOUT) {
                ret_sendto = sendto(g_env.socket_fd, buf, ip->ip_len, 0, (struct sockaddr *)&g_env.ip_and_hosts[g_env.ite_ip].dst_addr, sizeof(struct sockaddr_in));
                if (ret_sendto < 0) {
                    printf("thread %d: sendto failed errno: %s\n", scanner.thread_id, strerror(errno));
                    printf("poll revents %d\n", fds[0].revents);
                    // error_exit("sendto failed\n", 1);
                }
            }
            else {
                printf("poll revents %d\n", fds[0].revents);
            }
            break ;
        }
        else if (ret == 0) {
            printf("poll timeout\n");
            break ;
        }
        else if (ret < 0) {
            error_exit("poll failed", 1);
        }
    }
    // printf("thread %d: scan 0x%x: port %d:ret sendto = |%d|\n", scanner.thread_id, scanner.scan_type, scanner.port, ret_sendto);
    
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
    }
    else {
        configure_udp_header(buffer, scanner.port);
    }


    scan(buffer, scanner, ip);
    // g_env.results[g_env.ite_ip].ports_result[scanner.port_index].scan_results[g_env.scan_bit_to_index[scanner.scan_bit]].change_me = true;
    pthread_mutex_lock(&(g_env.launch_thread_m));
    g_env.threads_availability[scanner.thread_id] = true;
    pthread_mutex_unlock(&(g_env.launch_thread_m));
}
