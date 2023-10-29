#include "../incs/ft_nmap.h"

void configure_socket(int port_id) {
    if ((g_env.socket_fd = socket(AF_INET, SOCK_RAW, 0)) < 0) {
        printf("%d %s\n", g_env.socket_fd, strerror(errno));
        error_exit("error: creating socket", 1);
    }
    int hincl = 1;
    if (setsockopt(g_env.socket_fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl)) < 0) {
        error_exit("error: setsockopt", 1);
    }
	sockaddr_in sin; 

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port_id);
	sin.sin_addr = g_env.ip_and_hosts[g_env.ite_ip].ip;
	bind(g_env.socket_fd, (struct sockaddr *)&sin, sizeof(sin));
}

int	ft_strcmp(const char *s1, const char *s2)
{
	while (*s1 != '\0')
	{
		if (*s2 == '\0')
			return (1);
		if (*s1 > *s2)
			return (1);
		if (*s2 > *s1)
			return (-1);
		s1++;
		s2++;
	}
	if (*s2 != '\0')
		return (-1);
	return (0);
}

char	*ft_strdup(const char *src)
{
	char	*dest;
	int		i;

	i = 0;
	while (src[i] != '\0')
		i++;
	if ((dest = malloc(sizeof(src[0]) * (i + 1))) == NULL)
		return (NULL);
	i = 0;
	while (src[i])
	{
		dest[i] = src[i];
		i++;
	}
	dest[i] = '\0';
	return (dest);
}

char *get_working_interface(void) {
	struct ifaddrs *ifap;
	struct ifaddrs *ifa;
	char *addr;

	addr = NULL;
	if (getifaddrs(&ifap) < 0)
		error_exit("Error getifaddrs", 1);
	ifa = ifap;
	while (ifa->ifa_next != NULL)
	{
		if (ifa->ifa_addr->sa_family == AF_INET && ft_strcmp(ifa->ifa_name, g_env.device) == 0)
		{
			addr = ft_strdup(inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr));
			break;
		}
		ifa = ifa->ifa_next;
	}
	freeifaddrs(ifap);
    if (addr==NULL) {
        error_exit("get_my_interface failed", 1);
    }
	return (addr);
}

struct ip *configure_ip(char *buffer, char *ip_dst, int scan_type) {
    struct ip *ip;
    ip = (struct ip*)buffer;

    ip->ip_v = 4;
    ip->ip_hl = 5; // idk
    ip->ip_tos = 0;
    ip->ip_len = sizeof(struct ip) + (scan_type^UDP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
    ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 64; // option ttl
    ip->ip_p = (scan_type^UDP) ? IPPROTO_TCP : IPPROTO_UDP;
    ip->ip_sum = 0;

    char *interface = get_working_interface();

    inet_pton(AF_INET, interface, &(ip->ip_src.s_addr));
    inet_pton(AF_INET, ip_dst, &(ip->ip_dst.s_addr));
    free(interface);

    return ip;
}

unsigned short	cksum(unsigned short *addr, int len)
{
	int				nleft;
	int				sum;
	unsigned short	*w;
	unsigned short	ans;

	nleft = len;
	w = addr;
	sum = 0;
	ans = 0;
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
	{
		*(unsigned char *)(&ans) = *(unsigned char *)w;
		sum += ans;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	ans = ~sum;
	return (ans);
}

struct tcphdr* configure_tcp_header(char *buffer, int dst_port, int tcp_flags) {
    struct iphdr *ip = (struct iphdr *)buffer;
    
    struct tcphdr *tcp = (struct tcphdr *)(buffer + ip->ihl*4);
    // some options were not verified
    // seq, ack seq, doff, window, urg_ptr, check
    tcp->source = htons(g_env.src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(123);
    tcp->ack_seq = htonl(456);
    tcp->doff = 5;
    tcp->fin = tcp_flags&FIN_F;
    tcp->syn = tcp_flags&SYN_F;
    tcp->rst = tcp_flags&RST_F;
    tcp->psh = tcp_flags&PSH_F;
    tcp->ack = tcp_flags&ACK_F;
    tcp->urg = tcp_flags&URG_F;
    tcp->window = htons(8192);
    tcp->urg_ptr = 0;
    tcp->check = cksum((unsigned short *)ip, ip->ihl); // htons? will likely need sub function because TPC_LEN != UDP_LEN
    return tcp;
}

struct udphdr* configure_udp_header(char *buffer, int dst_port) {
    struct iphdr *ip = (struct iphdr *)buffer;
    
    struct udphdr *udp = (struct udphdr *)(buffer + ip->ihl*4);
    udp->source = htons(g_env.src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr));
    udp->check = cksum((unsigned short *)ip, ip->ihl); // htons? will likely need sub function because TPC_LEN != UDP_LEN
    return udp;
}
