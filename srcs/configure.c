#include "../incs/ft_nmap.h"

void configure_socket(void) {
    if ((g_env.socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        printf("%d %s\n", g_env.socket_fd, strerror(errno));
        error_exit("error: creating socket", 1);
    }
    int hincl = 1;
    if (setsockopt(g_env.socket_fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl)) < 0) {
        printf("%d %s\n", g_env.socket_fd, strerror(errno));
        error_exit("error: setsockopt", 1);
    }
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


char *get_working_interface_ip(void) {
	struct ifaddrs *ifap;
	struct ifaddrs *ifa;
	char *addr;

	addr = NULL;
	if (getifaddrs(&ifap) < 0)
		error_exit("Error getifaddrs", 1);
	ifa = ifap;
	while (ifa)
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
		nleft -= sizeof(unsigned short);
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

struct ip *configure_ip(char *buffer, int scan_type) {
    struct ip *ip;
    ip = (struct ip*)buffer;

    ip->ip_v = 4;
    ip->ip_hl = 5; // idk
    ip->ip_tos = 0;
    ip->ip_len = sizeof(struct ip) + ((scan_type^UDP) ? sizeof(struct tcphdr) : sizeof(struct udphdr));
	ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = g_env.ttl;
    ip->ip_p = (scan_type^UDP) ? IPPROTO_TCP : IPPROTO_UDP;
    ip->ip_sum = cksum((unsigned short*)ip, sizeof(struct ip));
	// printf("ip check %d\n", ip->ip_sum);

    char *interface = get_working_interface_ip();

    int ret = inet_pton(AF_INET, interface, &(ip->ip_src.s_addr));
	if (ret != 1) {
		printf("%d: errno: %s\n", ret, strerror(errno));
		error_exit("inet pton interface src failed", 3);
	}
    char *dst_ip_str = inet_ntoa(g_env.ip_and_hosts[g_env.ite_ip].ip);
	// printf("dst_ip_str = %s\n", dst_ip_str);
    ret = inet_pton(AF_INET, dst_ip_str, &(ip->ip_dst.s_addr));
	if (ret != 1) {
		printf("%d: errno: %s\n", ret, strerror(errno));
		error_exit("inet pton interface src failed", 3);
	}
    free(interface);

    return ip;
}


struct pseudo_header {
	uint32_t source;
	uint32_t dest;
	uint8_t reserved;
	uint8_t protocol;
	uint16_t len;
};

struct tcphdr* configure_tcp_header(char *buffer, int dst_port, int tcp_flags) {
    struct ip *ip = (struct ip *)buffer;
    struct tcphdr *tcp = (struct tcphdr *)(buffer + ip->ip_hl*4);

    tcp->source = htons(g_env.s_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(123);
    tcp->ack_seq = htonl(456);
    tcp->doff = 5;
    tcp->fin = (tcp_flags&FIN_F) ? 1 : 0;
    tcp->syn = (tcp_flags&SYN_F) ? 1 : 0;
    tcp->rst = (tcp_flags&RST_F) ? 1 : 0;
    tcp->psh = (tcp_flags&PSH_F) ? 1 : 0;
    tcp->ack = (tcp_flags&ACK_F) ? 1 : 0;
    tcp->urg = (tcp_flags&URG_F) ? 1 : 0;
    tcp->window = htons(8192);
    tcp->urg_ptr = 0;

	struct pseudo_header pseudo;
	pseudo.source = ip->ip_src.s_addr;
	pseudo.dest = ip->ip_dst.s_addr;
	pseudo.reserved = 0;
	pseudo.protocol = IPPROTO_TCP;
	pseudo.len = htons(sizeof(struct tcphdr))/*+ 20*/;
	char *pseudogram = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr));
	if (pseudogram==NULL) {
		error_exit("malloc pseudogram tcp failed", 1);
	}
	memcpy(pseudogram, (char*)&pseudo, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

	tcp->check = cksum((unsigned short*)pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr));
	ip->ip_sum = cksum((unsigned short*)buffer, ip->ip_len);
	// printf("tcp check %d\n", tcp->check);
	free(pseudogram);
    return tcp;
}

struct udphdr* configure_udp_header(char *buffer, int dst_port) {
    struct ip *ip = (struct ip *)buffer;
    
    struct udphdr *udp = (struct udphdr *)(buffer + ip->ip_hl*4);
    udp->source = htons(g_env.s_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr));
	
	struct pseudo_header pseudo;
	pseudo.source = ip->ip_src.s_addr;
	pseudo.dest = ip->ip_dst.s_addr;
	pseudo.reserved = 0;
	pseudo.protocol = IPPROTO_UDP;
	pseudo.len = htons(sizeof(struct udphdr))/*+ 20*/;
	char *pseudogram = malloc(sizeof(struct pseudo_header) + sizeof(struct udphdr));
	if (pseudogram==NULL) {
		error_exit("malloc pseudogram udp failed", 1);
	}
	memcpy(pseudogram, (char*)&pseudo, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), udp, sizeof(struct udphdr));

	udp->check = cksum((unsigned short*)pseudogram, sizeof(struct pseudo_header) + sizeof(struct udphdr));
	ip->ip_sum = cksum((unsigned short*)buffer, ip->ip_len);
    udp->check = cksum((unsigned short*)udp, sizeof(struct udphdr));
	free(pseudogram);
	// printf("udp check %d\n", udp->check);
    return udp;
}
