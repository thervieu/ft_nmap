#include "ft_nmap.h"

static int		lookup_host(char *host, int ip_idx)
{
	char			name[255];
	struct addrinfo		*res;
	struct addrinfo		*to_free;
	struct addrinfo		hints;
	struct sockaddr_in	dst;

	memset(&dst, 0, sizeof(struct sockaddr_in));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = AI_CANONNAME;
	if (getaddrinfo(host, NULL, &hints, &res) != 0)
	{
		printf("./ft_nmap: warning: No address associated with hostname %s\n", host);
		return (-1);
	}
	dst = (*(struct sockaddr_in *)res->ai_addr);
	g_env.ip_and_hosts[ip_idx].ip = dst.sin_addr;
	g_env.ip_and_hosts[ip_idx].canonname = ft_strdup(res->ai_canonname);
	g_env.ip_and_hosts[ip_idx].dst_addr = dst;
	while (res != NULL)
	{
		getnameinfo((struct sockaddr *)&dst, sizeof(struct sockaddr), name, 255, NULL, 0, NI_NUMERICSERV);
		to_free = res;
		g_env.ip_and_hosts[ip_idx].nameinfo = ft_strdup(name);
		res = res->ai_next;
		free(to_free->ai_canonname);
		free(to_free);
	}
	return (0);
}

int				get_ip_addr(char *host, int ip_idx)
{
	struct in_addr		addr;

	if (inet_pton(AF_INET, host, &addr) == 1)
		g_env.ip_and_hosts[ip_idx].nameinfo = host;
	return (lookup_host(host, ip_idx));
}
