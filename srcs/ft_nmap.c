#include "../incs/ft_nmap.h"

void error_exit(char *err, int code) {
    if (err != NULL) {
        printf("ft_nmap: %s\n", err);
    }
    exit(code);
}

void usage(void) {
    printf("usage: ft_nmap [options] ip_to_scan\n");
}

int main(int ac, char **av) {
    if (ac < 2) {
        usage();
        error_exit(NULL, 255);
    }
    (void)av;
    
}