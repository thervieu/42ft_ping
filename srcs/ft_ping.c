#include "../incs/ft_ping.h"

void usage_error(void) {
    printf("usage: ./ft_ping [-h, -f, -n -p, -W, -ttl] hostname\n");
    printf("\t\t./ft_ping -h to print the help\n");
    exit(1);
}

void help_and_exit(void) {
    printf("FT_PING: help:\nusage: ./ft_ping [-h, -f, -n -p, -W, -ttl] hostname\n");
    printf("\t\t-h\n\t\t\tprint this help\n\n");
    printf("\t\t-f\n\t\t\tFlood ping. For every ECHO_REQUEST sent a period “.” is printed, while for ");
    printf("every ECHO_REPLY received a backspace is printed.\n\n");
    printf("\t\t-n\n\t\t\tNumeric output only. No attempt will be made to lookup symbolic names for host addresses.\n");
    printf("\t\t-p pattern\n\t\t\tYou may specify up to 16 “pad” bytes to fill out the packet you send. This is useful for diagnosing");
    printf(" data-dependent problems in a network. For example, -p ff will cause the sent packet to be filled with all ones.\n\n");
    printf("\t\t-W timeout\n\t\t\tTime to wait for a response, in seconds. The option affects only timeout in absence of any responses, otherwise");
    printf(" ping waits for two RTTs. Real number allowed with dot as a decimal separator (regardless locale setup). 0 means infinite timeout.\n\n");
    printf("\t\t-t ttl\n\t\t\tping only. Set the IP Time to Live.\n");
    exit(0);
}

void error_exit(char *err) {
    printf("ft_ping: %s\n", err);
    exit(1);
}

size_t ft_strlen(char *s) {
    size_t i = 0;
    while (s[i] != '\0') {
        i++;
    }
    return i;
}

size_t ft_strcmp(char *s1, char *s2) {
    if (ft_strlen(s1) != ft_strlen(s2)) {
        return 1;
    }
    for (size_t i = 0; i < ft_strlen(s1); i ++) {
        if (s1[i] != s2[i])
            return 1;
        if (s1[i] == '\0' || s2[i] == '\0')
            break ;
    }
    return 0;
}

void	*ft_memset(void *b, int c, size_t len)
{
	size_t			i;
	unsigned char	*ptr;

	i = 0;
	ptr = (unsigned char *)b;
	while (i < len)
		ptr[i++] = (unsigned char)c;
	return (b);
}

void print_stats(t_env *env) {
    (void)env;
    printf("print_stats\n");
    exit(0);
}


void signal_handler(int signal) {
    if (signal == SIGINT) {
        print_stats(&env);
    }
    return ;
}


char *get_ip_from_hostname(char *hostname) {
    struct addrinfo hints;
    struct addrinfo *res;
    struct sockaddr_in *sa_in;
    
    ft_memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status < 0) {
        error_exit("getaddrinfo failed");
    }

    sa_in = (struct sockaddr_in *)res->ai_addr;
    char *ip_address = malloc(INET_ADDRSTRLEN*sizeof(char));
    if (ip_address == NULL) {
        freeaddrinfo(res);
        error_exit("malloc failed");
    }

    if (inet_ntop(res->ai_family, &(sa_in->sin_addr),  ip_address, INET_ADDRSTRLEN) == NULL) {
        freeaddrinfo(res);
        free(ip_address);
        error_exit("inet_ntop failed");
    }

    freeaddrinfo(res);
    return ip_address;
}

void create_socket(t_env *env) {
    env->host_src = "0.0.0.0"; // us
    env->host_dst = get_ip_from_hostname(env->hostname);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        error_exit("socket failed");
    }
    env->socket_fd = sockfd;
}

void init_env(t_env *env) {
    env->pid = getpid();
    env->sequence = 0;
    env->count = 0;
    env->interval = 1;

    // bonuses default
    env->timeout = 0;
    env->ttl = 64;
    env->flood = false;
    env->numeric = false;
    env->pattern = false;
}

void arg_handler(t_env *env, int ac, char **av) {
    char *hostname = NULL;
    for (int i = 1; i < ac; i++) {
        if (hostname == NULL) {
            hostname = av[i];
        } else {
            error_exit("too many arguments");
        }
    }
    env->hostname = hostname;
    return ;
}


short ft_checksum(unsigned short *data, int len) {
    unsigned long checksum = 0;

    while (len > 1) {
        checksum += *data++;
        len -= sizeof(unsigned short);
    }
    if (len)
        checksum += *(unsigned char*)data;

    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    return (short)~checksum;
}

void print_host(t_env env) {
    printf("PING %s (%s) 56(84) bytes of data.\n", env.hostname, env.host_dst);
}

void flood_loop(t_env *env) {
    (void)env;
    return ;
}

void ping_loop(t_env *env) {
    (void)env;
    return ;
}

int main(int ac, char **av) {
    if (ac < 2) {
        usage_error();
    }
    if (getuid() != 0) {
        error_exit("should be uid 0");
    }
    signal(SIGINT, signal_handler);

    init_env(&env); // set default values
    arg_handler(&env, ac, av); // get hostname and options

    create_socket(&env); // create socket

    env.ip = (struct ip *)env.buffer;
    env.icmp = (struct icmp *)(env.ip + 1);
    print_host(env);
    if (env.flood) {
        env.interval = 0; // /!\ only if not set. Only the super-user may use this option with zero interval. 
        flood_loop(&env);
    } else {
        ping_loop(&env);
    }
    return 0;
}
