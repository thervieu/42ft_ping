#include "../incs/ft_ping.h"

void usage_error(void) {
    printf("usage: ./ft_ping [-v] HOST\n");
    exit(1);
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

void open_socket(t_env *env) {
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

int main(int ac, char **av) {
    if (ac < 2) {
        usage_error();
    }
    if (getuid() != 0) {
        error_exit("should be uid 0");
    }
    signal(SIGINT, signal_handler);

    init_env(&env);
    open_socket(&env);

    arg_handler(&env, ac, av);
}
