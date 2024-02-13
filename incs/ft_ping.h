#ifndef FT_PING_H
# define FT_PING_H

# include <unistd.h>
# include <stdio.h>
# include <signal.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netdb.h>
# include <sys/time.h>
# include <stdbool.h>
# include <stdlib.h>
# include <float.h>
# include <math.h>

typedef struct s_env {

    // names
    char *hostname;
    char *host_dst;
    char *host_src;

    // communication structures
    pid_t pid;
    struct ip *ip;
    struct icmp *icmp;
    struct addrinfo hints;
    struct addrinfo *res;
    char buffer[1000];

    struct iovec iov[1];
    struct msghdr msg;
    char buffer_control[1000];
    //  -f

    // communication data
    unsigned int sequence;
    unsigned int count;
    unsigned int interval;

    bool flood; // floods the ECHO requests, ECHO_REQUEST adds a ".", ECHO_REPLY is a backspace \b. bonus -f
    bool numeric; // just don't print the weird sub dns rebound. bonus -n
    bool pattern; // if set sequence is a set number that doesn't increment. given as a 2 bytes hexa number "00" to "XX". bonus -p
    unsigned int timeout; // 0 by default (infinite). bonus -W 
    unsigned int ttl; // 64 by default,=. bonus -ttl

    // socket
    int socket_fd;

    // calculus data
    unsigned int packets_sent;
    unsigned int packets_recv;
    double min;
    double max;
} t_env;

t_env env;

#endif