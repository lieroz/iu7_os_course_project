#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/unistd.h>
#include <linux/wait.h>

#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>

#define DEFAULT_PORT 8080
#define MAX_CONNS 16

int tcp_listener_stopped = 0;
int tcp_acceptor_stopped = 0;

struct tcp_conn_handler_data {
    struct sockaddr_in *address;
    struct socket *accept_socket;
    int thread_id;
};

struct tcp_conn_handler {
    struct tcp_conn_handler_data *data[MAX_CONNS];
    struct task_struct *thread[MAX_CONNS];
    int tcp_conn_handler_stopped[MAX_CONNS];
};

struct tcp_conn_handler *tcp_conn_handler;


struct tcp_server_service {
    int running;
    struct socket *listen_socket;
    struct task_struct *thread;
    struct task_struct *accept_thread;
};

struct tcp_server_service *tcp_server;

