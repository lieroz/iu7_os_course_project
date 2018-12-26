
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>

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

#include <linux/kthread.h>

#define DEFAULT_PORT 8080
#define MODULE_NAME "tmem_tcp_server"
#define MAX_CONNS 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kamakin Andrey");

static int tcp_listener_stopped = 0;
static int tcp_acceptor_stopped = 0;

DEFINE_SPINLOCK(tcp_server_lock);

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

static struct tcp_conn_handler *tcp_conn_handler;


struct tcp_server_service {
    int running;
    struct socket *listen_socket;
    struct task_struct *thread;
    struct task_struct *accept_thread;
};

static struct tcp_server_service *tcp_server;

char *inet_ntoa(struct in_addr *in)
{
    char *str_ip = NULL;
    u_int32_t int_ip = 0;

    if (!(str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL))) {
        return NULL;
    } else {
        memset(str_ip, 0, 16);
    }

    int_ip = in->s_addr;
    sprintf(str_ip, "%d.%d.%d.%d", (int_ip) & 0xFF, (int_ip >> 8) & 0xFF, (int_ip >> 16) & 0xFF, (int_ip >> 16) & 0xFF);

    return str_ip;
}

int tcp_server_send(struct socket *sock, int id, const char *buf, const size_t length, unsigned long flags)
{
    struct msghdr msg;
    struct kvec vec;
    int len, written = 0, left = length;
    mm_segment_t oldmm;

    msg.msg_name    = 0;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = flags;
    msg.msg_flags   = 0;

    oldmm = get_fs();
    set_fs(KERNEL_DS);

    while (1) {
        vec.iov_len = left;
        vec.iov_base = (char *)buf + written;
        len = kernel_sendmsg(sock, &msg, &vec, left, left);

        if ((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) && (len == -EAGAIN))) {
            continue;
        }

        if (len > 0) {
            written += len;
            left -= len;

            if (!left) {
                break;
            }
        }
    }

    set_fs(oldmm);
    return written ? written : len;
}

int tcp_server_receive(struct socket *sock, int id, struct sockaddr_in *address, unsigned char *buf, int size, unsigned long flags)
{
    struct msghdr msg;
    struct kvec vec;
    int len;
    char *tmp = NULL;

    if (sock == NULL) {
        pr_info(" *** mtp | tcp server receive socket is NULL | tcp_server_receive *** \n");
        return -1;
    }

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = flags;

    vec.iov_len = size;
    vec.iov_base = buf;

    while (1) {
        if (!skb_queue_empty(&sock->sk->sk_receive_queue)) {
            pr_info("recv queue empty ? %s \n", skb_queue_empty(&sock->sk->sk_receive_queue) ? "yes" : "no");
        }

        len = kernel_recvmsg(sock, &msg, &vec, size, size, flags);

        if (len != -EAGAIN && len != -ERESTARTSYS) {
            break;
        }
    }

    tmp = inet_ntoa(&(address->sin_addr));
    pr_info("client-> %s:%d, says: %s\n", tmp, ntohs(address->sin_port), buf);
    kfree(tmp);

    return len;
}

int connection_handler(void *data)
{
    struct tcp_conn_handler_data *conn_data = (struct tcp_conn_handler_data *)data;
    struct sockaddr_in *address = conn_data->address;
    struct socket *accept_socket = conn_data->accept_socket;

    int id = conn_data->thread_id;
    int ret;
    int len = 49;
    unsigned char in_buf[len + 1];
    unsigned char out_buf[len + 1];

    DECLARE_WAITQUEUE(recv_wait, current);
    allow_signal(SIGKILL | SIGSTOP);

    while (1) {
        add_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);

        while (skb_queue_empty(&accept_socket->sk->sk_receive_queue)) {
            __set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(HZ);

            if (kthread_should_stop()) {
                pr_info(" *** mtp | tcp server handle connection thread stopped | connection_handler *** \n");
                tcp_conn_handler->tcp_conn_handler_stopped[id] = 1;

                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);
                kfree(tcp_conn_handler->data[id]->address);
                kfree(tcp_conn_handler->data[id]);
                sock_release(tcp_conn_handler->data[id]->accept_socket);

                return 0;
            }

            if (signal_pending(current)) {
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);
                goto release;
            }
        }

        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);

        pr_info("receiving message\n");
        memset(in_buf, 0, len + 1);
        ret = tcp_server_receive(accept_socket, id, address, in_buf, len, MSG_DONTWAIT);

        if (ret > 0) {
            memset(out_buf, 0, len + 1);
            memcmp(in_buf, "done", 4) == 0 ? strcat(out_buf, "See you again...") : strcat(out_buf, in_buf);
            pr_info("sending response: %s\n", out_buf);
            tcp_server_send(accept_socket, id, out_buf, strlen(out_buf), MSG_DONTWAIT);

            if (memcmp(in_buf, "done", 4) == 0) break;
        }
    }

release:
    tcp_conn_handler->tcp_conn_handler_stopped[id] = 1;
    kfree(tcp_conn_handler->data[id]->address);
    kfree(tcp_conn_handler->data[id]);
    sock_release(tcp_conn_handler->data[id]->accept_socket);
    tcp_conn_handler->thread[id] = NULL;

    do_exit(0);
}

int tcp_server_accept(void)
{
    struct socket *socket;
    struct socket *accept_socket = NULL;
    struct inet_connection_sock *isock;
    int accept_err = 0, id = 0;

    DECLARE_WAITQUEUE(accept_wait, current);
    allow_signal(SIGKILL | SIGSTOP);

    socket = tcp_server->listen_socket;
    pr_info(" *** mtp | creating the accept socket | tcp_server_accept *** \n");

    while (1) {
        struct tcp_conn_handler_data *data = NULL;
        struct sockaddr_in *client = NULL;
        char *tmp;
        int addr_len;
        accept_err = sock_create(socket->sk->sk_family, socket->type, socket->sk->sk_protocol, &accept_socket);

        if (accept_err < 0 || !accept_socket) {
            pr_info(" *** mtp | accept_error: %d while creating tcp server accept socket | tcp_server_accept *** \n", accept_err);
            goto err;
        }

        accept_socket->type = socket->type;
        accept_socket->ops  = socket->ops;
        isock = inet_csk(socket->sk);
        add_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);

        while (reqsk_queue_empty(&isock->icsk_accept_queue)) {
            __set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(HZ);

            if (kthread_should_stop()) {
                pr_info(" *** mtp | tcp server acceptor thread stopped | tcp_server_accept *** \n");
                tcp_acceptor_stopped = 1;
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
                sock_release(accept_socket);
                return 0;
            }

            if (signal_pending(current)) {
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
                goto release;
            }

        }

        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
        pr_info("accept connection\n");
        accept_err = socket->ops->accept(socket, accept_socket, O_NONBLOCK, false);

        if (accept_err < 0) {
            pr_info(" *** mtp | accept_error: %d while accepting tcp server | tcp_server_accept *** \n", accept_err);
            goto release;
        }

        client = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
        memset(client, 0, sizeof(struct sockaddr_in));
        addr_len = sizeof(struct sockaddr_in);
        accept_err = accept_socket->ops->getname(accept_socket, (struct sockaddr *)client, addr_len);

        if (accept_err < 0) {
            pr_info(" *** mtp | accept_error: %d in getname tcp server | tcp_server_accept *** \n", accept_err);
            goto release;
        }

        tmp = inet_ntoa(&(client->sin_addr));
        pr_info("connection from: %s %d \n", tmp, ntohs(client->sin_port));
        kfree(tmp);
        pr_info("handle connection\n");

        for (id = 0; id < MAX_CONNS; id++) {
            if (tcp_conn_handler->thread[id] == NULL)
                break;
        }

        pr_info("gave free id: %d\n", id);

        if (id == MAX_CONNS) {
            goto release;
        }

        data = kmalloc(sizeof(struct tcp_conn_handler_data), GFP_KERNEL);
        memset(data, 0, sizeof(struct tcp_conn_handler_data));

        data->address = client;
        data->accept_socket = accept_socket;
        data->thread_id = id;

        tcp_conn_handler->tcp_conn_handler_stopped[id] = 0;
        tcp_conn_handler->data[id] = data;
        tcp_conn_handler->thread[id] = kthread_run((void *)connection_handler, (void *)data, MODULE_NAME);

        if (kthread_should_stop()) {
            pr_info(" *** mtp | tcp server acceptor thread stopped | tcp_server_accept *** \n");
            tcp_acceptor_stopped = 1;
            return 0;
        }

        if (signal_pending(current)) {
            break;
        }
    }

release:
    sock_release(accept_socket);

err:
    tcp_acceptor_stopped = 1;
    do_exit(0);
}

int tcp_server_listen(void)
{
    int server_err;
    struct socket *conn_socket;
    struct sockaddr_in server;

    DECLARE_WAIT_QUEUE_HEAD(wq);
    allow_signal(SIGKILL | SIGTERM);

    if ((server_err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &tcp_server->listen_socket)) < 0) {
        pr_info(" *** mtp | Error: %d while creating tcp server listen socket | tcp_server_listen *** \n", server_err);
        goto err;
    }

    conn_socket = tcp_server->listen_socket;
    tcp_server->listen_socket->sk->sk_reuse = 1;

    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_family = AF_INET;
    server.sin_port = htons(DEFAULT_PORT);

    if ((server_err = conn_socket->ops->bind(conn_socket, (struct sockaddr*)&server, sizeof(server))) < 0) {
        pr_info(" *** mtp | Error: %d while binding tcp server listen socket | tcp_server_listen *** \n", server_err);
        goto release;
    }

    if ((server_err = conn_socket->ops->listen(conn_socket, MAX_CONNS)) < 0) {
        pr_info(" *** mtp | Error: %d while listening in tcp server listen socket | tcp_server_listen *** \n", server_err);
        goto release;
    }

    tcp_server->accept_thread = kthread_run((void*)tcp_server_accept, NULL, MODULE_NAME);

    while (1) {
        wait_event_timeout(wq, 0, 3 * HZ);

        if (kthread_should_stop()) {
            pr_info(" *** mtp | tcp server listening thread stopped | tcp_server_listen *** \n");
            return 0;
        }

        if (signal_pending(current)) {
            break;
        }
    }

release:
    sock_release(conn_socket);

err:
    tcp_listener_stopped = 1;
    do_exit(0);
}

int tcp_server_start(void)
{
    tcp_server->running = 1;
    tcp_server->thread = kthread_run((void *)tcp_server_listen, NULL, MODULE_NAME);
    return 0;
}

static int __init network_server_init(void)
{
    pr_info(" *** mtp | network_server initiated | network_server_init ***\n");
    tcp_server = kmalloc(sizeof(struct tcp_server_service), GFP_KERNEL);
    memset(tcp_server, 0, sizeof(struct tcp_server_service));

    tcp_conn_handler = kmalloc(sizeof(struct tcp_conn_handler), GFP_KERNEL);
    memset(tcp_conn_handler, 0, sizeof(struct tcp_conn_handler));

    tcp_server_start();
    return 0;
}

static void __exit network_server_exit(void)
{
    int ret;
    int id;

    if (tcp_server->thread == NULL)
        pr_info(" *** mtp | No kernel thread to kill | network_server_exit *** \n");
    else {
        for (id = 0; id < MAX_CONNS; id++) {
            if (tcp_conn_handler->thread[id] != NULL) {

                if (!tcp_conn_handler->tcp_conn_handler_stopped[id]) {
                    ret = kthread_stop(tcp_conn_handler->thread[id]);

                    if (!ret)
                        pr_info(" *** mtp | tcp server connection handler thread: %d stopped | network_server_exit *** \n", id);
                }
            }
        }

        if (!tcp_acceptor_stopped) {
            ret = kthread_stop(tcp_server->accept_thread);
            if (!ret)
                pr_info(" *** mtp | tcp server acceptor thread stopped | network_server_exit *** \n");
        }

        if (!tcp_listener_stopped) {
            ret = kthread_stop(tcp_server->thread);
            if (!ret)
                pr_info(" *** mtp | tcp server listening thread stopped | network_server_exit *** \n");
        }


        if (tcp_server->listen_socket != NULL && !tcp_listener_stopped) {
            sock_release(tcp_server->listen_socket);
            tcp_server->listen_socket = NULL;
        }

        kfree(tcp_conn_handler);
        kfree(tcp_server);
        tcp_server = NULL;
    }

    pr_info(" *** mtp | network server module unloaded | network_server_exit *** \n");
}

module_init(network_server_init)
module_exit(network_server_exit)
