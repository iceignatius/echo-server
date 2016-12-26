#include <stdio.h>
#include <signal.h>
#include <gen/jmpbk.h>
#include <gen/timectr.h>
#include "listener.h"
#include "tcp_peer.h"
#include "tls_peer.h"

static bool go_terminate = false;

static
void signal_handler(int signum)
{
    if( signum == SIGQUIT || signum == SIGTERM )
        go_terminate = true;
}

int main(int argc, char *argv[])
{
    signal(SIGQUIT, signal_handler);

    epoll_encap_t epoll;
    epoll_encap_init(&epoll);

    listener_t tcp_listener;
    listener_init(&tcp_listener, &epoll, (int(*)(void*)) tcp_peer_proc);

    listener_t tls_listener;
    listener_init(&tls_listener, &epoll, (int(*)(void*)) tls_peer_proc);

    JMPBK_BEGIN
    {
        static const unsigned tcp_listen_port = 4220;
        if( !listener_start(&tcp_listener, tcp_listen_port) )
        {
            fprintf(stderr, "ERROR: TCP listener start failed!\n");
            JMPBK_THROW(0);
        }

        static const unsigned tls_listen_port = 4221;
        if( !listener_start(&tls_listener, tls_listen_port) )
        {
            fprintf(stderr, "ERROR: TLS listener start failed!\n");
            JMPBK_THROW(0);
        }

        static const unsigned ap_timeout  = 10*1000;
        timectr_t timer = timectr_init_inline(ap_timeout);
        while( !timectr_is_expired(&timer) && !go_terminate )
        {
            static const unsigned event_timeout = 500;
            epoll_encap_process_events(&epoll, event_timeout);
        }

        listener_stop(&tls_listener);
        tls_peer_wait_all_finished();

        listener_stop(&tcp_listener);
        tcp_peer_wait_all_finished();
    }
    JMPBK_END

    listener_deinit(&tls_listener);
    listener_deinit(&tcp_listener);

    epoll_encap_wait_all_events(&epoll);
    epoll_encap_deinit(&epoll);

    return 0;
}
