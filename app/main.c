#include <stdio.h>
#include <gen/jmpbk.h>
#include <gen/timectr.h>
#include "listener.h"
#include "tcp_peer.h"

int main(int argc, char *argv[])
{
    epoll_encap_t epoll;
    epoll_encap_init(&epoll);

    listener_t listener;
    listener_init(&listener, &epoll, (int(*)(void*)) tcp_peer_proc);

    JMPBK_BEGIN
    {
        static const unsigned listen_port = 4220;
        sockaddr_t listen_addr;
        sockaddr_init_value(&listen_addr, ipv4_const_any, listen_port);

        if( !listener_start(&listener, &listen_addr) )
        {
            fprintf(stderr, "ERROR: Listener start failed!\n");
            JMPBK_THROW(0);
        }

        static const unsigned ap_timeout  = 10*1000;
        timectr_t timer = timectr_init_inline(ap_timeout);
        while( !timectr_is_expired(&timer) )
        {
            static const unsigned event_timeout = 500;
            epoll_encap_process_events(&epoll, event_timeout);
        }

        listener_stop(&listener);
        tcp_peer_wait_all_finished();
    }
    JMPBK_END

    listener_deinit(&listener);

    epoll_encap_wait_all_events(&epoll);
    epoll_encap_deinit(&epoll);

    return 0;
}
