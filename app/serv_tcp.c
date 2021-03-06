#include <stdatomic.h>
#include <stdio.h>
#include <gen/jmpbk.h>
#include <gen/cirbuf.h>
#include <gen/timectr.h>
#include "serv_tcp.h"

//------------------------------------------------------------------------------
void serv_tcp_init(serv_tcp_t *self, epoll_encap_t *epoll)
{
    listener_init(&self->listener,
                  epoll,
                  (void(*)(void*,socktcp_t*)) serv_tcp_peer_proc,
                  self);

    self->idle_timeout = 0;
}
//------------------------------------------------------------------------------
void serv_tcp_deinit(serv_tcp_t *self)
{
    listener_deinit(&self->listener);
}
//------------------------------------------------------------------------------
bool serv_tcp_start(serv_tcp_t *self, unsigned port, unsigned idle_timeout)
{
    self->idle_timeout = idle_timeout;
    return listener_start(&self->listener, port);
}
//------------------------------------------------------------------------------
void serv_tcp_stop_listen(serv_tcp_t *self)
{
    listener_stop(&self->listener);
}
//------------------------------------------------------------------------------
void serv_tcp_wait_all_stopped(serv_tcp_t *self)
{
    listener_wait_all_peer_finished(&self->listener);
}
//------------------------------------------------------------------------------
static
void addr_to_str(char *buf, size_t bufsize, sockaddr_t addr)
{
    char ipstr[32] = {0};
    ipv4_to_str(ipstr, sizeof(ipstr)-1, sockaddr_get_ip(&addr));

    unsigned port = sockaddr_get_port(&addr);

    snprintf(buf, bufsize, "%s:%u", ipstr, port);
}
//------------------------------------------------------------------------------
static
int recv_to_cache(socktcp_t *sock, cirbuf_t *cache)
{
    int recvsz = socktcp_receive(sock,
                                 cirbuf_get_write_buf(cache),
                                 cirbuf_get_freesize(cache));
    if( recvsz <= 0 ) return recvsz;

    return ( recvsz == cirbuf_commit_write(cache, recvsz) )?( recvsz ):( -1 );
}
//------------------------------------------------------------------------------
static
int send_from_cache(socktcp_t *sock, cirbuf_t *cache)
{
    if( !cirbuf_get_datasize(cache) ) return 0;

    int sentsz = socktcp_send(sock,
                              cirbuf_get_read_buf(cache),
                              cirbuf_get_datasize(cache));
    if( sentsz <= 0 ) return sentsz;

    return ( sentsz == cirbuf_commit_read(cache, sentsz) )?( sentsz ):( -1 );
}
//------------------------------------------------------------------------------
static
void data_exchange_proc(socktcp_t *sock, cirbuf_t *cache, unsigned idle_timeout)
{
    timectr_t timer = timectr_init_inline(idle_timeout);
    while( !timectr_is_expired(&timer) )
    {
        int recvsz = recv_to_cache(sock, cache);
        int sentsz = send_from_cache(sock, cache);
        if( recvsz < 0 || sentsz < 0 ) break;

        if( recvsz || sentsz )
            timectr_reset(&timer);
        else
            systime_sleep_awhile();
    }
}
//------------------------------------------------------------------------------
void serv_tcp_peer_proc(serv_tcp_t *self, socktcp_t *sock)
{
    char addrstr[32] = {0};
    addr_to_str(addrstr, sizeof(addrstr)-1, socktcp_get_remote_addr(sock));
    printf("TCP connected: %s\n", addrstr);

    cirbuf_t cache;
    cirbuf_init(&cache);

    JMPBK_BEGIN
    {
        static const size_t bufsize = 1024;
        if( !cirbuf_alloc(&cache, bufsize) )
        {
            fprintf(stderr, "ERROR: Allocate data buffer failed!\n");
            JMPBK_THROW(0);
        }

        data_exchange_proc(sock, &cache, self->idle_timeout);
    }
    JMPBK_END

    cirbuf_deinit(&cache);

    printf("TCP disconnected: %s\n", addrstr);
}
//------------------------------------------------------------------------------
