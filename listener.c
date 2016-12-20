#include <stdlib.h>
#include <stdio.h>
#include <threads.h>
#include <gen/jmpbk.h>
#include <gen/cirbuf.h>
#include <gen/timectr.h>
#include "listener.h"

//------------------------------------------------------------------------------
static
void addr_to_str(char *buf, size_t bufsize, sockaddr_t addr)
{
    char ipstr[32] = {0};
    ipv4_to_str(ipstr, sizeof(ipstr)-1, sockaddr_get_ip(&addr));

    unsigned port = sockaddr_get_port(&addr);

    snprintf(buf, bufsize, "%s:%u\n", ipstr, port);
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
int peer_process(socktcp_t *peer)
{
    char addrstr[32] = {0};
    addr_to_str(addrstr, sizeof(addrstr)-1, socktcp_get_remote_addr(peer));
    printf("Connected: %s\n", addrstr);

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

        static const unsigned idle_timeout = 3*1000;
        timectr_t timer = timectr_init_inline(idle_timeout);
        while( !timectr_is_expired(&timer) )
        {
            int recvsz = recv_to_cache(peer, &cache);
            int sentsz = send_from_cache(peer, &cache);
            if( recvsz < 0 || sentsz < 0 ) break;

            if( recvsz || sentsz )
                timectr_reset(&timer);
            else
                systime_sleep_awhile();
        }
    }
    JMPBK_END

    cirbuf_deinit(&cache);

    socktcp_release(peer);
    printf("Disconnected: %s\n", addrstr);

    return 0;
}
//------------------------------------------------------------------------------
static
void on_read(listener_t *self)
{
    socktcp_t *peer = socktcp_get_new_connect(&self->sock);
    if( !peer ) return;

    thrd_t thrd;
    if( thrd_success != thrd_create(&thrd, (int(*)(void*)) peer_process, peer) )
    {
        fputs("ERROR: Cannot create thread!\n", stderr);
        abort();
    }

    if( thrd_success != thrd_detach(thrd) )
    {
        fputs("ERROR: Cannot detach thread!\n", stderr);
        abort();
    }
}
//------------------------------------------------------------------------------
static
void on_error(listener_t *self)
{
    printf("Listener on error!\n");
    epoll_encap_remove(self->epoll, socktcp_get_fd(&self->sock));
}
//------------------------------------------------------------------------------
void listener_init(listener_t *self, epoll_encap_t *epoll)
{
    self->super.userarg  = self;
    self->super.on_read  = (void(*)(void*)) on_read;
    self->super.on_write = NULL;
    self->super.on_error = (void(*)(void*)) on_error;

    self->epoll = epoll;
    socktcp_init(&self->sock);
}
//------------------------------------------------------------------------------
void listener_deinit(listener_t *self)
{
    listener_stop(self);
    socktcp_deinit(&self->sock);
}
//------------------------------------------------------------------------------
bool listener_start(listener_t *self, const sockaddr_t *addr)
{
    listener_stop(self);

    bool res = false;
    do
    {
        if( !socktcp_listen(&self->sock, addr, true) )
            break;

        if( !epoll_encap_add(self->epoll, socktcp_get_fd(&self->sock), EPOLLIN, &self->super) )
            break;

        res = true;
    } while(false);

    if( !res )
        listener_stop(self);

    return res;
}
//------------------------------------------------------------------------------
void listener_stop(listener_t *self)
{
    epoll_encap_remove(self->epoll, socktcp_get_fd(&self->sock));
    socktcp_close(&self->sock);
}
//------------------------------------------------------------------------------
