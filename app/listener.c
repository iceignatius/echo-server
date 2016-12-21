#include <stdlib.h>
#include <stdio.h>
#include "listener.h"

//------------------------------------------------------------------------------
static
void on_read(listener_t *self)
{
    socktcp_t *peer = socktcp_get_new_connect(&self->sock);
    if( !peer ) return;

    thrd_t thrd;
    if( thrd_success != thrd_create(&thrd, self->peer_proc, peer) )
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
void listener_init(listener_t *self, epoll_encap_t *epoll, thrd_start_t peer_proc)
{
    self->super.userarg  = self;
    self->super.on_read  = (void(*)(void*)) on_read;
    self->super.on_write = NULL;
    self->super.on_error = (void(*)(void*)) on_error;

    self->epoll     = epoll;
    self->peer_proc = peer_proc;
    socktcp_init(&self->sock);
}
//------------------------------------------------------------------------------
void listener_deinit(listener_t *self)
{
    listener_stop(self);
    socktcp_deinit(&self->sock);
}
//------------------------------------------------------------------------------
bool listener_start(listener_t *self, unsigned port)
{
    listener_stop(self);

    bool res = false;
    do
    {
        sockaddr_t addr;
        sockaddr_init_value(&addr, ipv4_const_any, port);

        if( !socktcp_listen(&self->sock, &addr, true) )
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
