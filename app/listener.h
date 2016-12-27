#ifndef _LISTENER_H_
#define _LISTENER_H_

#include <stdatomic.h>
#include <gen/net/socktcp.h>
#include "epoll_encap.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void(*listener_on_new_peer_t)(void *userarg, socktcp_t *sock);

typedef struct listener_t
{
    epoll_encap_callbacks_t super;

    epoll_encap_t          *epoll;
    socktcp_t               sock;
    listener_on_new_peer_t  peer_proc;
    void                   *peer_arg;

    atomic_int peer_inst_cnt;

} listener_t;

void listener_init(listener_t             *self,
                   epoll_encap_t          *epoll,
                   listener_on_new_peer_t  peer_proc,
                   void                   *peer_arg);
void listener_deinit(listener_t *self);

bool listener_start(listener_t *self, unsigned port);
void listener_stop (listener_t *self);

void listener_wait_all_peer_finished(listener_t *self);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
