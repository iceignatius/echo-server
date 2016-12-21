#ifndef _LISTENER_H_
#define _LISTENER_H_

#include <threads.h>
#include <gen/net/socktcp.h>
#include "epoll_encap.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct listener_t
{
    epoll_encap_callbacks_t super;

    epoll_encap_t *epoll;
    thrd_start_t   peer_proc;
    socktcp_t      sock;

} listener_t;

void listener_init  (listener_t *self, epoll_encap_t *epoll, thrd_start_t peer_proc);
void listener_deinit(listener_t *self);

bool listener_start(listener_t *self, unsigned port);
void listener_stop (listener_t *self);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
