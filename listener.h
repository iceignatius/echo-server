#ifndef _LISTENER_H_
#define _LISTENER_H_

#include <gen/net/socktcp.h>
#include "epoll_encap.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct listener_t
{
    epoll_encap_callbacks_t super;

    epoll_encap_t *epoll;
    socktcp_t      sock;

} listener_t;

void listener_init  (listener_t *self, epoll_encap_t *epoll);
void listener_deinit(listener_t *self);

bool listener_start(listener_t *self, const sockaddr_t *addr);
void listener_stop (listener_t *self);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
