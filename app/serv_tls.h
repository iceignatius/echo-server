#ifndef _SERV_TLS_H_
#define _SERV_TLS_H_

#include "listener.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct serv_tls_t
{
    listener_t listener;
} serv_tls_t;

void serv_tls_init  (serv_tls_t *self, epoll_encap_t *epoll);
void serv_tls_deinit(serv_tls_t *self);

bool serv_tls_start           (serv_tls_t *self, unsigned port);
void serv_tls_stop_listen     (serv_tls_t *self);
void serv_tls_wait_all_stopped(serv_tls_t *self);

void serv_tls_peer_proc(serv_tls_t *self, socktcp_t *sock);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
