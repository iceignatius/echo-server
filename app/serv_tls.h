#ifndef _SERV_TLS_H_
#define _SERV_TLS_H_

#include "listener.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct serv_tls_t
{
} serv_tls_t;

void serv_tls_init  (serv_tls_t *self);
void serv_tls_deinit(serv_tls_t *self);

bool serv_tls_start(serv_tls_t *self);
void serv_tls_stop (serv_tls_t *self);

void serv_tls_peer_proc(serv_tls_t *self, socktcp_t *sock);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
