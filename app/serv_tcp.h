#ifndef _SERV_TCP_H_
#define _SERV_TCP_H_

#include "listener.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct serv_tcp_t
{
} serv_tcp_t;

void serv_tcp_init  (serv_tcp_t *self);
void serv_tcp_deinit(serv_tcp_t *self);

bool serv_tcp_start(serv_tcp_t *self);
void serv_tcp_stop (serv_tcp_t *self);

void serv_tcp_peer_proc(serv_tcp_t *self, socktcp_t *sock);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif