#ifndef _SERV_TCP_H_
#define _SERV_TCP_H_

#include <gen/net/socktcp.h>

#ifdef __cplusplus
extern "C" {
#endif

void serv_tcp_peer_proc(void *dummy, socktcp_t *sock);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
