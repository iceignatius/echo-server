#ifndef _SERV_TLS_H_
#define _SERV_TLS_H_

#include <gen/net/socktcp.h>

#ifdef __cplusplus
extern "C" {
#endif

void serv_tls_peer_proc(void *dummy, socktcp_t *sock);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
