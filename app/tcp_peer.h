#ifndef _TCP_PEER_H_
#define _TCP_PEER_H_

#include <gen/net/socktcp.h>

#ifdef __cplusplus
extern "C" {
#endif

int tcp_peer_proc(socktcp_t *sock);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
