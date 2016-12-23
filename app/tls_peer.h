#ifndef _TLS_PEER_H_
#define _TLS_PEER_H_

#include <gen/net/socktcp.h>

#ifdef __cplusplus
extern "C" {
#endif

int tls_peer_proc(socktcp_t *sock);

void tls_peer_wait_all_finished(void);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
