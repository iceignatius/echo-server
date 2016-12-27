#ifndef _SERVCONF_H_
#define _SERVCONF_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct servconf_tcp_t
{
    bool     enabled;
    unsigned port;
    unsigned idle_timeout;
} servconf_tcp_t;

typedef struct servconf_tls_t
{
    bool     enabled;
    unsigned port;
    unsigned idle_timeout;
    char     priv_key_file[1024];
    char     cert_file[1024];
} servconf_tls_t;

typedef struct servconf_t
{
    servconf_tcp_t tcp;
    servconf_tls_t tls;
} servconf_t;

void servconf_init  (servconf_t *self);
void servconf_deinit(servconf_t *self);

bool servconf_load_file(servconf_t *self, const char *filename);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
