#ifndef _TLS_RESOURCE_H_
#define _TLS_RESOURCE_H_

#include <stdbool.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl_cache.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tls_resource_t
{
    mbedtls_entropy_context   entropy;
    mbedtls_ctr_drbg_context  rndg;
    mbedtls_pk_context        key;
    mbedtls_x509_crt          cert;
    mbedtls_ssl_cache_context cache;
    mbedtls_ssl_config        conf;
} tls_resource_t;

void tls_resource_init  (tls_resource_t *self);
void tls_resource_deinit(tls_resource_t *self);

bool tls_resource_setup(tls_resource_t *self, const char *keyfile, const char *certfile);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
