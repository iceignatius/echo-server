#include <stdio.h>
#include "tls_resource.h"

//------------------------------------------------------------------------------
void tls_resource_init(tls_resource_t *self)
{
    mbedtls_entropy_init   (&self->entropy);
    mbedtls_ctr_drbg_init  (&self->rndg);
    mbedtls_pk_init        (&self->key);
    mbedtls_x509_crt_init  (&self->cert);
    mbedtls_ssl_cache_init (&self->cache);
    mbedtls_ssl_config_init(&self->conf);
}
//------------------------------------------------------------------------------
void tls_resource_deinit(tls_resource_t *self)
{
    mbedtls_ssl_config_free(&self->conf);
    mbedtls_ssl_cache_free (&self->cache);
    mbedtls_x509_crt_free  (&self->cert);
    mbedtls_pk_free        (&self->key);
    mbedtls_ctr_drbg_free  (&self->rndg);
    mbedtls_entropy_free   (&self->entropy);
}
//------------------------------------------------------------------------------
static
void on_debug_message(void *userarg, int level, const char *file, int line, const char *msg)
{
    // Ignore debug message.
}
//------------------------------------------------------------------------------
bool tls_resource_setup(tls_resource_t *self, const char *keyfile, const char *certfile)
{
    bool res = false;
    do
    {
        static const char pdata[] = "tls-server";
        if( mbedtls_ctr_drbg_seed(&self->rndg,
                                  mbedtls_entropy_func,
                                  &self->entropy,
                                  (const unsigned char*) pdata,
                                  sizeof(pdata)) )
        {
            fputs("ERROR: Initialise random number generator failed!\n", stderr);
            break;
        }

        if( mbedtls_pk_parse_keyfile(&self->key, keyfile, NULL) )
        {
            fputs("ERROR: Load key file failed!\n", stderr);
            break;
        }

        if( mbedtls_x509_crt_parse_file(&self->cert, certfile) )
        {
            fputs("ERROR: Load certification file failed!\n", stderr);
            break;
        }

        if( mbedtls_ssl_config_defaults(&self->conf,
                                        MBEDTLS_SSL_IS_SERVER,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) )
        {
            fputs("ERROR: Initialise TLS configuration failed!\n", stderr);
            break;
        }

        if( mbedtls_ssl_conf_own_cert(&self->conf, &self->cert, &self->key) )
        {
            fputs("ERROR: Set up keys failed!\n", stderr);
            break;
        }

        mbedtls_ssl_conf_rng(&self->conf, mbedtls_ctr_drbg_random, &self->rndg);
        mbedtls_ssl_conf_dbg(&self->conf, on_debug_message, stderr);
        mbedtls_ssl_conf_session_cache(&self->conf,
                                       &self->cache,
                                       mbedtls_ssl_cache_get,
                                       mbedtls_ssl_cache_set );

        res = true;
    } while(false);

    return res;
}
//------------------------------------------------------------------------------
