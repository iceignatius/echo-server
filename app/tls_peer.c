#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/ssl.h>
#include <gen/jmpbk.h>
#include <gen/cirbuf.h>
#include <gen/timectr.h>
#include "tls_peer.h"

static atomic_int refcnt = ATOMIC_VAR_INIT(0);

//------------------------------------------------------------------------------
static
void addr_to_str(char *buf, size_t bufsize, sockaddr_t addr)
{
    char ipstr[32] = {0};
    ipv4_to_str(ipstr, sizeof(ipstr)-1, sockaddr_get_ip(&addr));

    unsigned port = sockaddr_get_port(&addr);

    snprintf(buf, bufsize, "%s:%u\n", ipstr, port);
}
//------------------------------------------------------------------------------
static
void on_debug_message(void *userarg, int level, const char *file, int line, const char *msg)
{
    // Ignore debug message.
}
//------------------------------------------------------------------------------
static
int on_send(socktcp_t *sock, const unsigned char *data, size_t size)
{
    int sentsz = socktcp_send(sock, data, size);
    return sentsz ? sentsz : MBEDTLS_ERR_SSL_WANT_WRITE;
}
//------------------------------------------------------------------------------
static
int on_recv(socktcp_t *sock, unsigned char *buf, size_t size)
{
    int recvsz = socktcp_receive(sock, buf, size);
    return recvsz ? recvsz : MBEDTLS_ERR_SSL_WANT_READ;
}
//------------------------------------------------------------------------------
static
int recv_to_cache(mbedtls_ssl_context *tls, cirbuf_t *cache)
{
    int recvsz = mbedtls_ssl_read(tls,
                                  cirbuf_get_write_buf(cache),
                                  cirbuf_get_freesize(cache));

    if( recvsz == MBEDTLS_ERR_SSL_WANT_READ )
        recvsz = 0;
    else if( recvsz == MBEDTLS_ERR_SSL_WANT_WRITE )
        recvsz = 0;
    else if( recvsz <= 0 )
        return recvsz;

    return ( recvsz == cirbuf_commit_write(cache, recvsz) )?( recvsz ):( -1 );
}
//------------------------------------------------------------------------------
static
int send_from_cache(mbedtls_ssl_context *tls, cirbuf_t *cache)
{
    if( !cirbuf_get_datasize(cache) ) return 0;

    int sentsz = mbedtls_ssl_write(tls,
                                   cirbuf_get_read_buf(cache),
                                   cirbuf_get_datasize(cache));

    if( sentsz == MBEDTLS_ERR_SSL_WANT_READ )
        sentsz = 0;
    else if( sentsz == MBEDTLS_ERR_SSL_WANT_WRITE )
        sentsz = 0;
    else if( sentsz <= 0 )
        return sentsz;

    return ( sentsz == cirbuf_commit_read(cache, sentsz) )?( sentsz ):( -1 );
}
//------------------------------------------------------------------------------
int tls_peer_proc(socktcp_t *sock)
{
    atomic_fetch_add(&refcnt, 1);

    char addrstr[32] = {0};
    addr_to_str(addrstr, sizeof(addrstr)-1, socktcp_get_remote_addr(sock));
    printf("TLS connected: %s\n", addrstr);

    cirbuf_t datacache;
    cirbuf_init(&datacache);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_context rndg;
    mbedtls_ctr_drbg_init(&rndg);

    mbedtls_ssl_cache_context tlscache;
    mbedtls_ssl_cache_init(&tlscache);

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);

    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);

    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);

    mbedtls_ssl_context tls;
    mbedtls_ssl_init(&tls);

    JMPBK_BEGIN
    {
        // Allocate data cache.

        static const size_t bufsize = 1024;
        if( !cirbuf_alloc(&datacache, bufsize) )
        {
            fprintf(stderr, "ERROR: Allocate data buffer failed!\n");
            JMPBK_THROW(0);
        }

        // Initialise random number generator.

        const char pdata[] = "tls-server";
        if( mbedtls_ctr_drbg_seed(&rndg,
                                  mbedtls_entropy_func,
                                  &entropy,
                                  (const unsigned char*) pdata,
                                  strlen(pdata)) )
        {
            fputs("ERROR: Initialise random number generator failed!\n", stderr);
            JMPBK_THROW(0);
        }

        // Load certificate and keys.

        if( mbedtls_pk_parse_keyfile(&key, "../conf/privkey.pem", NULL) )
        {
            fputs("ERROR: Load key file failed!\n", stderr);
            JMPBK_THROW(0);
        }

        if( mbedtls_x509_crt_parse_file(&cert, "../conf/cert.pem") )
        {
            fputs("ERROR: Load certification file failed!\n", stderr);
            JMPBK_THROW(0);
        }

        // Set configuration.

        if( mbedtls_ssl_config_defaults(&conf,
                                        MBEDTLS_SSL_IS_SERVER,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) )
        {
            fputs("ERROR: Initialise TLS configuration failed!\n", stderr);
            JMPBK_THROW(0);
        }

        if( mbedtls_ssl_conf_own_cert(&conf, &cert, &key) )
        {
            fputs("ERROR: Set up keys failed!\n", stderr);
            JMPBK_THROW(0);
        }

        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &rndg);
        mbedtls_ssl_conf_dbg(&conf, on_debug_message, stderr);
        mbedtls_ssl_conf_session_cache(&conf,
                                       &tlscache,
                                       mbedtls_ssl_cache_get,
                                       mbedtls_ssl_cache_set );

        // Set up session.

        if( mbedtls_ssl_setup(&tls, &conf) )
        {
            fputs("ERROR: Set up TLS session failed!\n", stderr);
            JMPBK_THROW(0);
        }

        mbedtls_ssl_set_bio(&tls,
                            sock,
                            (int(*)(void*,const unsigned char*,size_t)) on_send,
                            (int(*)(void*,unsigned char*,size_t)) on_recv,
                            NULL);

        // Handshake.

        int handshake_rescode;
        do
        {
            handshake_rescode = mbedtls_ssl_handshake(&tls);
        } while( handshake_rescode == MBEDTLS_ERR_SSL_WANT_READ ||
                 handshake_rescode == MBEDTLS_ERR_SSL_WANT_WRITE );

        if( handshake_rescode )
        {
            char msg[512];
            mbedtls_strerror(handshake_rescode, msg, sizeof(msg));
            fprintf(stderr, "ERROR: TLS handshake error: %s\n", msg);
            JMPBK_THROW(0);
        }

        // Information display.

        printf("Connection protocol:\n");
        printf("  Version : %s\n", mbedtls_ssl_get_version(&tls));
        printf("  Cipher  : %s\n", mbedtls_ssl_get_ciphersuite(&tls));

        // Send and receive.

        static const unsigned idle_timeout = 3*1000;
        timectr_t timer = timectr_init_inline(idle_timeout);
        while( !timectr_is_expired(&timer) )
        {
            int recvsz = recv_to_cache(&tls, &datacache);
            int sentsz = send_from_cache(&tls, &datacache);
            if( recvsz < 0 || sentsz < 0 ) break;

            if( recvsz || sentsz )
                timectr_reset(&timer);
            else
                systime_sleep_awhile();
        }

        // End session.

        int close_rescode;
        do
        {
            close_rescode = mbedtls_ssl_close_notify(&tls);
        } while( close_rescode == MBEDTLS_ERR_SSL_WANT_READ ||
                 close_rescode == MBEDTLS_ERR_SSL_WANT_WRITE );
    }
    JMPBK_END

    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&key);
    mbedtls_ssl_cache_free(&tlscache);
    mbedtls_ctr_drbg_free(&rndg);
    mbedtls_entropy_free(&entropy);
    cirbuf_deinit(&datacache);

    socktcp_release(sock);
    printf("TLS disconnected: %s\n", addrstr);

    atomic_fetch_sub(&refcnt, 1);
    return 0;
}
//------------------------------------------------------------------------------
void tls_peer_wait_all_finished(void)
{
    while( atomic_load(&refcnt) )
        systime_sleep_awhile();
}
//------------------------------------------------------------------------------
