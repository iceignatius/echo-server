#include <stdio.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <gen/jmpbk.h>
#include <gen/cirbuf.h>
#include <gen/timectr.h>
#include "serv_tls.h"

//------------------------------------------------------------------------------
void serv_tls_init(serv_tls_t *self, epoll_encap_t *epoll)
{
    listener_init(&self->listener,
                  epoll,
                  (void(*)(void*,socktcp_t*)) serv_tls_peer_proc,
                  self);

    mbedtls_entropy_init   (&self->entropy);
    mbedtls_ctr_drbg_init  (&self->rndg);
    mbedtls_pk_init        (&self->key);
    mbedtls_x509_crt_init  (&self->cert);
    mbedtls_ssl_cache_init (&self->cache);
    mbedtls_ssl_config_init(&self->conf);
}
//------------------------------------------------------------------------------
void serv_tls_deinit(serv_tls_t *self)
{
    mbedtls_ssl_config_free(&self->conf);
    mbedtls_ssl_cache_free (&self->cache);
    mbedtls_x509_crt_free  (&self->cert);
    mbedtls_pk_free        (&self->key);
    mbedtls_ctr_drbg_free  (&self->rndg);
    mbedtls_entropy_free   (&self->entropy);

    listener_deinit(&self->listener);
}
//------------------------------------------------------------------------------
static
void on_debug_message(void *userarg, int level, const char *file, int line, const char *msg)
{
    // Ignore debug message.
}
//------------------------------------------------------------------------------
static
bool setup_tls_resources(serv_tls_t *self, const char *keyfile, const char *certfile)
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
bool serv_tls_start(serv_tls_t *self,
                    unsigned    port,
                    const char *keyfile,
                    const char *certfile)
{
    if( !setup_tls_resources(self, keyfile, certfile) ) return false;
    if( !listener_start(&self->listener, port) ) return false;
    return true;
}
//------------------------------------------------------------------------------
void serv_tls_stop_listen(serv_tls_t *self)
{
    listener_stop(&self->listener);
}
//------------------------------------------------------------------------------
void serv_tls_wait_all_stopped(serv_tls_t *self)
{
    listener_wait_all_peer_finished(&self->listener);
}
//------------------------------------------------------------------------------
static
void addr_to_str(char *buf, size_t bufsize, sockaddr_t addr)
{
    char ipstr[32] = {0};
    ipv4_to_str(ipstr, sizeof(ipstr)-1, sockaddr_get_ip(&addr));

    unsigned port = sockaddr_get_port(&addr);

    snprintf(buf, bufsize, "%s:%u", ipstr, port);
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
static
bool setup_session(serv_tls_t *self, mbedtls_ssl_context *tls, socktcp_t *sock)
{
    if( mbedtls_ssl_setup(tls, &self->conf) ) return false;

    mbedtls_ssl_set_bio(tls,
                        sock,
                        (int(*)(void*,const unsigned char*,size_t)) on_send,
                        (int(*)(void*,unsigned char*,size_t)) on_recv,
                        NULL);

    return true;
}
//------------------------------------------------------------------------------
static
bool handshake(mbedtls_ssl_context *tls)
{
    int handshake_rescode;
    do
    {
        handshake_rescode = mbedtls_ssl_handshake(tls);
    } while( handshake_rescode == MBEDTLS_ERR_SSL_WANT_READ ||
             handshake_rescode == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( handshake_rescode )
    {
        char msg[512];
        mbedtls_strerror(handshake_rescode, msg, sizeof(msg));
        fprintf(stderr, "ERROR: TLS handshake error: %s\n", msg);
    }

    return !handshake_rescode;
}
//------------------------------------------------------------------------------
static
void print_tls_info(mbedtls_ssl_context *tls)
{
    printf("Connection protocol:\n");
    printf("  Version : %s\n", mbedtls_ssl_get_version(tls));
    printf("  Cipher  : %s\n", mbedtls_ssl_get_ciphersuite(tls));
}
//------------------------------------------------------------------------------
static
void data_exchange_proc(mbedtls_ssl_context *tls, cirbuf_t *cache, unsigned idle_timeout)
{
    timectr_t timer = timectr_init_inline(idle_timeout);
    while( !timectr_is_expired(&timer) )
    {
        int recvsz = recv_to_cache(tls, cache);
        int sentsz = send_from_cache(tls, cache);
        if( recvsz < 0 || sentsz < 0 ) break;

        if( recvsz || sentsz )
            timectr_reset(&timer);
        else
            systime_sleep_awhile();
    }
}
//------------------------------------------------------------------------------
static
void notify_end_session(mbedtls_ssl_context *tls)
{
    int close_rescode;
    do
    {
        close_rescode = mbedtls_ssl_close_notify(tls);
    } while( close_rescode == MBEDTLS_ERR_SSL_WANT_READ ||
             close_rescode == MBEDTLS_ERR_SSL_WANT_WRITE );
}
//------------------------------------------------------------------------------
void serv_tls_peer_proc(serv_tls_t *self, socktcp_t *sock)
{
    char addrstr[32] = {0};
    addr_to_str(addrstr, sizeof(addrstr)-1, socktcp_get_remote_addr(sock));
    printf("TLS connected: %s\n", addrstr);

    cirbuf_t cache;
    cirbuf_init(&cache);

    mbedtls_ssl_context tls;
    mbedtls_ssl_init(&tls);

    JMPBK_BEGIN
    {
        static const size_t bufsize = 1024;
        if( !cirbuf_alloc(&cache, bufsize) )
        {
            fprintf(stderr, "ERROR: Allocate data buffer failed!\n");
            JMPBK_THROW(0);
        }

        if( !setup_session(self, &tls, sock) )
        {
            fputs("ERROR: Set up TLS session failed!\n", stderr);
            JMPBK_THROW(0);
        }

        if( !handshake(&tls) )
        {
            fputs("ERROR: TLS handshake failed!\n", stderr);
            JMPBK_THROW(0);
        }

        print_tls_info(&tls);

        static const unsigned idle_timeout = 3*1000;
        data_exchange_proc(&tls, &cache, idle_timeout);

        notify_end_session(&tls);
    }
    JMPBK_END

    mbedtls_ssl_free(&tls);
    cirbuf_deinit(&cache);

    printf("TLS disconnected: %s\n", addrstr);
}
//------------------------------------------------------------------------------
