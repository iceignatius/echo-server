#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <gen/jmpbk.h>
#include <gen/cirbuf.h>
#include <gen/timectr.h>
#include "tls_resource.h"
#include "serv_tls.h"

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
tls_resource_t* get_unique_resource(void)
{
    static tls_resource_t res;

    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    if( pthread_mutex_lock(&lock) )
    {
        fputs("ERROR: Mutex failure!\n", stderr);
        abort();
    }

    static bool inited = false;
    if( !inited )
    {
        inited = true;

        tls_resource_init(&res);
        if( !tls_resource_setup(&res, "conf/privkey.pem", "conf/cert.pem") )
        {
            fputs("ERROR: Set up TLS resource failed!\n", stderr);
            abort();
        }
    }

    if( pthread_mutex_unlock(&lock) )
    {
        fputs("ERROR: Mutex failure!\n", stderr);
        abort();
    }

    return &res;
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
bool setup_session(mbedtls_ssl_context *tls, socktcp_t *sock, tls_resource_t *resource)
{
    if( mbedtls_ssl_setup(tls, &resource->conf) ) return false;

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
void serv_tls_peer_proc(void *dummy, socktcp_t *sock)
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

        if( !setup_session(&tls, sock, get_unique_resource()) )
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
