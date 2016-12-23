#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <gen/jmpbk.h>
#include <gen/cirbuf.h>
#include <gen/timectr.h>
#include "tls_resource.h"
#include "tls_peer.h"

static atomic_int refcnt = ATOMIC_VAR_INIT(0);

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
int tls_peer_proc(socktcp_t *sock)
{
    atomic_fetch_add(&refcnt, 1);

    char addrstr[32] = {0};
    addr_to_str(addrstr, sizeof(addrstr)-1, socktcp_get_remote_addr(sock));
    printf("TLS connected: %s\n", addrstr);

    cirbuf_t datacache;
    cirbuf_init(&datacache);

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

        // Set up and get TLS resource.

        tls_resource_t *resource = get_unique_resource();

        // Set up session.

        if( mbedtls_ssl_setup(&tls, &resource->conf) )
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
