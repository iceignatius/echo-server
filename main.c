#include <stdio.h>
#include <threads.h>
#include <gen/jmpbk.h>
#include <gen/timectr.h>
#include <gen/cirbuf.h>
#include <gen/net/socktcp.h>

static
void addr_to_str(char *buf, size_t bufsize, sockaddr_t addr)
{
    char ipstr[32] = {0};
    ipv4_to_str(ipstr, sizeof(ipstr)-1, sockaddr_get_ip(&addr));

    unsigned port = sockaddr_get_port(&addr);

    snprintf(buf, bufsize, "%s:%u\n", ipstr, port);
}

static
int recv_to_cache(socktcp_t *sock, cirbuf_t *cache)
{
    int recvsz = socktcp_receive(sock,
                                 cirbuf_get_write_buf(cache),
                                 cirbuf_get_freesize(cache));
    if( recvsz <= 0 ) return recvsz;

    return ( recvsz == cirbuf_commit_write(cache, recvsz) )?( recvsz ):( -1 );
}

static
int send_from_cache(socktcp_t *sock, cirbuf_t *cache)
{
    if( !cirbuf_get_datasize(cache) ) return 0;

    int sentsz = socktcp_send(sock,
                              cirbuf_get_read_buf(cache),
                              cirbuf_get_datasize(cache));
    if( sentsz <= 0 ) return sentsz;

    return ( sentsz == cirbuf_commit_read(cache, sentsz) )?( sentsz ):( -1 );
}

static
int peer_process(socktcp_t *peer)
{
    char addrstr[32] = {0};
    addr_to_str(addrstr, sizeof(addrstr)-1, socktcp_get_remote_addr(peer));
    printf("Connected: %s\n", addrstr);

    cirbuf_t cache;
    cirbuf_init(&cache);

    JMPBK_BEGIN
    {
        static const size_t bufsize = 1024;
        if( !cirbuf_alloc(&cache, bufsize) )
        {
            fprintf(stderr, "ERROR: Allocate data buffer failed!\n");
            JMPBK_THROW(0);
        }

        static const unsigned idle_timeout = 3*1000;
        timectr_t timer = timectr_init_inline(idle_timeout);
        while( !timectr_is_expired(&timer) )
        {
            int recvsz = recv_to_cache(peer, &cache);
            int sentsz = send_from_cache(peer, &cache);
            if( recvsz < 0 || sentsz < 0 ) break;

            if( recvsz || sentsz )
                timectr_reset_ctronly(&timer);
            else
                systime_sleep_awhile();
        }
    }
    JMPBK_END

    cirbuf_deinit(&cache);

    socktcp_release(peer);
    printf("Disconnected: %s\n", addrstr);

    return 0;
}

int main(int argc, char *argv[])
{
    static const unsigned ap_timeout  = 10*1000;
    static const unsigned listen_port = 4220;

    socktcp_t listener;
    socktcp_init(&listener);

    sockaddr_t listen_addr;
    sockaddr_init_value(&listen_addr, ipv4_const_any, listen_port);

    JMPBK_BEGIN
    {
        if( !socktcp_listen(&listener, &listen_addr, true) )
        {
            fprintf(stderr, "ERROR: Start listen failed!\n");
            JMPBK_THROW(0);
        }

        timectr_t timer = timectr_init_inline(ap_timeout);
        while( !timectr_is_expired(&timer) )
        {
            socktcp_t *peer = socktcp_get_new_connect(&listener);
            if( peer )
            {
                thrd_t thrd;

                if( thrd_success != thrd_create(&thrd, (int(*)(void*)) peer_process, peer) )
                {
                    fprintf(stderr, "ERROR: Start peer thread failed!\n");
                    JMPBK_THROW(0);
                }

                if( thrd_success != thrd_detach(thrd) )
                {
                    fprintf(stderr, "ERROR: Detach peer thread failed!\n");
                    JMPBK_THROW(0);
                }
            }
            else
            {
                systime_sleep_awhile();
            }
        }
    }
    JMPBK_END

    socktcp_deinit(&listener);

    return 0;
}
