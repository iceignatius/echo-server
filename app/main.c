#include <stdio.h>
#include <signal.h>
#include <gen/jmpbk.h>
#include <gen/timectr.h>
#include "listener.h"
#include "tcp_peer.h"
#include "tls_peer.h"
#include "cmdopt.h"
#include "servconf.h"

static bool go_terminate = false;

//------------------------------------------------------------------------------
static
void signal_handler(int signum)
{
    if( signum == SIGQUIT || signum == SIGTERM )
        go_terminate = true;
}
//------------------------------------------------------------------------------
int print_help(void)
{
    printf("Echo server\n");
    printf("\n");
    printf("This is a server designed for connection test purpose\n");
    printf("that will respond all of data which the client sent out.\n");
    printf("\n");
    printf("Usage:\n");
    printf("  echo-server [options]\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help              Print help message.\n");
    printf("      --auto-exit=time    Let server terminate automatically with\n");
    printf("                          a specific time in seconds.\n");
    printf("                          This option may be useful for test usage.\n");
    printf("      --config-file=file  Specify a configuration file to be used,\n");
    printf("                          or the default file /etc/echo-server/conf\n");
    printf("                          will be used.\n");

    return 0;
}
//------------------------------------------------------------------------------
int server_process(cmdopt_t *cmdopt)
{
    servconf_t conf;
    servconf_init(&conf);

    epoll_encap_t epoll;
    epoll_encap_init(&epoll);

    listener_t tcp_listener;
    listener_init(&tcp_listener, &epoll, tcp_peer_proc, NULL);

    listener_t tls_listener;
    listener_init(&tls_listener, &epoll, tls_peer_proc, NULL);

    int res;
    JMPBK_BEGIN
    {
        if( !servconf_load_file(&conf, cmdopt->config_file) )
        {
            fprintf(stderr, "ERROR: Load configuration file (%s) failed!\n", cmdopt->config_file);
            JMPBK_THROW(0);
        }

        static const unsigned tcp_listen_port = 4220;
        if( !listener_start(&tcp_listener, tcp_listen_port) )
        {
            fprintf(stderr, "ERROR: TCP listener start failed!\n");
            JMPBK_THROW(0);
        }

        static const unsigned tls_listen_port = 4221;
        if( !listener_start(&tls_listener, tls_listen_port) )
        {
            fprintf(stderr, "ERROR: TLS listener start failed!\n");
            JMPBK_THROW(0);
        }

        timectr_t timer = timectr_init_inline(cmdopt->auto_exit_time);
        while( !go_terminate &&
              ( !cmdopt->auto_exit_enabled || !timectr_is_expired(&timer) ))
        {
            static const unsigned event_timeout = 500;
            epoll_encap_process_events(&epoll, event_timeout);
            timectr_reset(&timer);
        }

        listener_stop(&tls_listener);
        tls_peer_wait_all_finished();

        listener_stop(&tcp_listener);
        tcp_peer_wait_all_finished();
    }
    JMPBK_CATCH_ALL
    {
        res = JMPBK_ERRCODE;
    }
    JMPBK_END

    listener_deinit(&tls_listener);
    listener_deinit(&tcp_listener);

    epoll_encap_wait_all_events(&epoll);
    epoll_encap_deinit(&epoll);

    servconf_deinit(&conf);

    return res;
}
//------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    signal(SIGQUIT, signal_handler);

    cmdopt_t cmdopt;
    cmdopt_load_defaults(&cmdopt);
    cmdopt_load_args(&cmdopt, argc, argv);

    if( cmdopt.need_help )
        return print_help();
    else
        return server_process(&cmdopt);
}
//------------------------------------------------------------------------------
