#include <stdio.h>
#include <signal.h>
#include <gen/jmpbk.h>
#include <gen/timectr.h>
#include "cmdopt.h"
#include "servconf.h"
#include "serv_tcp.h"
#include "serv_tls.h"

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

    serv_tcp_t serv_tcp;
    serv_tcp_init(&serv_tcp, &epoll);

    serv_tls_t serv_tls;
    serv_tls_init(&serv_tls, &epoll);

    int res;
    JMPBK_BEGIN
    {
        if( !servconf_load_file(&conf, cmdopt->config_file) )
        {
            fprintf(stderr, "ERROR: Load configuration file (%s) failed!\n", cmdopt->config_file);
            JMPBK_THROW(0);
        }

        if( conf.tcp.enabled && !serv_tcp_start(&serv_tcp,
                                                conf.tcp.port,
                                                conf.tcp.idle_timeout) )
        {
            fprintf(stderr, "ERROR: TCP server start failed!\n");
            JMPBK_THROW(0);
        }

        if( conf.tls.enabled && !serv_tls_start(&serv_tls,
                                                conf.tls.port,
                                                conf.tls.priv_key_file,
                                                conf.tls.cert_file,
                                                conf.tls.idle_timeout) )
        {
            fprintf(stderr, "ERROR: TLS server start failed!\n");
            JMPBK_THROW(0);
        }

        timectr_t timer = timectr_init_inline(cmdopt->auto_exit_time);
        while( !go_terminate && !( cmdopt->auto_exit_enabled && timectr_is_expired(&timer) ) )
        {
            static const unsigned event_timeout = 500;
            epoll_encap_process_events(&epoll, event_timeout);
        }

        serv_tcp_stop_listen(&serv_tcp);
        serv_tls_stop_listen(&serv_tls);

        serv_tcp_wait_all_stopped(&serv_tcp);
        serv_tls_wait_all_stopped(&serv_tls);
    }
    JMPBK_FINAL
    {
        res = JMPBK_ERRCODE;
    }
    JMPBK_END

    serv_tls_deinit(&serv_tls);
    serv_tcp_deinit(&serv_tcp);

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
