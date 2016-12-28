#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include "cmdopt.h"

//------------------------------------------------------------------------------
void cmdopt_load_defaults(cmdopt_t *self)
{
    self->need_help         = false;
    self->auto_exit_enabled = false;
    self->auto_exit_time    = 60*1000;
    self->config_file       = "/usr/local/etc/echo-server/config";
}
//------------------------------------------------------------------------------
void cmdopt_load_args(cmdopt_t *self, int argc, char *argv[])
{
    struct option longopts[] =
    {
        { "help"       , no_argument      , NULL, 'h' },
        { "auto-exit"  , required_argument, NULL, 'X' },
        { "config-file", required_argument, NULL, 'C' },
        { NULL         , 0                , NULL,  0  }
    };

    int opt, index;
    while( ( opt = getopt_long(argc, argv, "h", longopts, &index) ) >= 0 )
    {
        switch( opt )
        {
        case 'X':
            self->auto_exit_enabled = true;
            self->auto_exit_time    = 1000*strtoul(optarg, NULL, 10);
            break;

        case 'C':
            self->config_file = optarg;
            break;

        case 'h':
        case '?':
            self->need_help = true;
            break;
        }
    }

    if( optind < argc )
        fprintf(stderr, "Unknown option: %s (use --help for help)\n", argv[optind]);
}
//------------------------------------------------------------------------------
