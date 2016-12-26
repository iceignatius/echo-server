#ifndef _CMDOPT_H_
#define _CMDOPT_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cmdopt_t
{
    bool      need_help;
    bool      auto_exit_enabled;
    unsigned  auto_exit_time;
    char     *config_file;
} cmdopt_t;

void cmdopt_load_defaults(cmdopt_t *self);
void cmdopt_load_args    (cmdopt_t *self, int argc, char *argv[]);

#ifdef __cplusplus
extern "C"
#endif

#endif
