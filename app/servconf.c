#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <ini.h>
#include "servconf.h"

//------------------------------------------------------------------------------
void servconf_init(servconf_t *self)
{
    memset(self, 0, sizeof(*self));
}
//------------------------------------------------------------------------------
void servconf_deinit(servconf_t *self)
{
    // Nothing to do.
}
//------------------------------------------------------------------------------
static
bool str_to_bool(const char *str, bool fail_value)
{
    switch( tolower(str[0]) )
    {
    case 'y':
    case 't':
    case '1':
        return true;

    case 'n':
    case 'f':
    case '0':
        return false;

    default:
        return fail_value;
    }
}
//------------------------------------------------------------------------------
static
int ini_item_handler(servconf_t *self, const char* section, const char* name, const char* value)
{
    if( 0 == strcmp(section, "TCP") && 0 == strcmp(name, "Enabled") )
        self->tcp.enabled = str_to_bool(value, false);

    if( 0 == strcmp(section, "TCP") && 0 == strcmp(name, "Port") )
        self->tcp.port = strtoul(value, NULL, 10);

    if( 0 == strcmp(section, "TCP") && 0 == strcmp(name, "IdleTimeout") )
        self->tcp.idle_timeout = 1000 * strtoul(value, NULL, 10);

    if( 0 == strcmp(section, "TLS") && 0 == strcmp(name, "Enabled") )
        self->tls.enabled = str_to_bool(value, false);

    if( 0 == strcmp(section, "TLS") && 0 == strcmp(name, "Port") )
        self->tls.port = strtoul(value, NULL, 10);

    if( 0 == strcmp(section, "TLS") && 0 == strcmp(name, "IdleTimeout") )
        self->tls.idle_timeout = 1000 * strtoul(value, NULL, 10);

    if( 0 == strcmp(section, "TLS") && 0 == strcmp(name, "PrivateKeyFile") )
        strncpy(self->tls.priv_key_file, value, sizeof(self->tls.priv_key_file)-1);

    if( 0 == strcmp(section, "TLS") && 0 == strcmp(name, "CertificateFileFile") )
        strncpy(self->tls.cert_file, value, sizeof(self->tls.cert_file)-1);

    return true;
}
//------------------------------------------------------------------------------
bool servconf_load_file(servconf_t *self, const char *filename)
{
    return !ini_parse(filename,
                      (int(*)(void*,const char*,const char*,const char*)) ini_item_handler,
                      self);
}
//------------------------------------------------------------------------------
