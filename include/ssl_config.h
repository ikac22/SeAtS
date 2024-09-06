#ifndef __SSL_CONFIG_H__
#define __SSL_CONFIG_H__

#include <openssl/ssl.h>
#include "common.h"

SSL_CTX* create_context(bool isServer);
void configure_server_context(SSL_CTX *ctx);
void configure_client_context(SSL_CTX *ctx);

#endif
