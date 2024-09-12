#ifndef __LOG_HPP__
#define __LOG_HPP__

#include <openssl/crypto.h>

void SSL_keylog_cb(const SSL *ssl, const char *line);

#endif
