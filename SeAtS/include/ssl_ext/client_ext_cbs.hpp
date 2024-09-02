#ifndef __CLIENT_EXT__
#define __CLIENT_EXT__

#include <stdint.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <sys/types.h>

// CLIENT HELLO EXTENSION
int client_hello_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg);

void client_hello_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg);


// SERVER CERTIFICATE EXTENTSION 
int  server_certificate_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg);

#endif // __CLIENT_EXT__
