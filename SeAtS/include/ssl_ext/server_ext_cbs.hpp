#ifndef __SERVER_EXT__
#define __SERVER_EXT__

#include <openssl/ssl.h>

// SERVER CERTIFICATE CALLBACKS
int server_certificate_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg);

void  server_certificate_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg);


// CLIENT HELLO CALLBACKS
int  client_hello_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg);


#endif // __SERVER_EXT__ 
