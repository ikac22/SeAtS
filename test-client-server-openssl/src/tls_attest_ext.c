#include "tls_attest_ext.h"
#include<string.h>

static bool verify_attestation(const unsigned char* in, size_t inlen){
    // TODO: calculate evidence using library or get precalculated evidence
     
    // TODO: compare evidence from server in more convenient way
    
    int result = strcmp(in, "TEST_ATTESTATION");
    if(result == 0)
        return true;
    return false;
}

static bool get_attestation(const unsigned char **out, size_t *outlen){
    // TODO: get evidence through library that contacts kernel module(libvirt)

    *out = "TEST_ATTESTATION";
    *outlen = strlen(*out);

    return true;
    
}


static int attestation_client_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg)
{
    //*out = "CLIENT MESSAGE: Hello there handsome ;)\0";
    switch (ext_type) {
        case 65280:
            printf(" - attestation_client_ext_add_cb from client called!\n");
            break;
        default:
            break;
    }
    return 1;
}

static void  attestation_client_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg)
{
    printf(" - attestation_client_ext_free_cb from client called!\n");
}

static int  attestation_client_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    printf(" - attestation_client_ext_parse_cb from client called!\n");
    verify_attestation(in,inlen);
    printf("=== ATTESTATION EXTENXION: Message from server: %s ===\n", in);
    return 1;
}



// SERVER CALLBACKS
static int attestation_server_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg)
{
    switch (ext_type) {
        case 65280:
            printf(" - attestation_server_ext_add_cb from server called!\n");
            get_attestation(out, outlen);
            printf("=== ATTESTATION EXTENXION: Sending message: %s ===\n", *out);
            break;
        default:
            break;
    }
    return 1;
}

static void  attestation_server_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg)
{
    printf(" - attestation_server_ext_free_cb from server called\n");
}

static int  attestation_server_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    printf(" - attestation_server_ext_parse_cb from server called!\n");
    return 1;
}

int add_attestation_extension(SSL_CTX *ctx, bool is_server){
    unsigned int id = 65280; 
    unsigned int flags = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_SERVER_HELLO;

    if (is_server){
        return SSL_CTX_add_custom_ext(ctx, 
                                        id,
                                        flags,
                                        attestation_server_ext_add_cb, 
                                        attestation_server_ext_free_cb, 
                                        NULL, 
                                        attestation_server_ext_parse_cb, 
                                        NULL);
    } 
    else
    {
        return SSL_CTX_add_custom_ext(ctx, 
                                        id,
                                        flags,
                                        attestation_client_ext_add_cb, 
                                        attestation_client_ext_free_cb, 
                                        NULL, 
                                        attestation_client_ext_parse_cb, 
                                        NULL);
    }
}
