
// CLIENT HELLO EXTENSION
#include "ssl_ext/client_ext_cbs.hpp"
#include "attest/verifier.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdlib>
#include <openssl/ssl.h>


#define UNUSED(x) (void)(x)
int client_hello_ext_add_cb(SSL *, unsigned int,
                                        unsigned int,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *,
                                        size_t, int *,
                                        void *add_arg)
{
    UNUSED(out);
    UNUSED(outlen);
    UNUSED(add_arg);

    printf("client_hello_ext_add_cb\n");
    // EvidenceRequestClient* erq = (EvidenceRequestClient*)add_arg;
    // *outlen = erq->serialize(out); 
    // return true;
    return 1;
}

void client_hello_ext_free_cb(SSL *, unsigned int,
                                          unsigned int,
                                          const unsigned char *out,
                                          void *add_arg)
{
    UNUSED(out);
    UNUSED(add_arg);
    printf("client_hello_ext_free_cb\n");
    // free((void*)out); 
}


// SERVER CERTIFICATE EXTENTSION 
int  server_certificate_ext_parse_cb(SSL *ssl, unsigned int,
                                          unsigned int,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *,
                                          void *parse_arg)
{
    UNUSED(in);
    UNUSED(inlen);
    UNUSED(parse_arg);
    UNUSED(x);
    UNUSED(chainidx);

    X509* cert = SSL_get1_peer_certificate(ssl);
    if(!cert & !x){
        printf("FAILED TO GET PEER CERT!");
    }

    // if(chainidx == 0){
        printf("server_certificate_ext_parse_cb\n");
        // AttestationExtension* aex = new AttestationExtension();       
        // seats::seats_client_socket* cs = (seats::seats_client_socket*) parse_arg;
        // aex->deserialize(in);
        // cs->verify(aex);
        // return true;
    // }
    return 1;
}
