
// CLIENT HELLO EXTENSION
#include "ssl_ext/client_ext_cbs.hpp"
#include "attest/verifier.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "seats/seats_client_socket.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdlib>
#include <openssl/ssl.h>
#include <openssl/x509.h>


#define UNUSED(x) (void)(x)
int seats::client_hello_ext_add_cb(SSL *, unsigned int,
                                        unsigned int,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *,
                                        size_t, int *,
                                        void *add_arg)
{
    printf("Getting argument for client hello\n");
    seats::seats_client_socket* client_skt = (seats::seats_client_socket*)add_arg;

    printf("Serializing Evidence Request\n");
    *outlen = client_skt->erq->serialize(out);

    return 1;
}

void seats::client_hello_ext_free_cb(SSL *, unsigned int,
                                          unsigned int,
                                          const unsigned char *out,
                                          void *)
{
    UNUSED(out);
    printf("Freeing buffer det Client Hello created\n");
    delete []out;
}

// SERVER CERTIFICATE EXTENTSION 
int  seats::server_certificate_ext_parse_cb(SSL *, unsigned int,
                                          unsigned int,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *,
                                          void *parse_arg)
{
    UNUSED(inlen);

    if(chainidx == 0){
        printf("Getting public key\n");
        EVP_PKEY* pkey = X509_get0_pubkey(x);
        AttestationExtension* aex = new AttestationExtension();       
        seats::seats_client_socket* cs = (seats::seats_client_socket*) parse_arg;
        printf("Deserializing attestation extension\n");
        aex->deserialize(in);
        printf("Trying to verify the attestation!\n");
        if(cs->verify(aex, pkey))
            return false;
    }
    return true;
}
