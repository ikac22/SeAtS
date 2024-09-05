
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
    seats::seats_client_socket* client_skt = (seats::seats_client_socket*)add_arg;

    *outlen = client_skt->erq->serialize(out);

    return 1;
}

void seats::client_hello_ext_free_cb(SSL *, unsigned int,
                                          unsigned int,
                                          const unsigned char *out,
                                          void *)
{
    UNUSED(out);
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
        EVP_PKEY* pkey = X509_get0_pubkey(x);
        AttestationExtension* aex = new AttestationExtension();       
        seats::seats_client_socket* cs = (seats::seats_client_socket*) parse_arg;
        aex->deserialize(in);
        if(cs->verify(aex, pkey)){
            cs->close();
            return false;
        }
    }
    return true;
}
