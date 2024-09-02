
// CLIENT HELLO EXTENSION
#include "ssl_ext/client_ext_cbs.hpp"
#include "attest/verifier.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include "seats.hpp"
#include <cstdlib>


int client_hello_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg)
{
    EvidenceRequestClient* erq = (EvidenceRequestClient*)add_arg;
    *outlen = erq->serialize(out); 
    return true;
}

void client_hello_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg)
{
    free((void*)out); 
}


// SERVER CERTIFICATE EXTENTSION 
int  server_certificate_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    AttestationExtension* aex = new AttestationExtension();       
    seats::seats_client_socket* cs = (seats::seats_client_socket*) parse_arg;
    aex->deserialize(in);
    cs->verify(aex);
    return true;
}
