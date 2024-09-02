

// SERVER CERTIFICATE CALLBACKS
#include "seats.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include "ssl_ext/server_ext_cbs.hpp"
#include <cstdlib>

int server_certificate_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg)
{
    seats::seats_server_socket* ss = (seats::seats_server_socket*)add_arg;
    AttestationExtension* ae = ss->attest();
    *outlen = ae->serialize(out);
    return true;
}

void  server_certificate_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg)
{
    free((void*)out);
}


// CLIENT HELLO CALLBACKS
int  client_hello_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)

{
    EvidenceRequestClient* erq = new EvidenceRequestClient();
    seats::seats_server_socket* ss = (seats::seats_server_socket*)parse_arg;
    erq->deserialize(in);
    ss->create_attester(erq);
    return true;
}

