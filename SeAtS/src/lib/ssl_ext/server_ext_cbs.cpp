

// SERVER CERTIFICATE CALLBACKS
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include "ssl_ext/server_ext_cbs.hpp"
#include <cstdlib>

#define UNUSED(x) (void)(x)

int server_certificate_ext_add_cb(SSL *, unsigned int,
                                        unsigned int,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *,
                                        size_t chainidx, int *,
                                        void *add_arg)
{
    *out = (const unsigned char*)"mica";
    *outlen = 4;

    UNUSED(add_arg);
    UNUSED(chainidx);

    // if(chainidx == 0){
    printf("server_certificate_ext_add_cb\n");
        // seats::seats_stc_socket* ss = (seats::seats_stc_socket*)add_arg;
        // AttestationExtension* ae = ss->attest();
        // *outlen = ae->serialize(out);
        // return true;
    // }
    return 1;
}

void  server_certificate_ext_free_cb(SSL *, unsigned int,
                                          unsigned int,
                                          const unsigned char *out,
                                          void *add_arg)
{
    UNUSED(out);
    UNUSED(add_arg);

    printf("server_certificate_ext_free_cb\n");
    // free((void*)out);
}


// CLIENT HELLO CALLBACKS
int  client_hello_ext_parse_cb(SSL *, unsigned int,
                                          unsigned int,
                                          const unsigned char *in,
                                          size_t inlen, X509 *,
                                          size_t, int *,
                                          void *parse_arg)

{
    UNUSED(in);
    UNUSED(inlen);
    UNUSED(parse_arg);

    printf("client_hello_ext_parse_cb\n");
    // EvidenceRequestClient* erq = new EvidenceRequestClient();
    // seats::seats_stc_socket* ss = (seats::seats_stc_socket*)parse_arg;
    // erq->deserialize(in);
    // ss->m_attester->set_data()
    // return true;
    return 1;
}

