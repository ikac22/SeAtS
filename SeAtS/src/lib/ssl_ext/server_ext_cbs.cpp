

// SERVER CERTIFICATE CALLBACKS
#include "seats/seats_types.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include "ssl_ext/server_ext_cbs.hpp"
#include "seats/seats_stc_socket.hpp"
#include <cstdlib>

#define UNUSED(x) (void)(x)

int seats::server_certificate_ext_add_cb(SSL *, unsigned int,
                                        unsigned int,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *,
                                        size_t chainidx, int *,
                                        void *add_arg)
{

    if(chainidx == 0){
        seats::seats_stc_socket* ss = (seats::seats_stc_socket*)add_arg;
        AttestationExtension* ax = ss->attest();
        *outlen = ax->serialize(out);
        delete ax;
    }
    return 1;
}

void seats::server_certificate_ext_free_cb(SSL *, unsigned int,
                                          unsigned int,
                                          const unsigned char *out,
                                          void *)
{
    delete []out;
}


// CLIENT HELLO CALLBACKS
int seats::client_hello_ext_parse_cb(SSL *, unsigned int,
                                          unsigned int,
                                          const unsigned char *in,
                                          size_t inlen, X509 *,
                                          size_t, int *,
                                          void *parse_arg)

{
    UNUSED(inlen);
    seats::seats_stc_socket* ss = (seats::seats_stc_socket*)parse_arg;
    ss->m_attester->set_data((uint8_t*)in); 
    // TODO: Add evidence output
    return 1;
}

