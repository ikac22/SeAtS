#ifndef __SEATS_STC_SOCKET_HPP__
#define __SEATS_STC_SOCKET_HPP__

#include "attest/attester.hpp"
#include "seats/seats_socket.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

namespace seats{

class seats_stc_socket: public seats_socket{
public:
    seats_stc_socket(int sock_fd, struct sockaddr_in addr, socklen_t addrlen, attester* t_attester);
	seats_status connect(const char* host, int port);
 
    friend int server_certificate_ext_add_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char **out, size_t *outlen, X509 *x, size_t chainidx, int *al, void *add_arg);
    friend void server_certificate_ext_free_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char *out, void *add_arg);
    friend int server_certificate_ext_parse_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char *in, size_t inlen, X509 *x, size_t chainidx, int *al, void *parse_arg);
private:
    AttestationExtension* attest(EvidenceRequestClient*);

    seats::attester* m_attester;
protected:
	seats_status create_context();

};

}
#endif // !__SEATS_STC_SOCKET_HPP__
