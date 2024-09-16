
#ifndef __SEATS_CLIENT_SOCKET_HPP__
#define __SEATS_CLIENT_SOCKET_HPP__

#include "seats/seats_socket.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

namespace seats{

class seats_client_socket: public seats_socket{	
public:
    seats_client_socket(bool mock_t = false);
	~seats_client_socket();

	seats_status connect(const char* host, int port) override;
    
    friend int client_hello_ext_add_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char **out, size_t *outlen, X509 *x, size_t chainidx, int *al, void *add_arg);
    friend void client_hello_ext_free_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char *out, void *add_arg);
    friend int server_certificate_ext_parse_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char *in, size_t inlen, X509 *x, size_t chainidx, int *al, void *parse_arg);

private:
    bool mock;
    seats_status verify(AttestationExtension*, EVP_PKEY*);
    EvidenceRequestClient* erq;

protected:
	seats_status create_context();
	seats_status create_socket();
};

}
#endif // !__SEATS_CLIENT_SOCKET_HPP__
