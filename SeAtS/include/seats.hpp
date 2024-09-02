
#ifndef __SEATS_H__
#define __SEATS_H__

#include "attest/attester.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include "ssl_ext/server_ext_cbs.hpp"
#include "ssl_ext/client_ext_cbs.hpp"
#include <openssl/ssl.h>
#include "attest/verifier.hpp"

namespace seats{

enum seats_status{
	CONNECTION_OK,
	CONNECTION_ERROR,
	ATTESTATION_INVALID,
	SENDING_FAILED,
	SENDING_OK
};

class seats_socket{
public:
	seats_socket();
	virtual ~seats_socket();
	
	SSL_CTX* get_ssl_context();
	virtual seats_status connect(const char* host, int port) = 0;
	virtual seats_status send(const char* data, int datalen) = 0;
	virtual seats_status recv(char* data, int datalen) = 0;	
	virtual seats_status send_async(const char* data, int datalen) = 0;
	virtual seats_status close() = 0;

protected:
	virtual seats_status create_context() = 0;
	virtual seats_status create_socket() = 0;
	virtual seats_status create_secure_socket(int socket_handle, SSL_CTX* context) = 0;

	int socket_handle;
	SSL_CTX* ssl_context;
	SSL* ssl_session;	
};

class seats_server_socket: public seats_socket{	
public:
    seats_server_socket();
	seats_status connect(const char* host, int port);
	seats_status send(const char* data, int datalen);
	seats_status recv(char* data, int datalen);	
	seats_status send_async(const char* data, int datalen);
	seats_status close();		
	~seats_server_socket();
    
    friend int server_certificate_ext_add_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char **out, size_t *outlen, X509 *x, size_t chainidx, int *al, void *add_arg);
    friend void server_certificate_ext_free_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char *out, void *add_arg);
    friend int server_certificate_ext_parse_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char *in, size_t inlen, X509 *x, size_t chainidx, int *al, void *parse_arg);
private:
    EvidenceRequestClient* erq;
    void verify(AttestationExtension*);
protected:
	seats_status create_context();
	seats_status create_socket();
	seats_status create_secure_socket();
};

class seats_client_socket: public seats_socket{	
public:
    seats_client_socket();
	seats_status connect(const char* host, int port);
	seats_status send(const char* data, int datalen);
	seats_status recv(char* data, int datalen);	
	seats_status send_async(const char* data, int datalen);
	seats_status close();	
	~seats_client_socket();
    
    friend int client_hello_ext_add_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char **out, size_t *outlen, X509 *x, size_t chainidx, int *al, void *add_arg);
    friend void client_hello_ext_free_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char *out, void *add_arg);
    friend int server_certificate_ext_parse_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char *in, size_t inlen, X509 *x, size_t chainidx, int *al, void *parse_arg);

private:
    attester* m_attester;
    void create_attester(EvidenceRequestClient*);
    AttestationExtension* attest();

protected:
	seats_status create_context();
	seats_status create_socket();
	seats_status create_secure_socket();
};

}

#endif
