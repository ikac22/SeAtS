#include"seats.hpp"

using namespace seats;

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

seats_status seats::seats_client_socket::create_socket(){
     
}

seats::seats_client_socket::seats_client_socket(){
    this->create_socket();
    this->create_context();
    this->create_secure_socket();
}




