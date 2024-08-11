
#ifndef __SEATS_H__
#define __SEATS_H__

#include <openssl/ssl.h>

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
	SSL_CTX* ssl_context;
};

class seats_server_socket: public seats_socket{	
	seats_status connect(const char* host, int port);
	seats_status send(const char* data, int datalen);
	seats_status recv(char* data, int datalen);	
	seats_status send_async(const char* data, int datalen);
	seats_status close();		
	~seats_server_socket();
};

class seats_client_socket: public seats_socket{	
	seats_status connect(const char* host, int port);
	seats_status send(const char* data, int datalen);
	seats_status recv(char* data, int datalen);	
	seats_status send_async(const char* data, int datalen);
	seats_status close();		
	~seats_client_socket();
};
}

#endif
