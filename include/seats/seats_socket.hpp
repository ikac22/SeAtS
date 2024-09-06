#ifndef __SEATS_SOCKET_HPP__
#define __SEATS_SOCKET_HPP__

#include "seats/seats_types.hpp"

#include <netinet/in.h>
#include <openssl/crypto.h>
#include <sys/socket.h>

namespace seats{
class seats_socket{
public:
    seats_socket() = default;
	virtual ~seats_socket();
	
	SSL_CTX* get_ssl_context();

	virtual seats_status connect(const char* host, int port);
    virtual seats_status accept();
	virtual seats_status close();

	virtual int send(const char* data, int datalen);
	virtual int recv(char* data, int datalen);	

    seats_status get_status();

protected:
    virtual seats_status create_secure_socket();

    seats_status status;

    struct sockaddr_in addr;
    socklen_t addr_len;
	int socket_handle;

	SSL_CTX* ssl_context;
	SSL* ssl_session;	
};

}
#endif // !__SEATS_SOCKET_HPP__

