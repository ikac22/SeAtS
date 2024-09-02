#include "seats.hpp"

using namespace seats;


class seats_server_socket: public seats_socket{	
public:
	seats_status connect(const char* host, int port);
	seats_status send(const char* data, int datalen);
	seats_status recv(char* data, int datalen);	
	seats_status send_async(const char* data, int datalen);
	seats_status close();		
	~seats_server_socket();
protected:
	seats_status create_context();
	seats_status create_socket();
	seats_status create_secure_socket();
};

seats::seats_server_socket::seats_server_socket(){
    this->create_socket();
    this->create_context();
    this->create_secure_socket();
}
