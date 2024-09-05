#ifndef __SEATS_SERVER_SOCKET_HPP__
#define __SEATS_SERVER_SOCKET_HPP__

#include "attest/attester.hpp"
#include "seats/seats_socket.hpp"

#include <sys/types.h>

namespace seats{

class seats_server_socket{	
public:
    seats_server_socket(uint port);
    ~seats_server_socket();
    seats_socket* accept();
    seats_status get_status();
private:
    seats_status create_socket(uint port);
    seats_status create_attester();

    seats_status status;
    int socket_handle;
    struct sockaddr_in addr;
    attester* m_attester;
};

}

#endif // !__SEATS_SERVER_SOCKET_HPP__
