#include "seats/seats_server_socket.hpp"
#include "attest/mock/sev/mock_sev_attester.hpp"
#include "seats/seats_stc_socket.hpp"
#include "attest/sev/tool_attest/sev_tool_attester.hpp"

#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace seats;

seats_server_socket::seats_server_socket(uint port){
    leave_if_true(status = create_attester());
    leave_if_true(status = create_socket(port));
}

seats_server_socket::~seats_server_socket(){
    close(socket_handle);
    if(m_attester) delete m_attester;
}

seats_socket* seats_server_socket::accept(){ 
    int client_skt;
    struct sockaddr_in cli_addr; 
    socklen_t cli_addr_len = sizeof(cli_addr);

    client_skt = ::accept(socket_handle, (struct sockaddr*)&addr, &cli_addr_len);

    if (client_skt < 0) {
        perror("Unable to accept");
        status = seats_status::UNABLE_TO_ACCEPT_CONNECTION;
        return NULL;
    }

    return new seats_stc_socket(client_skt, addr, cli_addr_len, this->m_attester);
}

seats_status seats_server_socket::get_status(){ return status; }

seats_status seats_server_socket::create_socket(uint port){
    int optval = 1;

    socket_handle = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_handle < 0) {
        perror("Unable to create socket");
        return seats_status::UNABLE_TO_CREATE_SOCKET;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Reuse the address; good for quick restarts */
    if (setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
            < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(socket_handle);
        return seats_status::UNABLE_TO_SOCKET_REUSE_ADR;

    }

    if (bind(socket_handle, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        close(socket_handle);
        return seats_status::UNABLE_TO_BIND_SOCKET;
    }

    if (listen(socket_handle, 1) < 0) {
        perror("Unable to listen");

        return seats_status::UNABLE_TO_LISTEN;
    }

    return seats_status::OK;
}

seats_status seats_server_socket::create_attester(){
    // m_attester = new sev_tool_attester();
    m_attester = new mock_sev_attester();
    return seats_status::OK;
}

