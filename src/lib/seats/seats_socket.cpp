#include "seats/seats_socket.hpp"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace seats;

seats_socket::~seats_socket(){ 
    if(ssl_session){
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
        ssl_session = NULL;
    }

    if(ssl_context)
        SSL_CTX_free(ssl_context);

    if(socket_handle > 0)
        ::close(socket_handle);
}

SSL_CTX* seats_socket::get_ssl_context(){
    return ssl_context;
}

seats_status seats_socket::connect(const char* host, int port){ 
    seats_status result = seats_status::OK;
 
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, host, &addr.sin_addr.s_addr);
    addr.sin_port = htons(port);
    /* Do TCP connect with server */
    if (::connect(socket_handle, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        perror("Unable to TCP connect to server");
        return seats_status::CONNECTION_ERROR;
    }

    if((result = create_secure_socket())){
        perror("FAILED TO CREATE SECURE SOCKET!");
        return result;
    }

    if(!ssl_session){
        perror("SSL session not created, you cannot connect.\n");
        return seats_status::CONNECTION_ERROR;
    }

    if (!SSL_connect(ssl_session)) {
        //TODO: check if attestation message is present
        perror("SSL connection to server failed\n\n");
        ERR_print_errors_fp(stderr);
        return seats_status::CONNECTION_ERROR;
    }

    return seats_status::OK;
}

seats_status seats_socket::accept(){
    if(!ssl_session){
        perror("SSL session not created, you cannot accept.\n");
        return seats_status::UNABLE_TO_ACCEPT_SESSION;
    }

    if (SSL_accept(ssl_session) <= 0) {
        perror("Unable to accept secure ssl connection from client\n");
        ERR_print_errors_fp(stderr);
        return seats_status::UNABLE_TO_ACCEPT_SESSION;
    }
    return seats_status::OK;
}
int seats_socket::send(const char* data, int datalen){ 
    if(!ssl_session){ 
        perror("SSL session not created, you cannot send packets.\n");
        return seats_status::SENDING_FAILED;
    }
    
    int txlen = SSL_write(ssl_session, data, datalen); 
    if (txlen <= 0) {
        perror("Unable to send packets.");
        ERR_print_errors_fp(stderr);
    }
    return txlen;
}

seats_status seats_socket::close(){
    if(ssl_session){
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
        ssl_session = NULL;
    }
   
    if(socket_handle > 0)
        ::shutdown(socket_handle, SHUT_RDWR);

    return seats_status::OK;
}

int seats_socket::recv(char* data, int datalen){
    if(!ssl_session){ 
        perror("SSL session not created, you cannot recieve packets.\n");
        return seats_status::RECEIVING_FAILED;
    }

    int rxlen = SSL_read(ssl_session, (void*)data, datalen);
    if (rxlen <= 0) {
        perror("Unable to receive packets.");
        ERR_print_errors_fp(stderr);
    }
    return rxlen;
}	

seats_status seats_socket::get_status(){
    return status;
}

seats_status seats_socket::create_secure_socket(){ 
    ssl_session = SSL_new(ssl_context);
    seats_status result = seats_status::OK;

    if(!ssl_session){ 
        perror("Unable to create ssl session");
        result = seats_status::UNABLE_TO_CREATE_SSL_SESSION; 
        goto end_create_secure_socket; 
    }

    if (!SSL_set_fd(ssl_session, socket_handle)) {
        perror("Unable to set socket for ssl session");
        ERR_print_errors_fp(stderr);
        result = seats_status::UNABLE_TO_SET_SOCKET_FOR_SSL_SESSION; 
        goto end_create_secure_socket;
    }

end_create_secure_socket:
    if(ssl_session && result){
        SSL_free(ssl_session);
        ssl_session = NULL;
    }
    return result;

}
