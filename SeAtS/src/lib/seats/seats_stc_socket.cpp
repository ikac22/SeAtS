#include "seats/seats_stc_socket.hpp"
#include "seats/seats_types.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include "ssl_ext/server_ext_cbs.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

using namespace seats;

seats_stc_socket::seats_stc_socket(int sock_fd, struct sockaddr_in addr, socklen_t addr_len, attester* t_attester){
    socket_handle = sock_fd;
    this->addr = addr; 
    this->addr_len = addr_len;
    this->m_attester = t_attester;

    if(sock_fd <= 0){
        perror("Provided socket fd invalid!.");
        status = UNABLE_TO_CREATE_SOCKET;
        return;
    }

    leave_if_true(status = create_context());
    if(this->m_attester->configure_ssl_ctx(this->ssl_context)){
        status = seats_status::UNABLE_TO_CONFIGURE_SSL_CONTEXT;
    }
    leave_if_true(status = create_secure_socket());
}

seats_status seats_stc_socket::connect(const char*, int){ return seats_status::CONNECTION_ERROR; }

AttestationExtension* seats_stc_socket::attest(EvidenceRequestClient* erq){
    m_attester->set_data((uint8_t*)erq); 
    if (m_attester->attest())
        return NULL;
    return m_attester->getResult();
}

seats_status seats_stc_socket::create_context(){ 
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    int extension_adding_result;

    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ssl_context = NULL;
        return seats_status::UNABLE_TO_CREATE_SSL_CONTEXT;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, SEATS_CERT_FILE_PATH) <= 0) {
        perror("Unable to add cert chain file.");
        ERR_print_errors_fp(stderr);
        return seats_status::UNABLE_TO_CREATE_SSL_CONTEXT;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SEATS_KEY_FILE_PATH, SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to add key file.");
        ERR_print_errors_fp(stderr);
        return seats_status::UNABLE_TO_CREATE_SSL_CONTEXT;
    }

    extension_adding_result = 
        SSL_CTX_add_custom_ext(ctx,
                                ATTESTATION_CLIENT_HELLO_EXTENSION_TYPE,
                                SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE,
                                server_certificate_ext_add_cb, 
                                server_certificate_ext_free_cb, 
                                this, 
                                client_hello_ext_parse_cb,
                                this);

    if(!extension_adding_result){
        perror("Unable to add attestation extensions");
        SSL_CTX_free(ctx);
        ssl_context = NULL;
        return seats_status::FAILED_TO_ADD_SSL_EXTENSIONS;
    }

    ssl_context = ctx; 

    return seats_status::OK;
}
