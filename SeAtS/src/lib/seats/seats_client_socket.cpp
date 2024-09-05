#include "seats/seats_client_socket.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/client_ext_cbs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

#include <cstdlib>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace seats;

seats_client_socket::seats_client_socket(){
    static int rand_init = false;
    if(!rand_init) srand(time(0));

    this->erq = new EvidenceRequestClient();
    // ADD FUNCTION FOR CHOOSING SUPPORTED EVIDENCE TYPES 
    // For now only one
    EvidenceType et;
    et.type_encoding = TypeEncoding::CONTENT_FORMAT;
    et.supported_content.content_format = ContentFormat::BINARY_FORMAT;
    
    erq->supported_evidence_types.push_back(et);

    leave_if_true(status = create_socket());
    leave_if_true(status = create_context());
}

seats_client_socket::~seats_client_socket(){
    delete erq;
}

seats_status seats_client_socket::connect(const char* host, int port){ 
    this->erq->nonce = rand();
    return seats_socket::connect(host, port); 
}

seats_status seats_client_socket::verify(AttestationExtension*){
    
    return seats_status::NOT_IMPLEMENTED_ERROR;
 
};

seats_status seats_client_socket::create_context(){
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    int extension_adding_result;

    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ssl_context = NULL;
        return seats_status::UNABLE_TO_CREATE_SSL_CONTEXT;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if(!SSL_CTX_set_default_verify_paths(ctx)){
        perror("Unable to create SSL context");
        SSL_CTX_free(ctx);
        ssl_context = NULL;
        return seats_status::UNABLE_TO_CREATE_SSL_CONTEXT;
    }

    extension_adding_result = 
        SSL_CTX_add_custom_ext(ctx,
                                ATTESTATION_CLIENT_HELLO_EXTENSION_TYPE,
                                SSL_EXT_CLIENT_HELLO |  SSL_EXT_TLS1_3_CERTIFICATE,
                                client_hello_ext_add_cb, 
                                client_hello_ext_free_cb, 
                                erq, 
                                server_certificate_ext_parse_cb, 
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

seats_status seats_client_socket::create_socket(){ 
    socket_handle = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_handle < 0) {
        perror("Unable to create socket");
        return seats_status::UNABLE_TO_CREATE_SOCKET;
    }
    return seats_status::OK;
}
// when creating context set vierifying to none



