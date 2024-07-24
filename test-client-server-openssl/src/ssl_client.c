#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>


int main(){

    /* 
     * Create an SSL_CTX which we can use to create SSL objects from. We
     * want an SSL_CTX for creating clients so we use TLS_client_method()
     * here.
     */
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("Failed to create the SSL_CTX\n");
        return 1;
    }

    /*
     * Configure the client to abort the handshake if certificate
     * verification fails. Virtually all clients should do this unless you
     * really know what you are doing.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);    
    
    /* Configure client which ca certs to trust */ 
    if (!SSL_CTX_load_verify_dir(ctx,"certs/ca")) {
        printf("Failed to set the default trusted certificate store\n");
        return 1; 
    } 

    /*
     * TLSv1.1 or earlier are deprecated by IETF and are generally to be
     * avoided if possible. We require a minimum TLS version of TLSv1.2.
     */
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        printf("Failed to set the minimum TLS protocol version\n");
        return 1;
    }
    
    
    SSL* ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("Failed to create the SSL object\n");
        return 1;
    }    

    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        return NULL;
    
    struct sockaddr_in serveraddr;
    struct hostent *server;
    
    server = gethostbyname("www.openssl.org");
    if (server == NULL) {
        close(sock);
        return NULL;
    }
    
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = server->h_addrtype;
    serveraddr.sin_port = htons(443);
    memcpy(&serveraddr.sin_addr.s_addr, server->h_addr, server->h_length);
    
    if (connect(sock, (struct sockaddr *)&serveraddr,
                sizeof(serveraddr)) == -1) {
        close(sock);
        return NULL;
    }
}
