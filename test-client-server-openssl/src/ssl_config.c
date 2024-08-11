#include "ssl_config.h"
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls_attest_ext.h"

SSL_CTX* create_context(bool isServer)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (isServer)
        method = TLS_server_method();
    else
        method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_server_context(SSL_CTX *ctx, const char* snpguest_path)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "certs/server/server.crt") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/server/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int result = add_attestation_extension(ctx, true, snpguest_path);
    printf("Server extension adding result: %d\n", result);


}

void configure_client_context(SSL_CTX *ctx)
{
    /*
     * Configure the client to abort the handshake if certificate verification
     * fails
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /*
     * In a real application you would probably just use the default system certificate trust store and call:
     *     SSL_CTX_set_default_verify_paths(ctx);
     * In this demo though we are using a self-signed certificate, so the client must trust it directly.
     */
    if (!SSL_CTX_load_verify_locations(ctx, "certs/ca/ca.crt", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
 
    int result = add_attestation_extension(ctx, false, NULL);
    printf("Client extension adding result: %d\n", result);
}
