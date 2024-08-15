/*
 *  Copyright 2022-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "common.h"
#include "ssl_config.h"
#include "socket_config.h"
#include "tls_attest_ext.h"


/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool    server_running = true;


static void usage(void)
{
    printf("Usage: sslecho s port\n");
    printf("       --or--\n");
    printf("       sslecho c ip port\n");
    printf("       c=client, s=server, ip=dotted ip of server, port=port of the server\n");
    exit(EXIT_FAILURE);
}

#define BUFFERSIZE 1024
int main(int argc, char **argv)
{
    bool isServer;
    int result;

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int server_skt = -1;
    int client_skt = -1;

    /* used by fgets */
    char buffer[BUFFERSIZE];
    char *txbuf;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    char *rem_server_ip = NULL;
    char *rem_server_port = NULL;
    int target_port = 0; 


    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);

    /* ignore SIGPIPE so that server can continue running when client pipe closes abruptly */
    signal(SIGPIPE, SIG_IGN);

    setbuf(stdout, NULL);

    /* Splash */
    printf("\nsslecho : Simple Echo Client/Server : %s : %s\n\n", __DATE__,
    __TIME__);

    /* Need to know if client or server */
    if (argc < 3) {
        usage();
        /* NOTREACHED */
    }
    isServer = (argv[1][0] == 's') ? true : false;
    /* If client get remote server address (could be 127.0.0.1) */
    if (!isServer) {
        if (argc != 4) { usage(); }
        rem_server_ip = argv[2];
        target_port = atoi(argv[3]);
    }
    else{
        if (argc != 3){ usage(); }
        target_port = atoi(argv[2]);
    }

    /* Create context used by both client and server */
    ssl_ctx = create_context(isServer);

    /* If server */
    if (isServer) {

        printf("We are the server on port: %d\n\n", target_port);

        /* Configure server context with appropriate key files */
        configure_server_context(ssl_ctx);

        /* Create server socket; will bind with server port and listen */
        server_skt = create_socket(true, target_port);

        /*
         * Loop to accept clients.
         * Need to implement timeouts on TCP & SSL connect/read functions
         * before we can catch a CTRL-C and kill the server.
         */
        while (server_running) {
            /* Wait for TCP connection from client */
            client_skt = accept(server_skt, (struct sockaddr*) &addr,
                    &addr_len);
            if (client_skt < 0) {
                perror("Unable to accept");
                exit(EXIT_FAILURE);
            }

            printf("Client TCP connection accepted\n");

            /* Create server SSL structure using newly accepted client socket */
            ssl = SSL_new(ssl_ctx);
            if (!SSL_set_fd(ssl, client_skt)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }

            /* Wait for SSL connection from the client */
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                server_running = false;
            } else {

                printf("Client SSL connection accepted\n\n");

                /* Echo loop */
                while (true) {
                    /* Get message from client; will fail if client closes connection */
                    if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
                        if (rxlen == 0) {
                            printf("Client closed connection\n");
                        } else {
                            printf("SSL_read returned %d\n", rxlen);
                        }
                        ERR_print_errors_fp(stderr);
                        break;
                    }
                    /* Insure null terminated input */
                    rxbuf[rxlen] = 0;
                    /* Look for kill switch */
                    if (strcmp(rxbuf, "kill\n") == 0) {
                        /* Terminate...with extreme prejudice */
                        printf("Server received 'kill' command\n");
                        server_running = false;
                        break;
                    }
                    /* Show received message */
                    printf("Received: %s", rxbuf);
                    /* Echo it back */
                    if (SSL_write(ssl, rxbuf, rxlen) <= 0) {
                        ERR_print_errors_fp(stderr);
                    }
                }
            }
            if (server_running) {
                /* Cleanup for next client */
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_skt);
            }
        }
        printf("Server exiting...\n");
    }
    /* Else client */
    else {

        printf("We are the client\n\n");

        /* Configure client context so we verify the server correctly */
        configure_client_context(ssl_ctx);

        /* Create "bare" socket */
        client_skt = create_socket(false, target_port);
        /* Set up connect address */
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, rem_server_ip, &addr.sin_addr.s_addr);
        addr.sin_port = htons(target_port);
        /* Do TCP connect with server */
        if (connect(client_skt, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
            perror("Unable to TCP connect to server");
            goto exit;
        } else {
            printf("TCP connection to server successful\n");
        }

        /* Create client SSL structure using dedicated client socket */
        ssl = SSL_new(ssl_ctx);
        if (!SSL_set_fd(ssl, client_skt)) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }
        /* Set hostname for SNI */
        SSL_set_tlsext_host_name(ssl, rem_server_ip);
        /* Configure server hostname check */
        if (!SSL_set1_host(ssl, rem_server_ip)) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }

        /* Now do SSL connect with server */
        if (SSL_connect(ssl) == 1) {
            if(!attestation_extension_present){
                printf("------ ATTESTATION EXTENSION NOT PRESENT ------\n");
                goto exit;
            }
            printf("SSL connection to server successful\n\n");

            /* Loop to send input from keyboard */
            while (true) {
                /* Get a line of input */
                memset(buffer, 0, BUFFERSIZE);
                txbuf = fgets(buffer, BUFFERSIZE, stdin);

                /* Exit loop on error */
                if (txbuf == NULL) {
                    break;
                }
                /* Exit loop if just a carriage return */
                if (txbuf[0] == '\n') {
                    break;
                }
                /* Send it to the server */
                if ((result = SSL_write(ssl, txbuf, strlen(txbuf))) <= 0) {
                    printf("Server closed connection\n");
                    ERR_print_errors_fp(stderr);
                    break;
                }

                /* Wait for the echo */
                rxlen = SSL_read(ssl, rxbuf, rxcap);
                if (rxlen <= 0) {
                    printf("Server closed connection\n");
                    ERR_print_errors_fp(stderr);
                    break;
                } else {
                    /* Show it */
                    rxbuf[rxlen] = 0;
                    printf("Received: %s", rxbuf);
                }
            }
            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }
    }
exit:
    /* Close up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1)
        close(client_skt);
    if (server_skt != -1)
        close(server_skt);

    printf("sslecho exiting\n");

    return EXIT_SUCCESS;
}
