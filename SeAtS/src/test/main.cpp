#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "seats/seats_client_socket.hpp"
#include"seats/seats_server_socket.hpp"
#include "seats/seats_types.hpp"


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

    seats::seats_server_socket* server_skt = NULL; 
    seats::seats_socket* client_skt = NULL;
    seats::seats_status status = seats::seats_status::OK;

    /* used by fgets */
    char buffer[BUFFERSIZE];
    char *txbuf;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    char *rem_server_ip = NULL;
    int target_port = 0; 
    int server_running = true;

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


    /* If server */
    if (isServer) {
        server_skt = new seats::seats_server_socket(target_port); 
        printf("We are the server on port: %d\n\n", target_port);


        /*
         * Loop to accept clients.
         * Need to implement timeouts on TCP & SSL connect/read functions
         * before we can catch a CTRL-C and kill the server.
         */
        while (server_running) {
            
            /* Wait for TCP connection from client */
            client_skt = server_skt->accept();
            printf("Client TCP connection accepted\n");

            status = client_skt->accept();
            if(status){
                printf("ERROR: Clinent SSL connection not established\n");
                server_running = false;
        
            } else {
                printf("Client SSL connection accepted\n\n");
                /* Echo loop */
                while (true) { 
                    /* Get message from client; will fail if client closes connection */
                    if ((rxlen = client_skt->recv(rxbuf, rxcap)) <= 0) {
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
                    if (client_skt->send(rxbuf, rxlen) <= 0) {
                        ERR_print_errors_fp(stderr);
                    }
                }
            }
            if (server_running) {
                delete client_skt;
                client_skt = NULL;
            }
        }
        printf("Server exiting...\n");
    }
    /* Else client */
    else {

        printf("We are the client\n\n");

        /* Create "bare" socket */
        client_skt = new seats::seats_client_socket;

        if(client_skt->connect(rem_server_ip, target_port)){
            perror("Unable to connect to host!");
            delete client_skt;
            client_skt = NULL;
        }
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
            if (client_skt->send(txbuf, strlen(txbuf)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            /* Wait for the echo */
            rxlen = client_skt->recv(rxbuf, strlen(txbuf));
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                break;
            }             
        }
        printf("Client exiting...\n");
    }

    /* Close up */
    if(client_skt)
        delete client_skt;

    if(server_skt)
        delete server_skt;

    printf("seatsecho exiting\n");

    return EXIT_SUCCESS;
}
