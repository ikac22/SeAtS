gcc src/main.c src/socket_config.c src/ssl_config.c src/tls_attest_ext.c -Iinclude  -lssl -lcrypto -o ssl_echo
