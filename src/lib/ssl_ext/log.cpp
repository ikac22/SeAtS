#include "ssl_ext/log.hpp"

void SSL_keylog_cb(const SSL *ssl, const char *line){
    FILE  * fp;
    fp = fopen("key_log.log", "a");
    if (fp == NULL)
    {
        printf("Failed to create log file\n");
    }
    fprintf(fp, "%s\n", line);
    fclose(fp);
}
