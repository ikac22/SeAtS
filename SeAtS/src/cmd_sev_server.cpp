
#include "attest/sev/tool_attest/cmd/sev_server.hpp"
#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include <cstddef>
#include <stdio.h>
#include <stdlib.h>

int load_cert_blob(char **cert_blob_buff, size_t* bufflen){
    FILE *file;
    char *buffer;
    unsigned long fileLen;

    //Open file
    file = fopen(SR_CERT_BLOB_FILE_PATH, "rb");
    if (!file)
    {
        fprintf(stderr, "Unable to open file %s", SR_CERT_BLOB_FILE_PATH);
        return false;
    }
    
    //Get file length
    fseek(file, 0, SEEK_END);
    fileLen=ftell(file);
    fseek(file, 0, SEEK_SET);

    //Allocate memory
    buffer=(char *)malloc(fileLen+1);
    if (!buffer)
    {
        fprintf(stderr, "Memory error!");
                                fclose(file);
        return false;
    }

    //Read file contents into buffer
    fread(buffer, fileLen, 1, file);
    fclose(file);

    *bufflen=fileLen;
    *cert_blob_buff = buffer;
    
    return true; 
    
}

int get_attestation_report(attestation_report_t* ar){
    FILE *att_file;
 
    system(snpguest_report_cmd);

    att_file = fopen(SR_ATTESTATION_FILE_PATH, "rb");

    fread((char*)ar, sizeof(attestation_report_t), 1, att_file);

    fclose(att_file);

    return 1;
}


