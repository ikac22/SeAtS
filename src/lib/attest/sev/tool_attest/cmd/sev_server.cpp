#include "attest/sev/tool_attest/cmd/common.hpp"
#include "attest/sev/tool_attest/cmd/sev_server.hpp"
#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include <cstddef>
#include <stdio.h>
#include <stdlib.h>


const char *snpguest_report_cmd = SNPGUEST_REPORT_CMD " " SR_ATTESTATION_FILE_PATH " " SR_REPORT_DATA_FILE_PATH " " SNPGUEST_LOG_PIPE;
const char *snphost_import_cmd = SNPHOST_IMPORT_CERTS_CMD " " SR_CERTS_PATH " " SR_CERT_BLOB_FILE_PATH " " SNPHOST_LOG_PIPE;
const char *snpguest_certificates_cmd = SNPGUEST_CERTIFICATES_CMD " pem " SR_CERTS_PATH " " SNPGUEST_LOG_PIPE;
bool CERTS_LOADED = false;

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

int save_report_data_file(char* buff64){
    FILE* report_data_file = fopen(SR_REPORT_DATA_FILE_PATH, "wb");
    fwrite(buff64, 1, 64, report_data_file);
    fclose(report_data_file);
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


