#include "attest/sev/tool_attest/cmd/common.hpp"
#include "attest/sev/tool_attest/cmd/sev_client.hpp"
#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include <cstdio>
#include <cstring>
#include <string>

const char *snpmeasure_cmd = CL_CALCULATE_MEASUREMENT_SCRIPT_PATH " > " CL_CALCULATED_ATTESTATION_FILE_PATH;
const char *snpguest_certs_cmd = SNPGUEST_VERIFY_CERTS_CMD " " CL_CERTS_PATH " " SNPGUEST_LOG_PIPE;
const char *snpguest_attestation_cmd = SNPGUEST_VERIFY_ATTESTATION_CMD " " CL_CERTS_PATH " " CL_ATTESTATION_FILE_PATH " " SNPGUEST_LOG_PIPE; 
const char *snphost_export_cmd = SNPHOST_EXPORT_CERTS_CMD " pem " CL_CERT_BLOB_FILE_PATH " " CL_CERTS_PATH " " SNPHOST_LOG_PIPE; 
const char *print_attestation_cmd = "xxd " CL_ATTESTATION_FILE_PATH;
bool CERTS_SAVED = false;
bool MEASUREMEN_CALCULATED = false;


static void sprint_string_hex(char* dst, const unsigned char* s, int len){ 
    for(int i = 0; i < len; i++){
        sprintf(dst, "%02x", (unsigned int) *s++);
        dst+=2;
    }
}

int save_attestation(attestation_report_t *ar, char** filename, size_t nonce){
    std::string fname = std::string(CL_ATTESTATION_FILE_PATH "_") + std::to_string(nonce);
    *filename = new char[fname.length() + 1];
    strcpy(*filename, fname.c_str());

    FILE* att_file = fopen(CL_ATTESTATION_FILE_PATH, "wb");

    fwrite(ar, sizeof(attestation_report_t), 1, att_file);

    fclose(att_file);

    return 1;
}

int save_certs(const unsigned char* certs_blob, size_t length){
    FILE* cert_file = fopen(CL_CERT_BLOB_FILE_PATH, "wb");
    fwrite(certs_blob, length, 1, cert_file);

    fclose(cert_file);
    
    system(snphost_export_cmd);

    return 1;
}

int verify_sev_snp_certs(){ return !system(snpguest_certs_cmd); }

int verify_attestation_signature(char* filename) {
    std::string cmd = std::string(SNPGUEST_VERIFY_ATTESTATION_CMD " " CL_CERTS_PATH " " ) + std::string(filename) + std::string(" " SNPGUEST_LOG_PIPE);

    return !system(snpguest_attestation_cmd); 
}

int verify_measurement(char* measurement, size_t nonce){
    std::string fname = std::string(CL_CALCULATED_ATTESTATION_FILE_PATH "_") + std::to_string(nonce);
    char calc_measurement[96];
    char got_measurement[96];

    sprint_string_hex(got_measurement, (unsigned char*)measurement, 48);

    system(snpmeasure_cmd);
 
    FILE *measurement_file;

    measurement_file = fopen(fname.c_str(), "rb");

    fread((char*)calc_measurement, 96, 1, measurement_file);

    if (memcmp(calc_measurement, got_measurement, 96)){
        printf("\nCALCULATED: ");
        fwrite(calc_measurement, 96, 1, stdout);
        fflush(stdout);
        printf("\n");
        return false;
    }

    fclose(measurement_file);

    std::remove(fname.c_str());

    return true;
}

