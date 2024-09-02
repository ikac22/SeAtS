#include "attest/sev/tool_attest/cmd/sev_client.hpp"
#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include <cstdio>
#include <cstring>

static void sprint_string_hex(char* dst, const unsigned char* s, int len){ 
    for(int i = 0; i < len; i++){
        sprintf(dst, "%02x", (unsigned int) *s++);
        dst+=2;
    }
}

int save_attestation(attestation_report_t *ar){
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

int verify_attestation_signature() { return !system(snpguest_attestation_cmd); }

int verify_measurement(char* measurement){
    char calc_measurement[96];
    char got_measurement[96];

    sprint_string_hex(got_measurement, (unsigned char*)measurement, 48);

    system(snpmeasure_cmd);
 
    FILE *measurement_file;

    measurement_file = fopen(CL_CALCULATED_ATTESTATION_FILE_PATH, "rb");

    fread((char*)calc_measurement, 96, 1, measurement_file);

    if (memcmp(calc_measurement, got_measurement, 96)){
        printf("\nCALCULATED: ");
        fwrite(calc_measurement, 96, 1, stdout);
        fflush(stdout);
        printf("\n");
        return false;
    }

    fclose(measurement_file);

    return true;
}

