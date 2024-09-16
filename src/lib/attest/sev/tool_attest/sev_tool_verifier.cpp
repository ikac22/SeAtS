#include "attest/sev/tool_attest/sev_tool_verifier.hpp"
#include "attest/sev/sev_structs.hpp"
#include "attest/sev/sev_verifier.hpp"
#include "attest/sev/tool_attest/cmd/sev_client.hpp"
#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdio>
#include <cstring>

seats::sev_tool_verifier::sev_tool_verifier():
    seats::sev_verifier(){}

void seats::sev_tool_verifier::set_data(uint8_t* data){
    seats::sev_verifier::set_data(data);
}

int seats::sev_tool_verifier::verify(EVP_PKEY* pkey){
    int result = 0;
    char* att_filename = NULL;

    save_attestation(&(this->sep->attestation_report), &att_filename, this->erq->nonce);
    if(!CERTS_SAVED){
        save_certs((const unsigned char*)this->sep->amd_cert_data, this->sep->amd_cert_data_len);
        CERTS_SAVED = true;
    }

    printf("Verifying certs...\n");
    if (!verify_sev_snp_certs()){
        printf("PROVIDED CERTIFICATES INVALID!\n");
        result = 1;
    }

    printf("Verifying att signature..\n");
    if (!verify_attestation_signature(att_filename)){
        printf("ATTESTATION SIGNATURE INVALID!\n");
        result = 2;
    } 

    printf("Verifying att measurement..\n");
    if (!verify_measurement((char*)this->sep->attestation_report.measurement, this->erq->nonce)){
        printf("MEASUREMENT INVALID!\nGOT: ");
        fwrite(this->sep->attestation_report.measurement, 48, 1, stdout);
        fflush(stdout);
        result = 3;
    }

    printf("Removing attestation file..\n");
    std::remove(att_filename);

    printf("Verifying kat..\n");
    if (!verify_kat(pkey, this->sep, this->erq)){
        printf("INVALID KAT!");
        result = 4;
    }

    this->result = result;

    printf("Finished verification..\n");
    return result;
}


