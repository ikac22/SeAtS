
#include "attest/sev/tool_attest/sev_tool_verifier.hpp"
#include "attest/sev/sev_structs.hpp"
#include "attest/sev/sev_verifier.hpp"
#include "attest/sev/tool_attest/cmd/sev_client.hpp"
#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdio>

seats::sev_tool_verifier::sev_tool_verifier(CredentialKind kind): 
    seats::sev_verifier(kind){}

void seats::sev_tool_verifier::setData(uint8_t* data){
    seats::sev_verifier::setData(data);
    
    SevEvidencePayload* sep = (SevEvidencePayload*) this->sep;
    
    save_attestation(&(this->sep->attestation_report));
    save_certs((const unsigned char*)this->sep->amd_cert_data, this->sep->amd_cert_data_len);
}

int seats::sev_tool_verifier::verify(){
    int result = 0;

    if (!verify_sev_snp_certs()){
        printf("PROVIDED CERTIFICATES INVALID!\n");
        result = 1;
    }

    if (!verify_attestation_signature()){
        printf("ATTESTATION SIGNATURE INVALID!\n");
        result = 2;
    } 

    if (!verify_measurement((char*)this->sep->attestation_report.measurement)){
        printf("MEASUREMENT INVALID!\nGOT: ");
        fwrite(this->sep->attestation_report.measurement, 48, 1, stdout);
        fflush(stdout);
        result = 3;
    }

    this->result = result;

    return result;
}


