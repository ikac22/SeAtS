
#include "attest/sev/tool_attest/sev_tool_verifier.hpp"
#include "attest/sev/sev_structs.hpp"
#include "attest/sev/sev_verifier.hpp"
#include "attest/sev/tool_attest/cmd/sev_client.hpp"
#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdio>
#include <cstring>

bool verify_kat(EVP_PKEY* pkey, SevEvidencePayload* sep, EvidenceRequestClient* erq){
    const unsigned char* m;
    size_t mlen = erq->serialize(&m);

    char* dig;
    unsigned int diglen;

    
    if(get_sha256_digest((char*)m, mlen, &dig, &diglen)){
        perror("Failed to generate digest of the client hello extension message");
        delete []m;
        return false;
    }
    delete []m;

    if(verify_signature(pkey, sep->sig, sep->siglen, dig, diglen)){
        perror("Failed to verify signature of the given TIK!");
        delete []dig;
        return false;
    }
    delete []dig;

    m = (const unsigned char*)new char[32];
    memcpy((void*)m, sep->attestation_report.report_data, 32);
    if(get_sha256_digest(sep->sig, sep->siglen, &dig, &diglen)){
        perror("Unable to generate hash from signature!");
        delete []m;
        return false;
    }

    if(memcmp(m, dig, diglen)){
        perror("Hash from attestation report dont match calculated hash of signature!");
        delete []m;
        delete []dig;
        return false; 
    }
    delete []m;
    delete []dig;

    return true;
}

seats::sev_tool_verifier::sev_tool_verifier():
    seats::sev_verifier(){}

void seats::sev_tool_verifier::set_data(uint8_t* data){
    seats::sev_verifier::set_data(data);
     
    save_attestation(&(this->sep->attestation_report));
    save_certs((const unsigned char*)this->sep->amd_cert_data, this->sep->amd_cert_data_len);
}

int seats::sev_tool_verifier::verify(EVP_PKEY* pkey){
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

    if (!verify_kat(pkey, this->sep, this->erq)){
        printf("INVALID KAT!");
        result = 4;
    }

    this->result = result;

    return result;
}


