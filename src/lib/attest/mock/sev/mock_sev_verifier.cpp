#include "attest/mock/sev/mock_sev_attester.hpp"
#include "attest/mock/sev/mock_sev_common.hpp"
#include "attest/sev/sev_structs.hpp"
#include "attest/sev/sev_verifier.hpp"
#include "attest/mock/sev/mock_sev_verifier.hpp"
#include <cstdio>
#include <cstring>

seats::mock_sev_verifier::mock_sev_verifier():
    seats::sev_verifier(){}

void seats::mock_sev_verifier::set_data(uint8_t* data){
    seats::sev_verifier::set_data(data);     
}

int seats::mock_sev_verifier::verify(EVP_PKEY* pkey){
    int result = 0;

    if(check_mock_str(sep->amd_cert_data)){
        printf("AMD CERTS VALIDATION FAILED");
        result = 1;
    }
    
    if (check_mock_str(&(sep->attestation_report.signature))){
        printf("ATTESTATION SIGNATURE INVALID!\n");
        result = 2;
    } 

    if(check_mock_str(&(sep->attestation_report.measurement))){ 
        printf("ATTESTATION MEASUREMENT INVALID!\n");
        result = 3;
    }

    if (!verify_kat(pkey, this->sep, this->erq)){
        printf("INVALID KAT!");
        result = 4;
    }

    this->result = result;

    return result;
}


