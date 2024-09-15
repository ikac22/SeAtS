#include "attest/sev/tool_attest/sev_tool_attester.hpp"
#include "attest/sev/sev_attester.hpp"
#include "attest/sev/sev_structs.hpp"
#include "attest/sev/tool_attest/cmd/sev_server.hpp"
#include <cstdlib>
#include <string.h>

seats::sev_tool_attester::sev_tool_attester(): sev_attester(){}

int seats::sev_tool_attester::attest(){ 
    SevEvidencePayload* sep = (SevEvidencePayload*) evidence_payload;

    if(!sep){
        perror("Called attest before set_data!");
        return 1;
    }

    char* buff64 = new char[64];

    memset(buff64, 0, 64);

    if (!CERTS_LOADED){
        system(snpguest_certificates_cmd);
        system(snphost_import_cmd);
        CERTS_LOADED=true;
        load_cert_blob(&(sep->amd_cert_data), &(sep->amd_cert_data_len));
    } 

    memcpy(buff64, kat, katlen);
   
    char* report_data_filename = NULL;
    
    save_report_data_file(buff64, &report_data_filename, this->erq->nonce);

    get_attestation_report(&(sep->attestation_report), report_data_filename); 

    return true; 
}
