#include "attest/sev/tool_attest/sev_tool_attester.hpp"
#include "attest/sev/sev_attester.hpp"
#include "attest/sev/sev_structs.hpp"
#include "attest/sev/tool_attest/cmd/sev_server.hpp"
#include <cstdlib>
#include <string.h>

seats::sev_tool_attester::sev_tool_attester(): sev_attester(){
    SevEvidencePayload* sep = (SevEvidencePayload*)evidence_payload;

    if (!CERTS_LOADED){
        system(snpguest_certificates_cmd);
        system(snphost_import_cmd);
        CERTS_LOADED=true;
        load_cert_blob(&(sep->amd_cert_data), &(sep->amd_cert_data_len));
    } 
}

int seats::sev_tool_attester::attest(){ 
    SevEvidencePayload* sep = (SevEvidencePayload*) evidence_payload;

    printf("checking sep!\n");
    if(!sep){
        perror("Called attest before set_data!");
        return 1;
    }

    printf("alloc buffer!\n");
    char* buff64 = new char[64];

    printf("seting buffer to 0os\n");
    memset(buff64, 0, 64);

    printf("copying kat\n");
    memcpy(buff64, kat, katlen);
   
    char* report_data_filename = NULL;
    
    printf("saving report data\n");
    save_report_data_file(buff64, &report_data_filename, this->erq->nonce);

    printf("saving and getting attestation report\n");
    get_attestation_report(&(sep->attestation_report), report_data_filename, this->erq->nonce); 

    printf("finished with adding extension.");

    return false; 
}
