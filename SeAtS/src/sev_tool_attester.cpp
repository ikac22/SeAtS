
#include "attest/sev/tool_attest/sev_tool_attester.hpp"
#include "attest/sev/sev_structs.hpp"
#include "attest/sev/tool_attest/cmd/sev_server.hpp"
#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdlib>

seats::sev_tool_attester::sev_tool_attester(CredentialKind kind):
    seats::sev_attester(kind){}

int seats::sev_tool_attester::attest(){ 
    SevEvidencePayload* sep = new SevEvidencePayload();

    char *cert_blob_buff = NULL;
    size_t cert_blob_buff_len = 0;

    if (!CERTS_LOADED){
        system(snpguest_certificates_cmd);
        system(snphost_import_cmd);
        CERTS_LOADED=true;
    } 
    
    load_cert_blob(&(sep->amd_cert_data), &(sep->amd_cert_data_len));

    get_attestation_report(&(sep->attestation_report)); 

    return true; 
}
