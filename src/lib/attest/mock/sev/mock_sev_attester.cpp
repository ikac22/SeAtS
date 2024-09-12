
#include "attest/mock/sev/mock_sev_attester.hpp"
#include "attest/mock/sev/mock_sev_common.hpp"
#include "attest/sev/sev_attester.hpp"
#include "attest/sev/sev_structs.hpp"
#include "ssl_ext/log.hpp"
#include <cstdlib>
#include <openssl/ssl.h>
#include <string.h>


seats::mock_sev_attester::mock_sev_attester(): sev_attester(){}

int seats::mock_sev_attester::configure_ssl_ctx(SSL_CTX* ctx){
    SSL_CTX_set_keylog_callback(ctx, SSL_keylog_cb);
    return seats::sev_attester::configure_ssl_ctx(ctx);
}

int seats::mock_sev_attester::attest(){ 
    SevEvidencePayload* sep = (SevEvidencePayload*) evidence_payload;

    if(!sep){
        perror("Called attest before set_data!");
        return 1;
    }

    // Mock attestsation report
    memset(&(sep->attestation_report), 0, sizeof(attestation_report_t));
    set_mock_str(&(sep->attestation_report.signature));
    set_mock_str(&(sep->attestation_report.measurement));
    memcpy(&(sep->attestation_report.report_data), kat, katlen); // KAT IS NOT MOCKED
    
    // Mock cert blob
    sep->amd_cert_data = new char[64];
    sep->amd_cert_data_len = 64;
    set_mock_str(sep->amd_cert_data);
   
    return 0; 
}
