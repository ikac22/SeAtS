#ifndef __SEV_STRUCTS_H__
#define __SEV_STRUCTS_H__

#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

#include <cstdint>
#include <openssl/crypto.h>

int get_sha256_digest(char* m, size_t mlen, char** dig, unsigned int* diglen);
int digest_and_sign(EVP_PKEY* pkey, char* m, size_t mlen, char** sig, size_t* siglen); 
int verify_signature(EVP_PKEY* pkey, char* sig, size_t siglen, char* orig, size_t origlen);

struct SevEvidencePayload: EvidencePayload{
    int serialize(const unsigned char**) override;
    int deserialize(const unsigned char*) override;

    attestation_report_t attestation_report;
    uint64_t amd_cert_data_len;
    char* amd_cert_data;
    size_t siglen;
    char* sig;
    EVP_PKEY* pkey;
};

bool verify_kat(EVP_PKEY* pkey, SevEvidencePayload* sep, EvidenceRequestClient* erq);

#endif
