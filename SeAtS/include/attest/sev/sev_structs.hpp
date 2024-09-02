#ifndef __SEV_STRUCTS_H__
#define __SEV_STRUCTS_H__

#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include <cstdint>

struct SevEvidencePayload: EvidencePayload{
    attestation_report_t attestation_report;
    uint64_t amd_cert_data_len;
    char* amd_cert_data;
    int serialize(const unsigned char**) override;
    int deserialize(const unsigned char*) override;
};

#endif
