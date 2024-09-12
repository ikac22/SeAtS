#ifndef __ATTESTATIN__STRUCTS_H__ 
#define __ATTESTATIN__STRUCTS_H__

#include "ssl_ext/evidence_ext_structs.hpp"

enum AttestationType {
    AMD_SEV,
    AMD_SEV_SNP,
    INTEL_TDX
};

struct EvidencePayload {
    virtual int serialize(const unsigned char**) = 0;
    virtual int deserialize(const unsigned char *) = 0;
    virtual ~EvidencePayload() = default;
};

// Used in extension of certificate message 
struct AttestationExtension{
    EvidenceRequestServer erq;
    AttestationType attestation_type;
    EvidencePayload* evidence_payload;
    int serialize(const unsigned char**);
    int deserialize(const unsigned char*);
};


#endif
