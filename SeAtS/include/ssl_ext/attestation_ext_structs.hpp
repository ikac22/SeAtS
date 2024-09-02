#ifndef __ATTESTATIN__STRUCTS_H__ 
#define __ATTESTATIN__STRUCTS_H__

enum AttestationType {
    AMD_SEV,
    AMD_SEV_SNP,
    INTEL_TDX
};

// Used in extension of certificate message 
struct EvidencePayload {
    virtual int serialize(const unsigned char**) = 0;
    virtual int deserialize(const unsigned char *) = 0;
};

struct AttestationExtension{
    AttestationType attestation_type;
    EvidencePayload* evidence_payload;
    int serialize(const unsigned char**);
    int deserialize(const unsigned char*);
};


#endif
