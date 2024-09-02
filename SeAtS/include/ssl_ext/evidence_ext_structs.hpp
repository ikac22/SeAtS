#ifndef __EVIDENCE_STRUCTS_H__
#define __EVIDENCE_STRUCTS_H__

#include <cstdint>
#include <vector>

// EVIDENCE REQUEST/PROPOSE
enum CredentialKind {
    ATTESTATION,
    CERT_ATTESTATION
};

enum TypeEncoding {
    CONTENT_FORMAT,
    MEDIA_TYPE,
};

enum ContentFormat{
    BINARY_FORMAT
};

struct EvidenceType{
    CredentialKind credential_kind;
    TypeEncoding type_encoding;
    union PayloadUnion{
        ContentFormat content_format;
        char* media_type;
    } supported_content;

    int serialize(const unsigned char**);
    int deserialize(char*); 
};

struct EvidenceRequestClient{
    std::vector<EvidenceType> supported_evidence_types;
    int64_t nonce;

    int serialize(const unsigned char**);
    int deserialize(const unsigned char *);
};

struct EvidenceRequestServer{
    EvidenceType selected_evidence_types;
};

#endif
