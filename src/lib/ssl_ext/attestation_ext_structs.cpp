#include "ssl_ext/attestation_ext_structs.hpp"
#include "attest/sev/sev_structs.hpp"
#include <cstring>

int AttestationExtension::serialize(const unsigned char** buff){
    int len = sizeof(AttestationType);
    int payload_len = 0;
    const unsigned char* tmp;
    const unsigned char* tmp_buff;

    len += payload_len = evidence_payload->serialize(&tmp);    
    tmp_buff = *buff = (const unsigned char*)new char[len]; 

    *(AttestationType*)tmp_buff = attestation_type;
    tmp_buff += sizeof(AttestationType);
    memcpy((void*)tmp_buff, tmp, payload_len);

    delete []tmp;
    return len;
}
int AttestationExtension::deserialize(const unsigned char* buff){
    const unsigned char* tmp = buff;
    attestation_type = *(AttestationType*)tmp;
    tmp += sizeof(AttestationType);

    switch (attestation_type) {
        case AMD_SEV_SNP: 
            evidence_payload = new SevEvidencePayload();
            tmp += evidence_payload->deserialize(tmp);
            break;
        default:
            evidence_payload = NULL; 
            break;
    }

    return 0;
}
