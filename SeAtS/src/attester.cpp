#include "attest/attester.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"

seats::attester::attester(CredentialKind cred_kind): 
    cred_kind(cred_kind){}

const EvidencePayload* seats::attester::getResult(){
    return this->evidence_payload;
}
