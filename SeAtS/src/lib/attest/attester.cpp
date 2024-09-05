#include "attest/attester.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

using namespace seats;

attester::~attester(){
    if(evidence_payload) delete evidence_payload;
}

void attester::set_cred_kind(CredentialKind cred_kind){
    this->cred_kind = cred_kind;
}

const EvidencePayload* attester::getResult(){
    return this->evidence_payload;
}
