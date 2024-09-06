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

AttestationExtension* attester::getResult(){
    AttestationExtension* ax = new AttestationExtension();
    ax->evidence_payload = this->evidence_payload;
    ax->attestation_type = AMD_SEV_SNP;
    return ax;
}
