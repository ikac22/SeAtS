#include "attest/verifier.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

seats::verifier::verifier(CredentialKind cred_kind): 
    cred_kind(cred_kind){}

int seats::verifier::getResult(){
    return this->result;
}
