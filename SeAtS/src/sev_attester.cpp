#include "attest/sev/sev_attester.hpp"
#include "attest/attester.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdint>

seats::sev_attester::sev_attester(CredentialKind kind): 
    seats::attester(kind), nonce(0){}

void seats::sev_attester::setData(uint8_t* data){
    this->nonce = *(uint64_t*)data;
}
