#include "attest/verifier.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

using namespace seats;

void verifier::set_erq(EvidenceRequestClient* erq){
    this->erq = erq; 
}

int verifier::getResult(){
    return this->result;
}


