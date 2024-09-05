#include "attest/sev/sev_verifier.hpp"
#include "attest/sev/sev_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

#include <cstdint>

seats::sev_verifier::sev_verifier(): sep(NULL){}

seats::sev_verifier::~sev_verifier(){ delete sep; }

void seats::sev_verifier::set_data(uint8_t* data){
    SevEvidencePayload* sep = new SevEvidencePayload();  
    sep->deserialize((const unsigned char*)data);
    this->sep = sep;
}
