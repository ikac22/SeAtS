#include "attest/sev/sev_verifier.hpp"
#include "attest/sev/sev_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdint>

seats::sev_verifier::sev_verifier(CredentialKind kind): seats::verifier(kind), sep(NULL){}

void seats::sev_verifier::setData(uint8_t* data){
    SevEvidencePayload* sep = new SevEvidencePayload();  
    sep->deserialize((char*)data);
    this->sep = sep;
}
