
#ifndef __ATTESTER_H__
#define __ATTESTER_H__

#include <cstdint>
#include <openssl/crypto.h>

#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

namespace seats{

class attester{
public:
    attester();
	virtual ~attester();
    virtual void set_cred_kind(CredentialKind cred_kind);
	virtual void set_data(uint8_t* data) = 0;
	virtual int attest() = 0;
	AttestationExtension* getResult();  
    virtual int configure_ssl_ctx(SSL_CTX* ctx) = 0;
protected:
    EvidencePayload* evidence_payload; 
    CredentialKind cred_kind;
};

}


#endif
