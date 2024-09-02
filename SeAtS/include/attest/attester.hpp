
#ifndef __VERIFIER_H__
#define __VERIFIER_H__

#include <cstdint>

#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include "ssl_ext/client_ext_cbs.hpp"
#include "ssl_ext/server_ext_cbs.hpp"

namespace seats{

class attester{
public:
    attester(CredentialKind cred_kind);
	virtual void setData(uint8_t* data) = 0;

	virtual int attest() = 0;
	const EvidencePayload* getResult();
	virtual ~attester();

 
protected:
    EvidencePayload* evidence_payload; 
    CredentialKind cred_kind;


};

}


#endif
