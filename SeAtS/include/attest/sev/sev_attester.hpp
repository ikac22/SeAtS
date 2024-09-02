#ifndef __SEV_ATTESTER_H__
#define __SEV_ATTESTER_H__

#include "attest/attester.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdint>

namespace seats{

class sev_attester: public attester{
public:
	sev_attester(CredentialKind cred_kind);
    void setData(uint8_t *data) override; 
	virtual ~sev_attester();
protected:
    uint64_t nonce;
};

}

#endif
