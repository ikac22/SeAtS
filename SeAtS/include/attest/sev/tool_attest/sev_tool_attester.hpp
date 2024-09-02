#ifndef __SEV_TOOL_ATTESTER__
#define __SEV_TOOL_ATTESTER__

#include "attest/sev/sev_attester.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdint>

namespace seats{

class sev_tool_attester:public sev_attester{
public:
    sev_tool_attester(CredentialKind cred_kind);
	virtual void setData(uint8_t* data);

	virtual int attest();
	const EvidencePayload* getResult();
	virtual ~sev_tool_attester();
};

}

#endif
