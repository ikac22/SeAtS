#ifndef __SEV_TOOL_ATTESTER__
#define __SEV_TOOL_ATTESTER__

#include "attest/sev/sev_attester.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

namespace seats{

class sev_tool_attester:public sev_attester{
public:
    sev_tool_attester();
	~sev_tool_attester() = default;
	// virtual void set_data(uint8_t* data) override;
	virtual int attest() override;
};

}

#endif
