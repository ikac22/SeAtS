#ifndef __sev_tool_verifier_h__
#define __sev_tool_verifier_h__

#include "attest/sev/sev_verifier.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

namespace seats{

class sev_tool_verifier: sev_verifier{
public:
    sev_tool_verifier();
	virtual ~sev_tool_verifier();
	void set_data(uint8_t* data) override;
	int verify(EVP_PKEY* pkey) override;
    

protected:
    int result;
    CredentialKind cred_kind;
};

}

#endif
