#ifndef __MOCK_SEV_VERIFIER_H__
#define __MOCK_SEV_VERIFIER_H__

#include "attest/sev/sev_structs.hpp"
#include "attest/sev/sev_verifier.hpp"

namespace seats{

class mock_sev_verifier: public sev_verifier{
public:
    mock_sev_verifier();
	void set_data(uint8_t* data) override;
	int verify(EVP_PKEY* pkey) override;
protected:
    int result;
    CredentialKind cred_kind;
};

}
#endif
