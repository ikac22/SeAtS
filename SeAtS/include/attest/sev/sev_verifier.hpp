#ifndef __SEV_VERIFIER_H__
#define __SEV_VERIFIER_H__

#include "attest/sev/sev_structs.hpp"
#include "attest/verifier.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"

namespace seats{

class sev_verifier: public verifier{
public:
	sev_verifier(CredentialKind cred_kind);
    void setData(uint8_t *data) override;
	~sev_verifier();
protected:
    SevEvidencePayload* sep;
};

}
#endif
