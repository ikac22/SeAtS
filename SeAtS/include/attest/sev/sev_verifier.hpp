#ifndef __SEV_VERIFIER_H__
#define __SEV_VERIFIER_H__

#include "attest/sev/sev_structs.hpp"
#include "attest/verifier.hpp"

namespace seats{

class sev_verifier: public verifier{
public:
	sev_verifier();
	~sev_verifier();
    void set_data(uint8_t *data) override;

protected:
    SevEvidencePayload* sep;
};

}
#endif
