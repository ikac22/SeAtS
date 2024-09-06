
#ifndef __MOCK_SEV_ATTESTER_H__
#define __MOCK_SEV_ATTESTER_H__

#include "attest/sev/sev_attester.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include <cstdint>
#include <openssl/crypto.h>


namespace seats{

class mock_sev_attester: public sev_attester{
public:
    mock_sev_attester();
	~mock_sev_attester() = default;
	// virtual void set_data(uint8_t* data) override;
	virtual int attest() override;
};

}

#endif 


