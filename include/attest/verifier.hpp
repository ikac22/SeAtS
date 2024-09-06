#ifndef __VERIFIER_H__
#define __VERIFIER_H__

#include "ssl_ext/evidence_ext_structs.hpp"

#include <cstdint>
#include <openssl/crypto.h>

namespace seats{

class verifier{
public:
    verifier() = default;
	virtual ~verifier() = default;
    virtual void set_erq(EvidenceRequestClient* erq);
	virtual void set_data(uint8_t* data) = 0;
	virtual int verify(EVP_PKEY*) = 0;
	int getResult();	

protected:
    int result;
    EvidenceRequestClient* erq;
};

}


#endif
