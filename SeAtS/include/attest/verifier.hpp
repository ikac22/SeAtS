#ifndef __VERIFIER_H__
#define __VERIFIER_H__

#include "ssl_ext/evidence_ext_structs.hpp"
#include <cstdint>

namespace seats{

class verifier{
public:
    verifier(CredentialKind cred_kind);
	virtual void setData(uint8_t* data) = 0;

	virtual int verify() = 0;
	int getResult();	
	virtual ~verifier();
protected:
    int result;
    CredentialKind cred_kind;
};

}


#endif
