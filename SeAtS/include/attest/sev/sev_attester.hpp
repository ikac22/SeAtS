#ifndef __SEV_ATTESTER_H__
#define __SEV_ATTESTER_H__

#include "attest/attester.hpp"
#include "ssl_ext/attestation_ext_structs.hpp"
#include <cstdint>
#include <openssl/crypto.h>

namespace seats{

class sev_attester: public attester{
public:
	sev_attester();
	~sev_attester() = default;
    int configure_ssl_ctx(SSL_CTX* ctx) override;
    void set_data(uint8_t *data) override; 
protected: 
    static void generate_and_save_cert();
    EvidenceRequestClient* erq;

    // KEY ATTESTATION TOKEN
    char* kat;
    uint katlen;

    // SIGNATURE
    char* sig;
    size_t siglen;
private:
    static EVP_PKEY* pkey;
};

}

#endif
