#include"attest/sev/sev_structs.hpp"
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rsa.h>

int get_sha256_digest(char* m, size_t mlen, char** dig, unsigned int* diglen){

    EVP_MD_CTX *mdctx;
    unsigned char md_value[EVP_MAX_MD_SIZE];

    mdctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex2(mdctx, EVP_sha256(), NULL)) {
        perror("Message digest initialization failed.\n");
        EVP_MD_CTX_free(mdctx);
        return 2;
    }

    if (!EVP_DigestUpdate(mdctx, m, mlen)) {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        return 3;
    }

    if (!EVP_DigestFinal_ex(mdctx, md_value, diglen)) {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdctx);
        return 4;
    }

    *dig = new char[*diglen];
    memcpy(dig, md_value, *diglen);

    EVP_MD_CTX_free(mdctx);
    return 0; 
}

int digest_and_sign(EVP_PKEY* pkey, char* m, size_t mlen, char** sig, size_t* siglen){ 
    char* md;
    unsigned int mdlen;

    if(get_sha256_digest(m, mlen, &md, &mdlen)){
        perror("Failed to get digest of the message!");
        return 6;
    } 

    EVP_PKEY_CTX *ctx;

    // GENERATE SIGN FOR THE ATTESTATION
    ctx = EVP_PKEY_CTX_new(pkey, NULL /* no engine */);
    
     
    if (ctx == NULL){
        perror("Signing context failed to initialize.");
        return 1;
    }
 
    if (EVP_PKEY_sign_init(ctx) <= 0){
        perror("Failed signing initialization.");
        return 2;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){
        perror("Failed rsa padding setting!");
        return 3;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0){
        perror("Failed signature algorithm setting!");
        return 4;
    }
    
    /* Determine sig buffer length */
    if (EVP_PKEY_sign(ctx, NULL, siglen, (const unsigned char*)m, mlen) <= 0){
        perror("Getting length did not work!\n");
        return 5;
    }
    
    *sig = new char[*siglen];
    
    if (sig == NULL){
        perror("");
        return 4;
    }
    
    if (EVP_PKEY_sign(ctx, (unsigned char*)*sig, siglen, (const unsigned char*)md, (size_t)mdlen) <= 0){
        perror("Failed signing message.");
        delete []sig;
        return 5;
    }

    return 0;
}

int verify_signature(EVP_PKEY* pkey, char* sig, size_t siglen, char* orig, size_t origlen){
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new(pkey, NULL /* no engine */);
    if (ctx == NULL){
        perror("FAILED while creating PKEY CTX!");
        return 1;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0){ 
        perror("FAILED while verify init");
        EVP_PKEY_CTX_free(ctx);
        return 2;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0){
        perror("FAILED while adding rsa pkcs padding");
        EVP_PKEY_CTX_free(ctx);
        return 3;
    }
    
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0){
        perror("Failed while setting signature algo!");
        EVP_PKEY_CTX_free(ctx);
        return 4;
    }
    
    /* Perform operation */
    if(!EVP_PKEY_verify(ctx, (const unsigned char*)sig, siglen, (const unsigned char*)orig, origlen)){
        perror("Failed to verify signature!");
        EVP_PKEY_CTX_free(ctx);
        return 5;
    }

    return 0;
}

bool verify_kat(EVP_PKEY* pkey, SevEvidencePayload* sep, EvidenceRequestClient* erq){
    const unsigned char* m;
    size_t mlen = erq->serialize(&m);

    char* dig;
    unsigned int diglen;

    
    if(get_sha256_digest((char*)m, mlen, &dig, &diglen)){
        perror("Failed to generate digest of the client hello extension message");
        delete []m;
        return false;
    }
    delete []m;

    if(verify_signature(pkey, sep->sig, sep->siglen, dig, diglen)){
        perror("Failed to verify signature of the given TIK!");
        delete []dig;
        return false;
    }
    delete []dig;

    m = (const unsigned char*)new char[32];
    memcpy((void*)m, sep->attestation_report.report_data, 32);
    if(get_sha256_digest(sep->sig, sep->siglen, &dig, &diglen)){
        perror("Unable to generate hash from signature!");
        delete []m;
        return false;
    }

    if(memcmp(m, dig, diglen)){
        perror("Hash from attestation report dont match calculated hash of signature!");
        delete []m;
        delete []dig;
        return false; 
    }
    delete []m;
    delete []dig;

    return true;
}

int SevEvidencePayload::serialize(const unsigned char** buff){
    int len = sizeof(attestation_report_t) 
        + sizeof(uint64_t) 
        + amd_cert_data_len 
        + sizeof(siglen)
        + siglen;   

    *buff = (const unsigned char*)new char[len];

    char* tmp = (char*)*buff;

    memcpy(tmp, (const void*)&attestation_report, sizeof(attestation_report_t));
    tmp += sizeof(attestation_report_t);
    
    memcpy(tmp, (const void*)&amd_cert_data_len, sizeof(amd_cert_data_len));
    tmp += sizeof(amd_cert_data_len);

    memcpy(tmp, (const void*)&amd_cert_data, amd_cert_data_len);
    tmp += amd_cert_data_len;
 
    memcpy(tmp, (const void*)&siglen, sizeof(siglen));
    tmp += sizeof(siglen);

    memcpy(tmp, (const void*)&sig, siglen);
    tmp += siglen;

    return len; 
}

int SevEvidencePayload::deserialize(const unsigned char*){
    return 0;
}
