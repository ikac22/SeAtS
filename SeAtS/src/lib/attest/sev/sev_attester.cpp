#include "attest/sev/sev_structs.hpp"
#include "seats/seats_types.hpp"
#include "ssl_ext/evidence_ext_structs.hpp"
#include "attest/sev/sev_attester.hpp"

#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

using namespace seats;

EVP_PKEY* sev_attester::pkey = NULL;

sev_attester::sev_attester(): attester::attester(), erq(NULL), kat(NULL), katlen(0){
    if(!pkey) generate_and_save_cert();
}
// TODO IMPLEMENT DESTRUctor

int seats::sev_attester::configure_ssl_ctx(SSL_CTX*){ return 0; }

void seats::sev_attester::set_data(uint8_t* data){
    if(!evidence_payload){ 
        evidence_payload = new SevEvidencePayload();
        ((SevEvidencePayload*)evidence_payload)->pkey = pkey;
    }
    SevEvidencePayload* sep = (SevEvidencePayload*)evidence_payload;

    if(kat) delete []kat;
    if(sep->sig) delete [](sep->sig); 

    erq = new EvidenceRequestClient();
    size_t len = erq->deserialize((const unsigned char*) data);
    if(digest_and_sign(pkey, (char*)data, len, &(sep->sig), &(sep->siglen))){
        perror("Failed to generate signature of sentdata");
        return;
    }

    if(get_sha256_digest(sig, siglen, &kat, &katlen)){ 
        perror("Failed to generate digest of the signature");
        return;
    } 
}

void sev_attester::generate_and_save_cert(){ 
    FILE * f = NULL;
    X509 *x509 = NULL;
    X509_NAME *name = NULL;
    seats_status result = seats_status::OK;

    pkey = NULL;

    pkey = EVP_RSA_gen(4096);
    if (!pkey){
        perror("Error while generating private key");
        result = seats_status::UNABLE_TO_GENERATE_PRIVATE_KEY;
        goto end_generate_and_save_certificate;
    }
     
    x509 = X509_new();
    if(!x509){
        perror("Error while creating x509 struct.");
        result = seats_status::UNABLE_TO_CREATE_X509;
        goto end_generate_and_save_certificate;
    }

    if(!ASN1_INTEGER_set(X509_get_serialNumber(x509), 1)){ 
        perror("Error while creating x509 struct.");
        result = seats_status::FAILED_TO_SET_SERIAL_NUMBER;
        goto end_generate_and_save_certificate;
    }
    if(!X509_gmtime_adj(X509_get_notBefore(x509), 0)){
        perror("Error while setting begin time of cert.");
        result = seats_status::FAILED_TO_SET_X509_BEGIN;
        goto end_generate_and_save_certificate;
    }
    
    if(!X509_gmtime_adj(X509_get_notAfter(x509), 31536000L)){
        perror("Error while setting end time of cert.");
        result = seats_status::FAILED_TO_SET_X509_END;
        goto end_generate_and_save_certificate;
    }
    
    if(!X509_set_pubkey(x509, pkey)){
        perror("Error while setting x509 cert public key.");
        result = seats_status::FAILED_TO_SET_X509_PUBKEY;
        goto end_generate_and_save_certificate;
    }
    
    name = X509_get_subject_name(x509);

    if(!name){ 
        perror("Error while getting x509 name.");
        result = seats_status::FAILED_TO_GET_X509_NAME;
        goto end_generate_and_save_certificate;
    }
    
    if(!X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                               (unsigned char *)"CA", -1, -1, 0)){ 
        perror("Error while setting x509 name 1.");
        result = seats_status::FAILED_TO_SET_X509_NAME_1;
        goto end_generate_and_save_certificate;
    }

    if(!X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                               (unsigned char *)"MyCompany Inc.", -1, -1, 0)){
        perror("Error while setting x509 name 2.");
        result = seats_status::FAILED_TO_SET_X509_NAME_2;
        goto end_generate_and_save_certificate;
    }
    
    if(!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"localhost", -1, -1, 0)){
        perror("Error while setting x509 name 3.");
        result = seats_status::FAILED_TO_SET_X509_NAME_3;
        goto end_generate_and_save_certificate;
    }
    
    if(!X509_set_issuer_name(x509, name)){
        perror("Error while setting x509 name 4.");
        result = seats_status::FAILED_TO_SET_X509_NAME_4;
        goto end_generate_and_save_certificate;
    }
    
    if(!X509_sign(x509, pkey, EVP_sha1())){ 
        perror("Error while signing x509 cert.");
        result = seats_status::FAILED_TO_SIGN_X509;
        goto end_generate_and_save_certificate;
    }

    f = fopen(SEATS_KEY_FILE_PATH, "wb");
    if(!f){ 
        perror("Error opening key file.");
        result = seats_status::FAILED_TO_SIGN_X509;
        goto end_generate_and_save_certificate;
    }

    
    if (!PEM_write_PrivateKey(
            f,                  /* write the key to the file we've opened */
            (const EVP_PKEY*)pkey,               /* our key from earlier */
            NULL, /* default cipher for encrypting the key on disk */
            NULL,       /* passphrase required for decrypting the key on disk */
            10,                 /* length of the passphrase string */
            NULL,               /* callback for requesting a password */
            NULL                /* data to pass to the callback */
    )){
        perror("Error writing key to file.");
        result = seats_status::FAILED_TO_SIGN_X509;
        goto end_generate_and_save_certificate;
    }
    fclose(f);

    // TODO: Add possibility to chose cert file path or to generate unique filepath
    f = fopen(SEATS_CERT_FILE_PATH, "wb");

    if(!f){ 
        perror("Error opening cert file.");
        result = seats_status::FAILED_TO_SIGN_X509;
        goto end_generate_and_save_certificate;
    }

    if (!PEM_write_X509(f, x509)){ 
        perror("Error writing cert to file.");
        result = seats_status::FAILED_TO_SIGN_X509;
        goto end_generate_and_save_certificate;
    }

end_generate_and_save_certificate: 

    if(f) fclose(f);
    if(pkey && result) { 
        EVP_PKEY_free(pkey); 
        pkey = NULL; 
    }
    if(x509) X509_free(x509);
    printf("CERTIFICATE SUCCESSFULLY CREATED!");
}
