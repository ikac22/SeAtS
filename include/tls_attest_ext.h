#ifndef __TLS_ATTEST_EXT_H__
#define __TLS_ATTEST_EXT_H__

#include <stdint.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <sys/types.h>
#include "common.h"

extern bool attestation_extension_present;

typedef struct attestation_report_struct{
    uint32_t version;
    uint32_t guest_svn;
    uint64_t policy;
    uint8_t  family_id[16];
    uint8_t  image_id[16];
    uint32_t vmpl;
    uint32_t signature_algo;
    uint64_t current_tcb;
    uint64_t platform_info;
    uint32_t signig_flags;
    uint32_t reseved1;
    uint8_t  report_data[64];
    uint8_t  measurement[48];
    uint8_t  host_provided_data[32]; 
    uint8_t  id_key_digest[48];
    uint8_t  author_key_digest[48];
    uint8_t  report_id[32];
    uint8_t  report_id_ma[32];
    uint64_t reported_tcb; 
    uint8_t  reserved2[24];
    uint8_t  chip_id[64];
    uint64_t committed_tcb;
    uint8_t  current_build;
    uint8_t  current_minor;
    uint8_t  current_major;
    uint8_t  reserved3;
    uint8_t  committed_build;
    uint8_t  committed_minor;
    uint8_t  committed_major;
    uint8_t  reserved4;
    uint64_t launch_tcb;
    uint8_t  reserved5[168];
    uint8_t  signature[512];
} attestation_report;

// Testing the offsets
void print_attestation_report_member_offsets();

static int attestation_client_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg);

static void  attestation_client_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg);

static int  attestation_client_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg);


// SERVER CALLBACKS
static int attestation_server_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg);

static void  attestation_server_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg);

static int  attestation_server_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg);

static bool get_attestation(const unsigned char **out, size_t *outlen);
static bool verify_attestation(const unsigned char *in, size_t inlen);

int add_attestation_extension(SSL_CTX* ctx, bool is_server);

static int get_attestation_report(attestation_report* ar);

// For the purpose of checking the reading
static void print_attestation_report_hex(attestation_report* ar);

#endif
