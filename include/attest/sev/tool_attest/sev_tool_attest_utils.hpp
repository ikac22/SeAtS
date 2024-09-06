#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <sys/types.h>

struct attestation_report_t{
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
};


// For debugging
void print_attestation_report_hex(attestation_report_t* ar);
void print_attestation_report_member_offsets();

#endif // __UTILS_H__
