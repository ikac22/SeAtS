#include "tls_attest_ext.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include<string.h>

#define ATTESTATION_FILE_PATH "/dev/shm/attestation.bin"
#define REPORT_DATA_FILE_PATH "/dev/shm/random.bin"
#define CMD_STRING_ADDITIONAL_LENGTH 13

static const char *snpguest_path=NULL;
static bool DEBUG = 0;

static bool verify_attestation(const unsigned char* in, size_t inlen){

    attestation_report* t = (attestation_report*)in;
    
    print_attestation_report_hex(t);

    return true;
}

static bool get_attestation(const unsigned char **out, size_t *outlen){

    *out = malloc(sizeof(attestation_report));

    get_attestation_report((attestation_report*)*out);
        
    print_attestation_report_hex((attestation_report*)*out);

    *outlen = sizeof(attestation_report);

    return true;
    
}


static int attestation_client_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg)
{
    //*out = "CLIENT MESSAGE: Hello there handsome ;)\0";
    switch (ext_type) {
        case 65280:
            printf(" - attestation_client_ext_add_cb from client called!\n");
            break;
        default:
            break;
    }
    return 1;
}

static void  attestation_client_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg)
{
    printf(" - attestation_client_ext_free_cb from client called!\n");
}

static int  attestation_client_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    printf(" - attestation_client_ext_parse_cb from client called!\n");
    verify_attestation(in,inlen);
    printf("=== ATTESTATION EXTENXION (%lu): Message from server: %s ===\n", sizeof(attestation_report), in);
    return 1;
}



// SERVER CALLBACKS
static int attestation_server_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg)
{
    switch (ext_type) {
        case 65280:
            printf(" - attestation_server_ext_add_cb from server called!\n");
            get_attestation(out, outlen);
            printf("=== ATTESTATION EXTENXION: Sending message: %s ===\n", *out);
            break;
        default:
            break;
    }
    return 1;
}

static void  attestation_server_ext_free_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg)
{
    printf(" - attestation_server_ext_free_cb from server called\n");
}

static int  attestation_server_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    printf(" - attestation_server_ext_parse_cb from server called!\n");
    return 1;
}

int add_attestation_extension(SSL_CTX *ctx, bool is_server, const char* snpguest_path_t){
    unsigned int id = 65280; 
    unsigned int flags = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_SERVER_HELLO;

    snpguest_path = snpguest_path_t;
    if (is_server){
        return SSL_CTX_add_custom_ext(ctx, 
                                        id,
                                        flags,
                                        attestation_server_ext_add_cb, 
                                        attestation_server_ext_free_cb, 
                                        NULL, 
                                        attestation_server_ext_parse_cb, 
                                        NULL);
    } 
    else
    {
        return SSL_CTX_add_custom_ext(ctx, 
                                        id,
                                        flags,
                                        attestation_client_ext_add_cb, 
                                        attestation_client_ext_free_cb, 
                                        NULL, 
                                        attestation_client_ext_parse_cb, 
                                        NULL);
    }
}


static int get_attestation_report(attestation_report* ar){
    uint8_t cmd_len = strlen(snpguest_path) + 1 
                      + sizeof(ATTESTATION_FILE_PATH) 
                      + sizeof(REPORT_DATA_FILE_PATH) 
                      + CMD_STRING_ADDITIONAL_LENGTH; 

    char *cmd=malloc(cmd_len);

    FILE *att_file;

    sprintf(cmd, "%s report %s %s --random\n", snpguest_path, ATTESTATION_FILE_PATH, REPORT_DATA_FILE_PATH);
    
    system(cmd);

    att_file = fopen(ATTESTATION_FILE_PATH, "rb");

    fread((char*)ar, sizeof(attestation_report), 1, att_file);

    fclose(att_file);

    if(DEBUG){
        printf("----------------------- ATTESTATION FILE -----------------------");
        sprintf(cmd, "xxd %s", ATTESTATION_FILE_PATH);
        system(cmd);
    }

    free(cmd);

    return 1;
}

//// FOR DEBUG PURPOSES

#define print_char_member(obj, field)   printf("%-30s: %02x\n", #field, obj->field)
#define print_int_member(obj, field)    printf("%-30s: %08x\n", #field, obj->field)
#define print_long_member(obj, field)   printf("%-30s: %016lx\n", #field, obj->field)
#define print_string_member(obj, field, len) printf("%-30s: ", #field); print_string_hex(obj->field, len); printf("\n")

void print_string_hex(const unsigned char* s, int len){
    for(int i = 0; i < len; i++)
        printf("%02x", (unsigned int) *s++);
}

// For the purpose of checking the reading
static void print_attestation_report_hex(attestation_report* ar){
    printf("----------------------- READ DATA USING STRUCT -----------------------");
    print_int_member(ar, version);
    print_int_member(ar, guest_svn);
    print_long_member(ar, policy);
    print_string_member(ar, family_id, 16);
    print_string_member(ar, image_id, 16);
    print_int_member(ar, vmpl);
    print_int_member(ar, signature_algo);
    print_long_member(ar, current_tcb);
    print_long_member(ar, platform_info);
    print_int_member(ar, signig_flags);
    print_int_member(ar, reseved1);
    print_string_member(ar, report_data, 64);
    print_string_member(ar, measurement, 48);
    print_string_member(ar, host_provided_data, 32);
    print_string_member(ar, id_key_digest, 48);
    print_string_member(ar, author_key_digest, 48);
    print_string_member(ar, report_id, 32);
    print_string_member(ar, report_id_ma, 32);
    print_long_member(ar, reported_tcb); 
    print_string_member(ar, reserved2, 24);
    print_string_member(ar, chip_id, 64);
    print_long_member(ar, committed_tcb);
    print_char_member(ar, current_build);
    print_char_member(ar, current_minor);
    print_char_member(ar, current_major);
    print_char_member(ar, reserved3);
    print_char_member(ar, committed_build);
    print_char_member(ar, committed_minor);
    print_char_member(ar, committed_major);
    print_char_member(ar, reserved4);
    print_long_member(ar, launch_tcb);
    print_string_member(ar, reserved5, 168);
    print_string_member(ar, signature, 512);
}

void print_attestation_report_member_offsets(){
    unsigned long offsets[] = {
        offsetof(attestation_report, version),
        offsetof(attestation_report, guest_svn),
        offsetof(attestation_report, policy),
        offsetof(attestation_report,  family_id),
        offsetof(attestation_report,  image_id),
        offsetof(attestation_report, vmpl),
        offsetof(attestation_report, signature_algo),
        offsetof(attestation_report, current_tcb),
        offsetof(attestation_report, platform_info),
        offsetof(attestation_report, signig_flags),
        offsetof(attestation_report, reseved1),
        offsetof(attestation_report,  report_data),
        offsetof(attestation_report,  measurement),
        offsetof(attestation_report,  host_provided_data), 
        offsetof(attestation_report,  id_key_digest),
        offsetof(attestation_report,  author_key_digest),
        offsetof(attestation_report,  report_id),
        offsetof(attestation_report,  report_id_ma),
        offsetof(attestation_report, reported_tcb), 
        offsetof(attestation_report,  reserved2),
        offsetof(attestation_report, committed_tcb),
        offsetof(attestation_report,  current_build),
        offsetof(attestation_report,  current_minor),
        offsetof(attestation_report,  current_major),
        offsetof(attestation_report,  reserved3),
        offsetof(attestation_report,  committed_build),
        offsetof(attestation_report,  committed_minor),
        offsetof(attestation_report,  committed_major),
        offsetof(attestation_report,  reserved4),
        offsetof(attestation_report, launch_tcb),
        offsetof(attestation_report,  reserved5),
        offsetof(attestation_report,  signature)
    }; 

    const char* names[] = {
        "version",
        "guest_svn",
        "policy",
        "family_id",
        "image_id",
        "vmpl",
        "signature_algo",
        "current_tcb",
        "platform_info",
        "signig_flags",
        "reseved1",
        "report_data",
        "measurement",
        "host_provided_data", 
        "id_key_digest",
        "author_key_digest",
        "report_id",
        "report_id_ma",
        "reported_tcb", 
        "reserved2",
        "committed_tcb",
        "current_build",
        "current_minor",
        "current_major",
        "reserved3",
        "committed_build",
        "committed_minor",
        "committed_major",
        "reserved4",
        "launch_tcb",
        "reserved5",
        "signature"
    }; 

    for(int i = 0; i < 32; i++){
       printf("%s: %lx\n", names[i], offsets[i]);  
    }
}
