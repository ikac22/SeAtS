#include "tls_attest_ext.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SR_ATTESTATION_FILE_PATH "/dev/shm/attestation.bin"
#define SR_REPORT_DATA_FILE_PATH "/dev/shm/random.bin"
#define SR_CERTS_PATH "/dev/shm/certs"
#define SR_CERT_BLOB_FILE_PATH "/dev/shm/certs.blob"

#define CL_CALCULATE_MEASUREMENT_SCRIPT_PATH  "snp_measurement_command.sh"
#define CL_CALCULATED_ATTESTATION_FILE_PATH "prefered_measurement.txt"
#define CL_CERTS_PATH "certs"
#define CL_ATTESTATION_FILE_PATH "attestation.bin"
#define CL_CERT_BLOB_FILE_PATH "certs.blob"

#define SNPGUEST_REPORT_CMD "snpguest report "
#define SNPGUEST_VERIFY_CERTS_CMD "snpguest verify certs"
#define SNPGUEST_VERIFY_ATTESTATION_CMD "snpguest verify attestation"
#define SNPGUEST_CERTIFICATES_CMD "snpguest certificates"
#define SNPHOST_EXPORT_CERTS_CMD "snphost export"
#define SNPHOST_IMPORT_CERTS_CMD "snphost import"


#define CMD_STRING_ADDITIONAL_LENGTH 13

// COMMANDS TO RUN ON SERVER
static const char *snpguest_report_cmd = SNPGUEST_REPORT_CMD " " SR_ATTESTATION_FILE_PATH " " SR_REPORT_DATA_FILE_PATH " --random";
static const char *snphost_import_cmd = SNPHOST_IMPORT_CERTS_CMD " " SR_CERT_BLOB_FILE_PATH;
static const char *snpguest_certificates_cmd = SNPGUEST_CERTIFICATES_CMD " " SR_CERTS_PATH;
static bool CERTS_LOADED = false;

// COMMANDS TO RUN ON CLIENT
static const char *snpmeasure_cmd = CL_CALCULATE_MEASUREMENT_SCRIPT_PATH " > " CL_CALCULATED_ATTESTATION_FILE_PATH;
static const char *snpguest_certs_cmd = SNPGUEST_VERIFY_CERTS_CMD " " CL_CERTS_PATH;
static const char *snpguest_attestation_cmd = SNPGUEST_VERIFY_ATTESTATION_CMD " " CL_CERTS_PATH " " CL_ATTESTATION_FILE_PATH; 
static const char *snphost_export_cmd = SNPHOST_EXPORT_CERTS_CMD " " CL_CERT_BLOB_FILE_PATH " " CL_CERTS_PATH; 

static bool DEBUG = 0;

bool attestation_extension_present = false;

static int verify_measurement(char* measurement){
    char calc_measurement[48];

    system(snpmeasure_cmd);
 
    FILE *measurement_file;

    measurement_file = fopen(CL_CALCULATED_ATTESTATION_FILE_PATH, "rb");

    fread((char*)calc_measurement, 48, 1, measurement_file);

    if (memcmp(calc_measurement, measurement, 48)){
        return false;
    }

    fclose(measurement_file);

    return true;
}

static int verify_sev_snp_certs(){ return !system(snpguest_certs_cmd); }

static int verify_attestation_signature() { return !system(snpguest_attestation_cmd); }

static int save_attestation(attestation_report *ar){
    FILE* att_file = fopen(CL_ATTESTATION_FILE_PATH, "wb");

    fwrite(ar, sizeof(attestation_report), 1, att_file);

    fclose(att_file);

    return 1;
}

static int save_cert_blob(const unsigned char* certs_blob, size_t length){
    FILE* cert_file = fopen(CL_CERT_BLOB_FILE_PATH, "wb");
    
    fwrite(certs_blob, length, 1, cert_file);

    fclose(cert_file);

    return 1;
}

static bool verify_attestation(const unsigned char* in, size_t inlen){
    attestation_report* ar = (attestation_report*)in;

    const unsigned char* cb = in + sizeof(attestation_report);
    size_t cb_size = inlen - sizeof(attestation_report);

    save_attestation(ar);

    save_cert_blob(cb, cb_size);     

    if (!verify_sev_snp_certs()){
        printf("PROVIDED CERTIFICATES INVALID!\n");
        return false;
    }

    if (!verify_attestation_signature()){
        printf("ATTESTATION SIGNATURE INVALID!\n");
        return false;
    } 

    if (!verify_measurement(ar->measurement)){
        printf("MEASUREMENT INVALID!\n");
        return false;
    }
    return true;
}

static int load_cert_blob(char **cert_blob_buff, size_t* bufflen){
    FILE *file;
	char *buffer;
	unsigned long fileLen;

	//Open file
	file = fopen(SR_CERT_BLOB_FILE_PATH, "rb");
	if (!file)
	{
		fprintf(stderr, "Unable to open file %s", SR_CERT_BLOB_FILE_PATH);
		return false;
	}
	
	//Get file length
	fseek(file, 0, SEEK_END);
	fileLen=ftell(file);
	fseek(file, 0, SEEK_SET);

	//Allocate memory
	buffer=(char *)malloc(fileLen+1);
	if (!buffer)
	{
		fprintf(stderr, "Memory error!");
                                fclose(file);
		return false;
	}

	//Read file contents into buffer
	fread(buffer, fileLen, 1, file);
	fclose(file);

    *bufflen=fileLen;
    *cert_blob_buff = buffer;
    
    return true; 
}

static int get_attestation_report(attestation_report* ar){
    FILE *att_file;
 
    system(snpguest_report_cmd);

    att_file = fopen(SR_ATTESTATION_FILE_PATH, "rb");

    fread((char*)ar, sizeof(attestation_report), 1, att_file);

    fclose(att_file);

    // if(DEBUG){
    //     printf("----------------------- ATTESTATION FILE -----------------------");
    //     sprintf(cmd, "xxd %s", SR_ATTESTATION_FILE_PATH);
    //     system(cmd);
    // }

    // free(cmd);

    return 1;
}

static bool get_attestation(const unsigned char **out, size_t *outlen){
    char *cert_blob_buff = NULL;
    size_t cert_blob_buff_len = 0;
    
    load_cert_blob(&cert_blob_buff, &cert_blob_buff_len);

    *out = malloc(sizeof(attestation_report) + cert_blob_buff_len);

    get_attestation_report((attestation_report*)*out); 

    memcpy((void*)(*out + sizeof(attestation_report)), cert_blob_buff, cert_blob_buff_len);
    
    *outlen = sizeof(attestation_report) + cert_blob_buff_len;

    return true; 
}


static int attestation_client_ext_add_cb(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx, int *al,
                                        void *add_arg)
{
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
    attestation_extension_present=true;
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

int add_attestation_extension(SSL_CTX *ctx, bool is_server){
    unsigned int id = 65280; 
    unsigned int flags = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_SERVER_HELLO;

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
