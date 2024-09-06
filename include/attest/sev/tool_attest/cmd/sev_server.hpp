#ifndef __SERVER_CMD__
#define __SERVER_CMD__

#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include <cstddef>

// SERVER PATHS 
#define SR_ATTESTATION_FILE_PATH "/dev/shm/attestation.bin"
#define SR_REPORT_DATA_FILE_PATH "/dev/shm/random.bin"
#define SR_CERTS_PATH "/dev/shm/certs"
#define SR_CERT_BLOB_FILE_PATH "/dev/shm/certs.blob"

// SERVER COMMANDS
#define SNPGUEST_REPORT_CMD "snpguest report "
#define SNPGUEST_CERTIFICATES_CMD "snpguest certificates"
#define SNPHOST_IMPORT_CERTS_CMD "snphost import"

// COMMANDS TO RUN ON SERVER
extern const char *snpguest_report_cmd;
extern const char *snphost_import_cmd;
extern const char *snpguest_certificates_cmd;

// INDICATOR IF NEEDED TO FETCH THE CERTS
extern bool CERTS_LOADED;

int load_cert_blob(char **cert_blob_buff, size_t* bufflen);
int save_report_data_file(char* buff64);
int get_attestation_report(attestation_report_t* ar);

#endif
