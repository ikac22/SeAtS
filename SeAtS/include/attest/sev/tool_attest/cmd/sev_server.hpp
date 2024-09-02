#ifndef __SERVER_CMD__
#define __SERVER_CMD__

#include "attest/sev/tool_attest/cmd/common.hpp"
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
static const char *snpguest_report_cmd = SNPGUEST_REPORT_CMD " " SR_ATTESTATION_FILE_PATH " " SR_REPORT_DATA_FILE_PATH " " SNPGUEST_LOG_PIPE;
static const char *snphost_import_cmd = SNPHOST_IMPORT_CERTS_CMD " " SR_CERTS_PATH " " SR_CERT_BLOB_FILE_PATH " " SNPHOST_LOG_PIPE;
static const char *snpguest_certificates_cmd = SNPGUEST_CERTIFICATES_CMD " pem " SR_CERTS_PATH " " SNPGUEST_LOG_PIPE;

// INDICATOR IF NEEDED TO FETCH THE CERTS
static bool CERTS_LOADED = false;

int load_cert_blob(char **cert_blob_buff, size_t* bufflen);
int get_attestation_report(attestation_report_t* ar);

#endif
