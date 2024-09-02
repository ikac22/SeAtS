#ifndef __CLIENT_CMD__
#define __CLIENT_CMD__

#include "attest/sev/tool_attest/cmd/common.hpp"
#include "attest/sev/tool_attest/sev_tool_attest_utils.hpp"
#include <cstdlib>

// CLIENT PATHS
#define CL_CALCULATE_MEASUREMENT_SCRIPT_PATH  "snp_measurement_command.sh"
#define CL_CALCULATED_ATTESTATION_FILE_PATH "prefered_measurement.txt"
#define CL_CERTS_PATH "certs"
#define CL_ATTESTATION_FILE_PATH "attestation.bin"
#define CL_CERT_BLOB_FILE_PATH "certs.blob"

// CLIENT COMMANDS
#define SNPGUEST_VERIFY_CERTS_CMD "snpguest verify certs"
#define SNPGUEST_VERIFY_ATTESTATION_CMD "snpguest verify attestation"
#define SNPHOST_EXPORT_CERTS_CMD "snphost export"

// COMMANDS TO RUN ON CLIENT
static const char *snpmeasure_cmd = CL_CALCULATE_MEASUREMENT_SCRIPT_PATH " > " CL_CALCULATED_ATTESTATION_FILE_PATH;
static const char *snpguest_certs_cmd = SNPGUEST_VERIFY_CERTS_CMD " " CL_CERTS_PATH " " SNPGUEST_LOG_PIPE;
static const char *snpguest_attestation_cmd = SNPGUEST_VERIFY_ATTESTATION_CMD " " CL_CERTS_PATH " " CL_ATTESTATION_FILE_PATH " " SNPGUEST_LOG_PIPE; 
static const char *snphost_export_cmd = SNPHOST_EXPORT_CERTS_CMD " pem " CL_CERT_BLOB_FILE_PATH " " CL_CERTS_PATH " " SNPHOST_LOG_PIPE; 
static const char *print_attestation_cmd = "xxd " CL_ATTESTATION_FILE_PATH;

int verify_sev_snp_certs();
int verify_measurement(char* measurement);
int verify_attestation_signature();
int save_attestation(attestation_report_t *ar);
int save_certs(const unsigned char* certs_blob, size_t length);

#endif
