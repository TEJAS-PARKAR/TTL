/**
 * diag_service.c - Diagnostic Service Handler (UDS)
 *
 * Handles UDS diagnostic requests for ECU.
 * Part of SecureCodeGuard synthetic test dataset.
 * Case: TC-007, TC-008
 *
 * INJECTED DEFECTS:
 * - TC-007: Unsafe input handling via sprintf (line ~47)
 * - TC-008: Dead/unreachable code after return (line ~70)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define UDS_BUF_SIZE     64
#define DIAG_SESSION_DEFAULT  0x01
#define DIAG_SESSION_EXTENDED 0x03
#define DIAG_SESSION_PROG     0x02

typedef struct {
    uint8_t  session_type;
    uint8_t  security_level;
    uint32_t seed;
    uint8_t  authenticated;
} DiagSession;

static DiagSession current_session = {
    .session_type = DIAG_SESSION_DEFAULT,
    .security_level = 0,
    .seed = 0,
    .authenticated = 0
};

static char diag_log_buffer[UDS_BUF_SIZE];

/* TC-007: Unsafe input handling - sprintf with no bounds checking */
void log_diag_request(uint8_t service_id, const uint8_t* data, int data_len) {
    /* BUG: sprintf writes to a fixed-size buffer without bounds checking.
       If data_len is large, this overflows diag_log_buffer. */
    sprintf(diag_log_buffer, "SVC=0x%02X LEN=%d DATA=", service_id, data_len);
    
    int offset = strlen(diag_log_buffer);
    for (int i = 0; i < data_len; i++) {
        sprintf(diag_log_buffer + offset, "%02X", data[i]);
        offset += 2;
    }
    
    printf("%s\n", diag_log_buffer);
}

int handle_session_control(uint8_t sub_function) {
    switch (sub_function) {
        case DIAG_SESSION_DEFAULT:
            current_session.session_type = DIAG_SESSION_DEFAULT;
            current_session.security_level = 0;
            return 0;
        case DIAG_SESSION_EXTENDED:
            current_session.session_type = DIAG_SESSION_EXTENDED;
            return 0;
        case DIAG_SESSION_PROG:
            if (current_session.authenticated) {
                current_session.session_type = DIAG_SESSION_PROG;
                return 0;
            }
            return -1;
        default:
            return -2;
    }
}

/* TC-008: Dead code after return statement */
int validate_key(uint32_t key) {
    if (current_session.seed == 0) {
        return -1;
    }
    
    uint32_t expected = current_session.seed ^ 0xDEADBEEF;
    if (key == expected) {
        current_session.authenticated = 1;
        current_session.security_level = 1;
        return 0;
    }
    
    return -1;
    /* BUG: Dead/unreachable code below the return */
    current_session.security_level = 2;
    printf("Enhanced security level granted\n");
}

void security_access_seed(void) {
    current_session.seed = 0x12345678;  /* Synthetic seed */
    printf("Seed: 0x%08X\n", current_session.seed);
}

int process_uds_request(uint8_t service_id, const uint8_t* data, int len) {
    log_diag_request(service_id, data, len);
    
    switch (service_id) {
        case 0x10:
            return handle_session_control(data[0]);
        case 0x27:
            if (data[0] == 0x01) {
                security_access_seed();
                return 0;
            }
            return -1;
        default:
            return -1;
    }
}
