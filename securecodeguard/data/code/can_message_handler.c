/**
 * can_message_handler.c - CAN Bus Message Handler
 * 
 * Processes incoming CAN messages for an automotive ECU.
 * Part of SecureCodeGuard synthetic test dataset.
 * Case: TC-003, TC-004
 *
 * INJECTED DEFECTS:
 * - TC-003: Unchecked return value from fopen (line ~35)
 * - TC-004: Array index out of bounds (line ~55)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CAN_MAX_DLC 8
#define CAN_ID_MASK 0x7FF
#define MAX_HANDLERS 32

typedef struct {
    uint32_t id;
    uint8_t dlc;
    uint8_t data[CAN_MAX_DLC];
    uint32_t timestamp;
} CanMessage;

typedef void (*CanHandler)(const CanMessage*);

static CanHandler handler_table[MAX_HANDLERS];
static int handler_count = 0;

/* TC-003: Unchecked return value - fopen may return NULL */
void log_can_message(const CanMessage* msg, const char* logfile) {
    FILE* fp = fopen(logfile, "a");
    /* BUG: No check if fopen returned NULL.
       If the file cannot be opened, fprintf will crash. */
    fprintf(fp, "[%u] ID=0x%03X DLC=%u DATA=",
            msg->timestamp, msg->id, msg->dlc);
    for (int i = 0; i < msg->dlc; i++) {
        fprintf(fp, "%02X ", msg->data[i]);
    }
    fprintf(fp, "\n");
    fclose(fp);
}

int register_handler(uint32_t can_id, CanHandler handler) {
    if (handler_count >= MAX_HANDLERS) {
        return -1;
    }
    handler_table[handler_count++] = handler;
    return 0;
}

/* TC-004: Array boundary issue - user_index not validated */
void dispatch_message(const CanMessage* msg, int user_index) {
    /* BUG: user_index is not bounds-checked against MAX_HANDLERS.
       Could read/call beyond handler_table bounds. */
    if (handler_table[user_index] != NULL) {
        handler_table[user_index](msg);
    }
}

void process_can_frame(const uint8_t* raw_frame, int frame_len) {
    if (frame_len < 5) {
        return;
    }
    
    CanMessage msg;
    msg.id = ((uint32_t)raw_frame[0] << 8) | raw_frame[1];
    msg.id &= CAN_ID_MASK;
    msg.dlc = raw_frame[2];
    
    if (msg.dlc > CAN_MAX_DLC) {
        msg.dlc = CAN_MAX_DLC;
    }
    
    memcpy(msg.data, &raw_frame[3], msg.dlc);
    msg.timestamp = 0;
    
    log_can_message(&msg, "can_log.txt");
}

void default_handler(const CanMessage* msg) {
    printf("Unhandled CAN ID: 0x%03X\n", msg->id);
}

int main(void) {
    register_handler(0x100, default_handler);
    
    uint8_t test_frame[] = {0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
    process_can_frame(test_frame, sizeof(test_frame));
    
    /* Dispatching with unchecked index */
    CanMessage dummy = {0x100, 4, {0}, 0};
    dispatch_message(&dummy, 50);  /* Out of bounds! */
    
    return 0;
}
