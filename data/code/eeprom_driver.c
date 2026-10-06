/**
 * eeprom_driver.c - EEPROM Non-Volatile Storage Driver
 *
 * Manages NVM read/write for calibration data.
 * Part of SecureCodeGuard synthetic test dataset.
 * Case: TC-009, TC-010
 *
 * INJECTED DEFECTS:
 * - TC-009: Unchecked return value of write operation (line ~52)
 * - TC-010: Use of gets() - critical unsafe input (line ~80)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define EEPROM_SIZE       4096
#define EEPROM_PAGE_SIZE  64
#define EEPROM_MAGIC      0xA5

typedef enum {
    EEPROM_OK = 0,
    EEPROM_ERR_ADDR,
    EEPROM_ERR_WRITE,
    EEPROM_ERR_READ,
    EEPROM_ERR_VERIFY
} EepromStatus;

static uint8_t eeprom_image[EEPROM_SIZE];
static uint8_t eeprom_initialized = 0;

EepromStatus eeprom_init(void) {
    memset(eeprom_image, 0xFF, EEPROM_SIZE);
    eeprom_image[0] = EEPROM_MAGIC;
    eeprom_initialized = 1;
    return EEPROM_OK;
}

EepromStatus eeprom_write(uint16_t addr, const uint8_t* data, uint16_t len) {
    if (addr + len > EEPROM_SIZE) {
        return EEPROM_ERR_ADDR;
    }
    if (!eeprom_initialized) {
        return EEPROM_ERR_WRITE;
    }
    memcpy(&eeprom_image[addr], data, len);
    return EEPROM_OK;
}

/* TC-009: Unchecked return value from eeprom_write */
void store_calibration(uint16_t offset, float value) {
    uint8_t buf[sizeof(float)];
    memcpy(buf, &value, sizeof(float));
    /* BUG: Return value of eeprom_write() is not checked.
       The write could fail silently. */
    eeprom_write(offset, buf, sizeof(float));
}

EepromStatus eeprom_read(uint16_t addr, uint8_t* data, uint16_t len) {
    if (addr + len > EEPROM_SIZE) {
        return EEPROM_ERR_ADDR;
    }
    if (!eeprom_initialized) {
        return EEPROM_ERR_READ;
    }
    memcpy(data, &eeprom_image[addr], len);
    return EEPROM_OK;
}

float read_calibration(uint16_t offset) {
    float value = 0.0f;
    uint8_t buf[sizeof(float)];
    EepromStatus status = eeprom_read(offset, buf, sizeof(float));
    if (status == EEPROM_OK) {
        memcpy(&value, buf, sizeof(float));
    }
    return value;
}

/* TC-010: Use of gets() - critical unsafe input function */
void interactive_eeprom_test(void) {
    char command[32];
    printf("Enter EEPROM command: ");
    /* BUG: gets() is critically unsafe - no bounds checking,
       removed from C11 standard. */
    gets(command);
    
    if (strcmp(command, "dump") == 0) {
        for (int i = 0; i < 64; i++) {
            printf("%02X ", eeprom_image[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
    } else if (strcmp(command, "init") == 0) {
        eeprom_init();
        printf("EEPROM initialized.\n");
    }
}

int main(void) {
    eeprom_init();
    store_calibration(0x10, 3.14159f);
    
    float val = read_calibration(0x10);
    printf("Calibration value: %.5f\n", val);
    
    return 0;
}
