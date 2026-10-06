/**
 * brake_controller.c - Brake-By-Wire Controller
 *
 * Demo file combining multiple defect types for walkthrough.
 * Part of SecureCodeGuard synthetic test dataset.
 * Case: TC-013 (buffer boundary), TC-014 (unchecked return),
 *       TC-015 (security issue), plus a compiler warning scenario.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define BRAKE_CHANNELS    4
#define PRESSURE_BUF_SIZE 16
#define MAX_PRESSURE_BAR  200

typedef struct {
    uint8_t  channel;
    uint16_t pressure_bar;
    uint8_t  abs_active;
    uint8_t  fault;
} BrakeChannel;

static BrakeChannel brakes[BRAKE_CHANNELS];
static char log_buffer[PRESSURE_BUF_SIZE];

/* TC-013: Buffer boundary defect - writing beyond buffer */
void format_pressure_log(const BrakeChannel* ch) {
    /* BUG: snprintf limit should be PRESSURE_BUF_SIZE but
       the format string can produce more than 16 chars,
       and we use sprintf instead of snprintf. */
    sprintf(log_buffer, "CH%d:P=%03u:ABS=%d:F=%d",
            ch->channel, ch->pressure_bar,
            ch->abs_active, ch->fault);
}

/* TC-014: Unchecked return value */
void load_brake_config(const char* config_path) {
    FILE* fp = fopen(config_path, "r");
    if (fp == NULL) return;
    
    char line[128];
    while (fgets(line, sizeof(line), fp) != NULL) {
        int ch, pressure;
        /* BUG: scanf return not checked properly */
        sscanf(line, "%d %d", &ch, &pressure);
        if (ch >= 0 && ch < BRAKE_CHANNELS) {
            brakes[ch].pressure_bar = (uint16_t)pressure;
        }
    }
    fclose(fp);
}

/* TC-015: Security issue - externally supplied data used without validation
   as array index via atoi with no error handling */
void set_brake_from_input(const char* channel_str, const char* pressure_str) {
    /* BUG: atoi has no error handling, could return garbage.
       No range validation before array access. */
    int ch = atoi(channel_str);
    int pressure = atoi(pressure_str);
    
    brakes[ch].pressure_bar = (uint16_t)pressure;
    brakes[ch].fault = 0;
}

void brake_init(void) {
    for (int i = 0; i < BRAKE_CHANNELS; i++) {
        brakes[i].channel = i;
        brakes[i].pressure_bar = 0;
        brakes[i].abs_active = 0;
        brakes[i].fault = 0;
    }
}

void apply_braking(uint16_t target_pressure) {
    if (target_pressure > MAX_PRESSURE_BAR) {
        target_pressure = MAX_PRESSURE_BAR;
    }
    
    for (int i = 0; i < BRAKE_CHANNELS; i++) {
        brakes[i].pressure_bar = target_pressure;
        
        format_pressure_log(&brakes[i]);
        printf("%s\n", log_buffer);
    }
}

void abs_control(uint8_t channel) {
    if (channel >= BRAKE_CHANNELS) return;
    
    if (brakes[channel].pressure_bar > 150) {
        brakes[channel].abs_active = 1;
        brakes[channel].pressure_bar -= 30;
    } else {
        brakes[channel].abs_active = 0;
    }
}

int main(void) {
    brake_init();
    apply_braking(180);
    
    for (int i = 0; i < BRAKE_CHANNELS; i++) {
        abs_control(i);
    }
    
    /* Simulate external input */
    set_brake_from_input("2", "100");
    
    return 0;
}
