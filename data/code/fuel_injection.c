/**
 * fuel_injection.c - Fuel Injection Controller
 *
 * Calculates and controls fuel injection timing and duration.
 * Part of SecureCodeGuard synthetic test dataset.
 * Case: TC-012
 *
 * INJECTED DEFECT:
 * - TC-012: Suspicious control flow - missing break in switch (line ~68)
 */

#include <stdio.h>
#include <stdint.h>

#define INJ_CHANNELS     4
#define INJ_MAX_PULSE_US 25000
#define MAP_TABLE_SIZE   16

typedef enum {
    ENGINE_OFF = 0,
    ENGINE_CRANKING,
    ENGINE_RUNNING,
    ENGINE_OVERREV,
    ENGINE_FAULT
} EngineState;

typedef struct {
    uint16_t rpm;
    uint16_t map_kpa;
    int16_t  coolant_temp;
    uint16_t throttle_pos;
    uint16_t lambda;
} EngineInputs;

typedef struct {
    uint16_t pulse_width_us[INJ_CHANNELS];
    uint8_t  enabled[INJ_CHANNELS];
} InjectorOutput;

static EngineState engine_state = ENGINE_OFF;
static InjectorOutput injectors;

static uint16_t base_fuel_map[MAP_TABLE_SIZE] = {
    1000, 1200, 1500, 1800, 2000, 2200, 2500, 2800,
    3000, 3200, 3500, 3800, 4000, 4500, 5000, 5500
};

uint16_t lookup_base_fuel(uint16_t rpm) {
    int index = rpm / 500;
    if (index >= MAP_TABLE_SIZE) {
        index = MAP_TABLE_SIZE - 1;
    }
    if (index < 0) {
        index = 0;
    }
    return base_fuel_map[index];
}

/* TC-012: Missing break causes fall-through in switch */
void update_engine_state(uint16_t rpm, int fault_flag) {
    switch (engine_state) {
        case ENGINE_OFF:
            if (rpm > 0) {
                engine_state = ENGINE_CRANKING;
            }
            break;
        case ENGINE_CRANKING:
            if (rpm > 500) {
                engine_state = ENGINE_RUNNING;
            }
            break;
        case ENGINE_RUNNING:
            if (rpm > 7000) {
                engine_state = ENGINE_OVERREV;
                /* BUG: Missing break! Falls through to ENGINE_OVERREV
                   case which immediately cuts fuel. Even at normal RPM
                   after setting OVERREV, fall-through could be triggered
                   by compiler optimization or logic change. */
            }
        case ENGINE_OVERREV:
            /* Fuel cut for overrev protection */
            for (int i = 0; i < INJ_CHANNELS; i++) {
                injectors.enabled[i] = 0;
            }
            if (rpm < 6500) {
                engine_state = ENGINE_RUNNING;
            }
            break;
        case ENGINE_FAULT:
            /* Limp mode - reduced fuel */
            for (int i = 0; i < INJ_CHANNELS; i++) {
                injectors.pulse_width_us[i] = 1000;
            }
            break;
    }
    
    if (fault_flag) {
        engine_state = ENGINE_FAULT;
    }
}

void calculate_injection(const EngineInputs* inputs) {
    uint16_t base = lookup_base_fuel(inputs->rpm);
    
    /* Temperature correction */
    float temp_factor = 1.0f;
    if (inputs->coolant_temp < 0) {
        temp_factor = 1.3f;
    } else if (inputs->coolant_temp < 40) {
        temp_factor = 1.1f;
    }
    
    uint16_t pulse = (uint16_t)(base * temp_factor);
    if (pulse > INJ_MAX_PULSE_US) {
        pulse = INJ_MAX_PULSE_US;
    }
    
    for (int i = 0; i < INJ_CHANNELS; i++) {
        injectors.pulse_width_us[i] = pulse;
        injectors.enabled[i] = (engine_state == ENGINE_RUNNING) ? 1 : 0;
    }
}

int main(void) {
    EngineInputs inputs = {
        .rpm = 3000,
        .map_kpa = 80,
        .coolant_temp = 20,
        .throttle_pos = 50,
        .lambda = 100
    };
    
    update_engine_state(inputs.rpm, 0);
    calculate_injection(&inputs);
    
    printf("Engine state: %d\n", engine_state);
    for (int i = 0; i < INJ_CHANNELS; i++) {
        printf("INJ%d: %u us, enabled=%u\n",
               i, injectors.pulse_width_us[i], injectors.enabled[i]);
    }
    
    return 0;
}
