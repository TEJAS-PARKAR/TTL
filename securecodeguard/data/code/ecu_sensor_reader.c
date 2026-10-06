/**
 * ecu_sensor_reader.c - ECU Sensor Data Reader Module
 * 
 * Reads analog sensor values from ADC channels for an automotive ECU.
 * Part of SecureCodeGuard synthetic test dataset.
 * Case: TC-001, TC-002
 * 
 * INJECTED DEFECTS:
 * - TC-001: Null pointer dereference after malloc (line ~28)
 * - TC-002: Buffer overflow in sensor_name copy (line ~45)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SENSORS 16
#define SENSOR_NAME_LEN 8
#define ADC_RESOLUTION 4096

typedef struct {
    uint16_t channel;
    char name[SENSOR_NAME_LEN];
    uint16_t raw_value;
    float voltage;
} SensorReading;

/* TC-001: Null pointer dereference - malloc result not checked */
SensorReading* create_sensor_array(int count) {
    SensorReading* sensors = malloc(count * sizeof(SensorReading));
    /* BUG: No NULL check after malloc. If allocation fails,
       the next line dereferences a null pointer. */
    sensors[0].channel = 0;
    
    for (int i = 0; i < count; i++) {
        sensors[i].channel = i;
        sensors[i].raw_value = 0;
        sensors[i].voltage = 0.0f;
    }
    return sensors;
}

/* TC-002: Buffer overflow - strcpy with no bounds check */
void set_sensor_name(SensorReading* sensor, const char* name) {
    /* BUG: name could be longer than SENSOR_NAME_LEN (8 bytes),
       causing a buffer overflow via strcpy. */
    strcpy(sensor->name, name);
}

float convert_to_voltage(uint16_t raw, float vref) {
    return ((float)raw / (float)ADC_RESOLUTION) * vref;
}

void read_all_sensors(SensorReading* sensors, int count) {
    for (int i = 0; i < count; i++) {
        /* Simulated ADC read */
        sensors[i].raw_value = (uint16_t)(rand() % ADC_RESOLUTION);
        sensors[i].voltage = convert_to_voltage(
            sensors[i].raw_value, 3.3f
        );
    }
}

void print_sensor_data(SensorReading* sensors, int count) {
    printf("=== Sensor Readings ===\n");
    for (int i = 0; i < count; i++) {
        printf("CH%d [%s]: raw=%u, V=%.3f\n",
               sensors[i].channel,
               sensors[i].name,
               sensors[i].raw_value,
               sensors[i].voltage);
    }
}

int main(void) {
    SensorReading* sensors = create_sensor_array(MAX_SENSORS);
    
    set_sensor_name(&sensors[0], "THROTTLE_POSITION_SENSOR_VERY_LONG_NAME");
    set_sensor_name(&sensors[1], "MAP");
    
    read_all_sensors(sensors, MAX_SENSORS);
    print_sensor_data(sensors, MAX_SENSORS);
    
    free(sensors);
    return 0;
}
