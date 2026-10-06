/**
 * motor_control.c - PWM Motor Control Module
 * 
 * Controls DC motor via PWM for automotive actuator.
 * Part of SecureCodeGuard synthetic test dataset.
 * Case: TC-005, TC-006
 *
 * INJECTED DEFECTS:
 * - TC-005: Integer overflow in duty cycle calculation (line ~38)
 * - TC-006: Resource leak - file descriptor not closed on error path (line ~55)
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define PWM_MAX_DUTY 65535
#define PWM_FREQ_HZ  20000
#define MOTOR_MAX_RPM 8000

typedef struct {
    uint8_t  channel;
    uint16_t duty_cycle;
    uint16_t target_rpm;
    uint16_t current_rpm;
    uint8_t  enabled;
} MotorState;

static MotorState motors[4];

/* TC-005: Integer overflow - uint8_t * uint16_t can overflow uint16_t */
uint16_t calculate_duty_cycle(uint8_t percent, uint16_t max_duty) {
    /* BUG: If percent=100 and max_duty=65535, the multiplication
       overflows uint16_t. Should use uint32_t intermediate. */
    uint16_t duty = (uint16_t)(percent * max_duty / 100);
    return duty;
}

void set_motor_speed(uint8_t channel, uint8_t percent) {
    if (channel >= 4) {
        return;
    }
    motors[channel].duty_cycle = calculate_duty_cycle(percent, PWM_MAX_DUTY);
    motors[channel].target_rpm = (uint16_t)((uint32_t)percent * MOTOR_MAX_RPM / 100);
}

/* TC-006: Resource leak - fp not closed if calibration data is invalid */
int load_motor_calibration(const char* cal_file, uint8_t channel) {
    FILE* fp = fopen(cal_file, "r");
    if (fp == NULL) {
        return -1;
    }
    
    int cal_value;
    if (fscanf(fp, "%d", &cal_value) != 1) {
        /* BUG: fp is not closed before returning on error. 
           Resource leak: file handle leaked. */
        return -2;
    }
    
    if (cal_value < 0 || cal_value > PWM_MAX_DUTY) {
        /* BUG: fp is not closed here either. */
        return -3;
    }
    
    motors[channel].duty_cycle = (uint16_t)cal_value;
    fclose(fp);
    return 0;
}

void emergency_stop(void) {
    for (int i = 0; i < 4; i++) {
        motors[i].duty_cycle = 0;
        motors[i].target_rpm = 0;
        motors[i].enabled = 0;
    }
}

void motor_control_init(void) {
    for (int i = 0; i < 4; i++) {
        motors[i].channel = i;
        motors[i].duty_cycle = 0;
        motors[i].target_rpm = 0;
        motors[i].current_rpm = 0;
        motors[i].enabled = 0;
    }
}

int main(void) {
    motor_control_init();
    set_motor_speed(0, 75);
    load_motor_calibration("motor_cal.dat", 0);
    
    printf("Motor 0: duty=%u, target_rpm=%u\n",
           motors[0].duty_cycle, motors[0].target_rpm);
    
    emergency_stop();
    return 0;
}
