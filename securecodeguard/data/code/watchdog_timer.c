/**
 * watchdog_timer.c - Software Watchdog Timer
 *
 * Implements a software watchdog for ECU task monitoring.
 * Part of SecureCodeGuard synthetic test dataset.
 * Case: TC-011
 *
 * INJECTED DEFECT:
 * - TC-011: Concurrency/state issue - shared state without synchronization (line ~45)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_WDG_TASKS   8
#define WDG_TIMEOUT_MS  100

typedef struct {
    uint8_t  task_id;
    uint32_t last_kick_ms;
    uint32_t timeout_ms;
    uint8_t  active;
    uint8_t  expired;
} WdgTask;

/* TC-011: Shared state without synchronization.
   In a real RTOS context, multiple tasks would access this
   concurrently without mutex/critical section protection. */
static WdgTask wdg_tasks[MAX_WDG_TASKS];
static uint32_t system_tick_ms = 0;
static uint8_t  wdg_fault_count = 0;

void wdg_init(void) {
    memset(wdg_tasks, 0, sizeof(wdg_tasks));
    system_tick_ms = 0;
    wdg_fault_count = 0;
}

int wdg_register_task(uint8_t task_id, uint32_t timeout_ms) {
    for (int i = 0; i < MAX_WDG_TASKS; i++) {
        if (!wdg_tasks[i].active) {
            /* BUG: No critical section / mutex protection.
               Concurrent task registration could corrupt shared state. */
            wdg_tasks[i].task_id = task_id;
            wdg_tasks[i].timeout_ms = timeout_ms;
            wdg_tasks[i].last_kick_ms = system_tick_ms;
            wdg_tasks[i].active = 1;
            wdg_tasks[i].expired = 0;
            return 0;
        }
    }
    return -1;
}

void wdg_kick(uint8_t task_id) {
    /* BUG: No synchronization when updating shared state */
    for (int i = 0; i < MAX_WDG_TASKS; i++) {
        if (wdg_tasks[i].active && wdg_tasks[i].task_id == task_id) {
            wdg_tasks[i].last_kick_ms = system_tick_ms;
            wdg_tasks[i].expired = 0;
            return;
        }
    }
}

void wdg_check(void) {
    for (int i = 0; i < MAX_WDG_TASKS; i++) {
        if (!wdg_tasks[i].active) continue;
        
        uint32_t elapsed = system_tick_ms - wdg_tasks[i].last_kick_ms;
        if (elapsed > wdg_tasks[i].timeout_ms) {
            if (!wdg_tasks[i].expired) {
                wdg_tasks[i].expired = 1;
                wdg_fault_count++;
                printf("WDG FAULT: Task %u timed out (%u ms)\n",
                       wdg_tasks[i].task_id, elapsed);
            }
        }
    }
}

void wdg_tick(uint32_t ms_elapsed) {
    system_tick_ms += ms_elapsed;
    wdg_check();
}

int main(void) {
    wdg_init();
    wdg_register_task(1, 100);
    wdg_register_task(2, 200);
    
    wdg_kick(1);
    wdg_tick(50);
    wdg_tick(60);  /* Task 1 should expire */
    
    printf("Fault count: %u\n", wdg_fault_count);
    return 0;
}
