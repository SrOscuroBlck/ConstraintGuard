/*
 * Minimal FreeRTOSConfig.h stub for static analysis with clang-tidy.
 * Not intended for compilation — only for enabling clang-analyzer-* checks
 * on FreeRTOS kernel source files without a real application config.
 */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#include <stdint.h>

#define configUSE_PREEMPTION                        1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION     0
#define configUSE_TICKLESS_IDLE                     0
#define configCPU_CLOCK_HZ                          72000000UL
#define configSYSTICK_CLOCK_HZ                      configCPU_CLOCK_HZ
#define configTICK_RATE_HZ                          1000
#define configMAX_PRIORITIES                        5
#define configMINIMAL_STACK_SIZE                    128
#define configMAX_TASK_NAME_LEN                     16
#define configUSE_16_BIT_TICKS                      0
#define configIDLE_SHOULD_YIELD                     1
#define configUSE_MUTEXES                           1
#define configUSE_RECURSIVE_MUTEXES                 1
#define configUSE_COUNTING_SEMAPHORES               1
#define configUSE_TASK_NOTIFICATIONS                1
#define configTASK_NOTIFICATION_ARRAY_ENTRIES       3
#define configUSE_QUEUE_SETS                        1
#define configUSE_TIME_SLICING                      1
#define configUSE_NEWLIB_REENTRANT                  0
#define configENABLE_BACKWARD_COMPATIBILITY         0
#define configNUM_THREAD_LOCAL_STORAGE_POINTERS     5
#define configSTACK_DEPTH_TYPE                      uint16_t
#define configMESSAGE_BUFFER_LENGTH_TYPE            size_t
#define configTOTAL_HEAP_SIZE                       ( (size_t)(75 * 1024) )
#define configAPPLICATION_ALLOCATED_HEAP            0
#define configSUPPORT_STATIC_ALLOCATION             1
#define configSUPPORT_DYNAMIC_ALLOCATION            1
#define configUSE_IDLE_HOOK                         0
#define configUSE_TICK_HOOK                         0
#define configCHECK_FOR_STACK_OVERFLOW              0
#define configUSE_MALLOC_FAILED_HOOK                0
#define configUSE_DAEMON_TASK_STARTUP_HOOK          0
#define configGENERATE_RUN_TIME_STATS               0
#define configUSE_STATS_FORMATTING_FUNCTIONS        0
#define configUSE_TRACE_FACILITY                    0
#define configUSE_CO_ROUTINES                       0
#define configMAX_CO_ROUTINE_PRIORITIES             1
#define configUSE_TIMERS                            1
#define configTIMER_TASK_PRIORITY                   ( configMAX_PRIORITIES - 1 )
#define configTIMER_QUEUE_LENGTH                    10
#define configTIMER_TASK_STACK_DEPTH                configMINIMAL_STACK_SIZE
#define configUSE_POSIX_ERRNO                       0
#define configUSE_SB_COMPLETED_CALLBACK             0

#define INCLUDE_vTaskPrioritySet                    1
#define INCLUDE_uxTaskPriorityGet                   1
#define INCLUDE_vTaskDelete                         1
#define INCLUDE_vTaskSuspend                        1
#define INCLUDE_xResumeFromISR                      1
#define INCLUDE_vTaskDelayUntil                     1
#define INCLUDE_vTaskDelay                          1
#define INCLUDE_xTaskGetSchedulerState              1
#define INCLUDE_xTaskGetCurrentTaskHandle           1
#define INCLUDE_uxTaskGetStackHighWaterMark         1
#define INCLUDE_xTaskGetIdleTaskHandle              0
#define INCLUDE_eTaskGetState                       1
#define INCLUDE_xEventGroupSetBitFromISR            1
#define INCLUDE_xTimerPendFunctionCall              0
#define INCLUDE_xTaskAbortDelay                     0
#define INCLUDE_xTaskGetHandle                      0
#define INCLUDE_xTaskResumeFromISR                  1

/* Cortex-M3 interrupt priorities for static analysis */
#define configKERNEL_INTERRUPT_PRIORITY             255
#define configMAX_SYSCALL_INTERRUPT_PRIORITY        191
#define configLIBRARY_KERNEL_INTERRUPT_PRIORITY     15

/* Satisfy portmacro.h expectations */
#define configASSERT( x )   ( (void)(x) )

#endif /* FREERTOS_CONFIG_H */
