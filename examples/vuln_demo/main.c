#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Intentionally vulnerable patterns for ConstraintGuard demo analysis.
 * Each function contains a detectable defect. Severity rankings change
 * depending on whether a tight or relaxed constraint profile is applied.
 */

/* CWE-120: Buffer overflow via unsafe strcpy into fixed-size stack buffer */
static void copy_input(const char *input)
{
    char buf[16];
    strcpy(buf, input);
    printf("input: %s\n", buf);
}

/* CWE-476: Null pointer dereference — pointer may be NULL on one path */
static int read_sensor(int *sensor_value)
{
    return *sensor_value;
}

/* CWE-401: Memory leak — allocation not freed before function return */
static char *build_packet(size_t size)
{
    char *packet = malloc(size);
    if (packet == NULL) {
        return NULL;
    }
    memset(packet, 0, size);
    char *header = malloc(8);
    if (header == NULL) {
        /* packet leaks here */
        return NULL;
    }
    memcpy(packet, header, 8);
    free(header);
    return packet;
}

/* CWE-416: Use after free */
static void process_buffer(void)
{
    char *buf = malloc(64);
    if (buf == NULL) {
        return;
    }
    snprintf(buf, 64, "data");
    free(buf);
    printf("processed: %s\n", buf);
}

/* CWE-190: Integer overflow in size calculation before malloc */
static void *allocate_matrix(int rows, int cols)
{
    int total = rows * cols;
    return malloc((size_t)total);
}

/* CWE-134: Use of uninitialized value through a conditional path */
static int compute_checksum(int mode)
{
    int result;
    if (mode == 1) {
        result = 0xDEAD;
    }
    return result;
}

/* CWE-120: Buffer overflow in UART interrupt handler (isr_ prefix triggers ISR scoring rules) */
static void isr_uart(const char *rx_data)
{
    char rx_buf[8];
    strcpy(rx_buf, rx_data);
    printf("uart: %s\n", rx_buf);
}

/* CWE-476: Null dereference in safety-critical control loop (matches critical_functions in tight.yml) */
static int control_loop(int *setpoint, int *measured)
{
    int error = *setpoint - *measured;
    return error;
}

int main(int argc, char *argv[])
{
    if (argc > 1) {
        copy_input(argv[1]);
    }

    int *sensor = NULL;
    if (argc > 2) {
        int val = 42;
        sensor = &val;
    }
    printf("sensor: %d\n", read_sensor(sensor));

    char *pkt = build_packet(256);
    if (pkt != NULL) {
        printf("packet built\n");
        free(pkt);
    }

    process_buffer();

    void *matrix = allocate_matrix(1000, 1000000);
    if (matrix != NULL) {
        free(matrix);
    }

    int checksum = compute_checksum(argc);
    printf("checksum: %d\n", checksum);

    if (argc > 3) {
        isr_uart(argv[3]);
    }

    int setpoint = 100;
    int *measured_ptr = NULL;
    if (argc > 4) {
        int measured = 90;
        measured_ptr = &measured;
    }
    printf("error: %d\n", control_loop(&setpoint, measured_ptr));

    return 0;
}
