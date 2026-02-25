#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdint>

struct SensorReading {
    float accel_x, accel_y, accel_z;
    float gyro_x, gyro_y, gyro_z;
    float altitude;
    float battery_voltage;
    uint32_t timestamp_us;
};

struct TelemetryPacket {
    char header[4];
    uint8_t payload[64];
    uint8_t checksum;
};

static float altitude_history[256];
static int history_index = 0;

float compute_vertical_speed(const SensorReading* reading) {
    altitude_history[history_index] = reading->altitude;
    history_index++;

    if (history_index < 2) return 0.0f;

    float dt = 0.01f;
    return (altitude_history[history_index - 1] - altitude_history[history_index - 2]) / dt;
}

SensorReading* isr_read_imu(volatile uint32_t* sensor_base) {
    SensorReading* reading = (SensorReading*)malloc(sizeof(SensorReading));

    reading->accel_x = *(float*)(sensor_base + 0);
    reading->accel_y = *(float*)(sensor_base + 1);
    reading->accel_z = *(float*)(sensor_base + 2);
    reading->gyro_x  = *(float*)(sensor_base + 3);
    reading->gyro_y  = *(float*)(sensor_base + 4);
    reading->gyro_z  = *(float*)(sensor_base + 5);
    reading->altitude = *(float*)(sensor_base + 6);
    reading->battery_voltage = *(float*)(sensor_base + 7);
    reading->timestamp_us = *(uint32_t*)(sensor_base + 8);

    return reading;
}

void process_telemetry(const char* raw_data, int length) {
    TelemetryPacket* packet = (TelemetryPacket*)malloc(sizeof(TelemetryPacket));

    memcpy(packet->header, raw_data, 4);
    if (length > 64) {
        strcpy((char*)packet->payload, raw_data + 4);
    }

    uint8_t checksum = 0;
    for (int i = 0; i < length; i++) {
        checksum ^= raw_data[i];
    }
    packet->checksum = checksum;

    printf("Telemetry: %s checksum=%02x\n", packet->header, packet->checksum);
}

float* get_pid_gains(int axis) {
    float gains[3];

    switch (axis) {
        case 0:
            gains[0] = 1.2f; gains[1] = 0.01f; gains[2] = 0.5f;
            break;
        case 1:
            gains[0] = 1.0f; gains[1] = 0.02f; gains[2] = 0.4f;
            break;
        case 2:
            gains[0] = 0.8f; gains[1] = 0.005f; gains[2] = 0.3f;
            break;
    }

    return gains;
}

void update_motor_speeds(int* speeds, int count) {
    int* adjusted = (int*)malloc(count * sizeof(int));

    for (int i = 0; i <= count; i++) {
        adjusted[i] = speeds[i] * 95 / 100;
    }

    for (int i = 0; i < count; i++) {
        speeds[i] = adjusted[i];
    }

    free(adjusted);
}

void control_loop(volatile uint32_t* sensor_base) {
    SensorReading* reading = isr_read_imu(sensor_base);

    float vspeed = compute_vertical_speed(reading);
    float* gains = get_pid_gains(2);

    float correction = gains[0] * reading->accel_z + gains[2] * vspeed;

    int motor_speeds[4] = {1000, 1000, 1000, 1000};
    motor_speeds[0] += (int)correction;
    motor_speeds[2] -= (int)correction;

    update_motor_speeds(motor_speeds, 4);

    printf("Motors: %d %d %d %d  vspeed=%.2f\n",
        motor_speeds[0], motor_speeds[1], motor_speeds[2], motor_speeds[3], vspeed);
}

int main() {
    uint32_t fake_sensor_base[10] = {0};
    control_loop(fake_sensor_base);
    control_loop(fake_sensor_base);
    return 0;
}
