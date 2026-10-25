/*
 * Read-only FT USB TOKEN 3000GM HID transport probe.
 *
 * The master file 3F00 and public metadata file F0FF are selected, then the
 * public metadata is read. No PIN, authentication, signing, key generation,
 * certificate update, or write command is present in this file.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <IOKit/hid/IOHIDManager.h>
#include <Security/Security.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ft3000gm_lock.h"
#include "ft3000gm_devices.h"

enum {
    FT_VENDOR_ID = 0x096e,
    FT_PRODUCT_ID = 0x0317,
    HID_REPORT_SIZE = 64,
    HID_PAYLOAD_SIZE = 58,
    APDU_RESPONSE_MAX = 8192,
    METADATA_SIZE = 0x320
};

struct InputState {
    uint8_t report[HID_REPORT_SIZE];
    CFIndex report_length;
    int ready;
};

static void input_report(void *context, IOReturn result, void *sender,
                         IOHIDReportType type, uint32_t report_id,
                         uint8_t *report, CFIndex report_length) {
    (void)sender;
    (void)type;
    (void)report_id;
    struct InputState *state = context;
    if (result != kIOReturnSuccess || report_length <= 0) {
        return;
    }
    if (report_length > HID_REPORT_SIZE) {
        report_length = HID_REPORT_SIZE;
    }
    memcpy(state->report, report, (size_t)report_length);
    state->report_length = report_length;
    state->ready = 1;
}

static CFMutableDictionaryRef make_matching(void) {
    CFMutableDictionaryRef matching = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (matching == NULL) {
        return NULL;
    }

    int vendor = FT_VENDOR_ID;
    int product = FT_PRODUCT_ID;
    CFNumberRef vendor_number = CFNumberCreate(
        kCFAllocatorDefault, kCFNumberIntType, &vendor);
    CFNumberRef product_number = CFNumberCreate(
        kCFAllocatorDefault, kCFNumberIntType, &product);
    if (vendor_number == NULL || product_number == NULL) {
        if (vendor_number != NULL) CFRelease(vendor_number);
        if (product_number != NULL) CFRelease(product_number);
        CFRelease(matching);
        return NULL;
    }

    CFDictionarySetValue(matching, CFSTR(kIOHIDVendorIDKey), vendor_number);
    CFDictionarySetValue(matching, CFSTR(kIOHIDProductIDKey), product_number);
    CFRelease(vendor_number);
    CFRelease(product_number);
    return matching;
}

static IOReturn wait_for_report(struct InputState *state, double timeout) {
    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + timeout;
    while (!state->ready && CFAbsoluteTimeGetCurrent() < deadline) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
    }
    return state->ready ? kIOReturnSuccess : kIOReturnTimeout;
}

static IOReturn hid_exchange(IOHIDDeviceRef device, struct InputState *state,
                             const uint8_t *request, size_t request_length,
                             uint8_t *response, size_t response_capacity,
                             size_t *response_length) {
    if (request_length > UINT16_MAX) {
        return kIOReturnBadArgument;
    }

    state->ready = 0;
    state->report_length = 0;
    for (size_t offset = 0; offset < request_length;) {
        size_t chunk = request_length - offset;
        if (chunk > HID_PAYLOAD_SIZE) chunk = HID_PAYLOAD_SIZE;

        uint8_t report[HID_REPORT_SIZE] = {0};
        report[0] = (uint8_t)(request_length >> 8);
        report[1] = (uint8_t)request_length;
        report[2] = (uint8_t)(offset >> 8);
        report[3] = (uint8_t)offset;
        report[4] = (uint8_t)(chunk >> 8);
        report[5] = (uint8_t)chunk;
        memcpy(report + 6, request + offset, chunk);

        IOReturn result = IOHIDDeviceSetReport(
            device, kIOHIDReportTypeOutput, 0, report, sizeof(report));
        if (result != kIOReturnSuccess) {
            return result;
        }
        offset += chunk;
    }

    size_t total = 0;
    size_t received = 0;
    do {
        IOReturn result = wait_for_report(state, 3.0);
        if (result != kIOReturnSuccess) {
            return result;
        }
        if (state->report_length < 6) {
            return kIOReturnUnderrun;
        }

        size_t frame_total = ((size_t)state->report[0] << 8) | state->report[1];
        size_t offset = ((size_t)state->report[2] << 8) | state->report[3];
        size_t chunk = ((size_t)state->report[4] << 8) | state->report[5];
        if (total == 0) total = frame_total;
        if (frame_total != total || chunk > HID_PAYLOAD_SIZE ||
            offset + chunk > total || offset + chunk > response_capacity ||
            6 + chunk > (size_t)state->report_length) {
            return kIOReturnBadArgument;
        }
        memcpy(response + offset, state->report + 6, chunk);
        if (offset + chunk > received) received = offset + chunk;
        state->ready = 0;
        state->report_length = 0;
    } while (received < total);

    *response_length = total;
    return kIOReturnSuccess;
}

static int apdu(IOHIDDeviceRef device, struct InputState *state,
                const uint8_t *command, size_t command_length,
                uint8_t *data, size_t data_capacity, size_t *data_length,
                uint16_t *status_word) {
    uint8_t response[APDU_RESPONSE_MAX];
    size_t response_length = 0;
    IOReturn result = hid_exchange(device, state, command, command_length,
                                   response, sizeof(response), &response_length);
    if (result != kIOReturnSuccess || response_length < 2) {
        return result == kIOReturnSuccess ? kIOReturnUnderrun : result;
    }

    size_t payload_length = response_length - 2;
    if (payload_length > data_capacity) {
        return kIOReturnNoSpace;
    }
    if (data != NULL && payload_length != 0) {
        memcpy(data, response, payload_length);
    }
    *data_length = payload_length;
    *status_word = (uint16_t)(((uint16_t)response[payload_length] << 8) |
                             response[payload_length + 1]);
    return kIOReturnSuccess;
}

static int hex_nibble(uint8_t value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int read_binary_file(IOHIDDeviceRef device, struct InputState *state,
                            uint8_t *output, size_t length) {
    for (size_t offset = 0; offset < length;) {
        size_t chunk = length - offset;
        if (chunk > 512) chunk = 512;

        uint8_t command[7] = {
            0x80, 0xb0, (uint8_t)(offset >> 8), (uint8_t)offset
        };
        size_t command_length;
        if (chunk < 256) {
            command[4] = (uint8_t)chunk;
            command_length = 5;
        } else {
            command[4] = 0;
            command[5] = (uint8_t)(chunk >> 8);
            command[6] = (uint8_t)chunk;
            command_length = 7;
        }

        size_t received = 0;
        uint16_t status = 0;
        int result = apdu(device, state, command, command_length,
                          output + offset, length - offset, &received, &status);
        if (result != kIOReturnSuccess || status != 0x9000 ||
            received != chunk) {
            return result == kIOReturnSuccess ? kIOReturnError : result;
        }
        offset += chunk;
    }
    return kIOReturnSuccess;
}

static int certificate_is_der(const uint8_t *data, size_t length) {
    if (length == 0) return 0;
    CFDataRef der = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)length);
    if (der == NULL) return 0;
    SecCertificateRef certificate = SecCertificateCreateWithData(
        kCFAllocatorDefault, der);
    CFRelease(der);
    if (certificate == NULL) return 0;
    CFRelease(certificate);
    return 1;
}

static void print_base64(const uint8_t *data, size_t length) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < length; i += 3) {
        uint32_t value = (uint32_t)data[i] << 16;
        if (i + 1 < length) value |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < length) value |= data[i + 2];
        putchar(alphabet[(value >> 18) & 0x3f]);
        putchar(alphabet[(value >> 12) & 0x3f]);
        putchar(i + 1 < length ? alphabet[(value >> 6) & 0x3f] : '=');
        putchar(i + 2 < length ? alphabet[value & 0x3f] : '=');
    }
}

int main(int argc, char **argv) {
    int include_certificate = 0, list_devices = 0;
    uint64_t device_id = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--include-certificate") == 0) include_certificate = 1;
        else if (strcmp(argv[i], "--list-devices") == 0) list_devices = 1;
        else if (strcmp(argv[i], "--device-id") == 0 && i + 1 < argc &&
                 ft_parse_device_id(argv[i + 1], &device_id)) i++;
        else { fputs("{\"error\":\"invalid probe arguments\"}\n", stdout); return 2; }
    }

    if (acquire_device_lock() < 0) {
        fputs("{\"device_found\":false,\"error\":\"USBKey device lock unavailable\"}\n", stdout);
        return 1;
    }

    IOHIDManagerRef manager = IOHIDManagerCreate(
        kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    CFMutableDictionaryRef matching = make_matching();
    if (manager == NULL || matching == NULL) {
        fputs("{\"device_found\":false,\"error\":\"HID setup failed\"}\n",
              stdout);
        if (matching != NULL) CFRelease(matching);
        if (manager != NULL) CFRelease(manager);
        return 2;
    }

    IOHIDManagerSetDeviceMatching(manager, matching);
    CFRelease(matching);
    IOReturn manager_result = IOHIDManagerOpen(
        manager, kIOHIDOptionsTypeNone);
    if (list_devices) {
        if (manager_result != kIOReturnSuccess) {
            fputs("{\"error\":\"HID enumeration failed\"}\n", stdout);
            CFRelease(manager); return 1;
        }
        CFSetRef devices = IOHIDManagerCopyDevices(manager);
        CFIndex count = devices == NULL ? 0 : CFSetGetCount(devices);
        const void **values = count > 0 ? calloc((size_t)count, sizeof(*values)) : NULL;
        if (count > 0 && values == NULL) { CFRelease(devices); CFRelease(manager); return 2; }
        if (values != NULL) CFSetGetValues(devices, values);
        fputs("{\"devices\":[", stdout);
        for (CFIndex i = 0; i < count; i++) {
            if (i) putchar(',');
            printf("{\"device_id\":\"%llx\",\"device_type\":47}",
                   (unsigned long long)ft_device_id((IOHIDDeviceRef)values[i]));
        }
        fputs("]}\n", stdout);
        free(values);
        if (devices != NULL) CFRelease(devices);
        IOHIDManagerClose(manager, kIOHIDOptionsTypeNone);
        CFRelease(manager); return 0;
    }
    IOHIDDeviceRef device = ft_select_device(manager, device_id);
    if (manager_result != kIOReturnSuccess || device == NULL) {
        printf("{\"device_found\":false,\"manager_status\":%d}\n",
               manager_result);
        if (device != NULL) CFRelease(device);
        CFRelease(manager);
        return 1;
    }

    IOReturn open_result = IOHIDDeviceOpen(device, kIOHIDOptionsTypeNone);
    if (open_result != kIOReturnSuccess) {
        printf("{\"device_found\":true,\"open_status\":%d}\n", open_result);
        CFRelease(device);
        CFRelease(manager);
        return 1;
    }

    struct InputState state = {0};
    uint8_t callback_buffer[HID_REPORT_SIZE] = {0};
    IOHIDDeviceRegisterInputReportCallback(device, callback_buffer,
                                           sizeof(callback_buffer),
                                           input_report, &state);
    IOHIDDeviceScheduleWithRunLoop(device, CFRunLoopGetCurrent(),
                                   kCFRunLoopDefaultMode);

    static const uint8_t select_master_file[] = {
        0x00, 0xa4, 0x00, 0x00, 0x02, 0x3f, 0x00
    };
    uint8_t master_file_data[256];
    size_t master_file_length = 0;
    uint16_t master_file_status = 0;
    int master_file_result = apdu(
        device, &state, select_master_file, sizeof(select_master_file),
        master_file_data, sizeof(master_file_data), &master_file_length,
        &master_file_status);

    static const uint8_t enumerate_dfs[] = {
        0x80, 0xd9, 0x00, 0x00, 0x00
    };
    uint8_t df_list[256];
    size_t df_list_length = 0;
    uint16_t df_list_status = 0;
    int df_list_result = -1;
    if (master_file_result == kIOReturnSuccess &&
        master_file_status == 0x9000) {
        df_list_result = apdu(device, &state, enumerate_dfs,
                              sizeof(enumerate_dfs), df_list,
                              sizeof(df_list), &df_list_length,
                              &df_list_status);
    }

    static const uint8_t select_metadata[] = {
        0x00, 0xa4, 0x00, 0x00, 0x02, 0xf0, 0xff
    };
    uint8_t select_data[256];
    size_t select_length = 0;
    uint16_t select_status = 0;
    int select_result = -1;
    uint16_t selected_df = 0;
    if (df_list_result == kIOReturnSuccess && df_list_status == 0x9000) {
        for (size_t i = 0; i + 7 <= df_list_length; ++i) {
            if (memcmp(df_list + i, "DF_", 3) != 0) continue;
            int a = hex_nibble(df_list[i + 3]);
            int b = hex_nibble(df_list[i + 4]);
            int c = hex_nibble(df_list[i + 5]);
            int d = hex_nibble(df_list[i + 6]);
            if (a < 0 || b < 0 || c < 0 || d < 0) continue;
            uint16_t candidate = (uint16_t)((a << 12) | (b << 8) |
                                            (c << 4) | d);
            uint8_t select_df[] = {
                0x00, 0xa4, 0x00, 0x00, 0x02,
                (uint8_t)(candidate >> 8), (uint8_t)candidate
            };
            uint8_t df_data[256];
            size_t df_length = 0;
            uint16_t df_status = 0;
            int df_result = apdu(device, &state, select_df,
                                 sizeof(select_df), df_data, sizeof(df_data),
                                 &df_length, &df_status);
            if (df_result != kIOReturnSuccess || df_status != 0x9000) continue;

            select_length = 0;
            select_status = 0;
            select_result = apdu(device, &state, select_metadata,
                                 sizeof(select_metadata), select_data,
                                 sizeof(select_data), &select_length,
                                 &select_status);
            if (select_result == kIOReturnSuccess &&
                select_status == 0x9000) {
                selected_df = candidate;
                break;
            }
        }
    }

    uint8_t metadata[METADATA_SIZE];
    size_t metadata_length = 0;
    uint16_t read_status = 0;
    int read_result = -1;
    if (select_result == kIOReturnSuccess && select_status == 0x9000) {
        static const uint8_t read_metadata[] = {
            0x80, 0xb0, 0x00, 0x00, 0x00,
            (uint8_t)(METADATA_SIZE >> 8), (uint8_t)METADATA_SIZE
        };
        read_result = apdu(device, &state, read_metadata,
                           sizeof(read_metadata), metadata, sizeof(metadata),
                           &metadata_length, &read_status);
    }

    unsigned certificate_files = 0;
    unsigned certificate_count = 0;
    size_t certificate_bytes = 0;
    uint8_t certificate_ders[2][APDU_RESPONSE_MAX];
    size_t certificate_der_lengths[2] = {0, 0};
    uint16_t certificate_der_file_ids[2] = {0, 0};
    char certificate_diagnostics[512] = {0};
    size_t diagnostics_used = 0;
    char certificate_file_ids[128] = {0};
    size_t file_ids_used = 0;
    char container_diagnostics[512] = {0};
    size_t container_diagnostics_used = 0;
    if (read_result == kIOReturnSuccess && read_status == 0x9000 &&
        metadata_length == METADATA_SIZE) {
        for (size_t record = 0; record < 8; ++record) {
            size_t base = 0x80 + record * 0x4c;
            uint8_t key_type = metadata[base];
            if (key_type != 0x11 && key_type != 0x12 && key_type != 0x21) {
                continue;
            }
            int container_written = snprintf(
                container_diagnostics + container_diagnostics_used,
                sizeof(container_diagnostics) - container_diagnostics_used,
                "%zu:", record);
            if (container_written > 0 &&
                (size_t)container_written < sizeof(container_diagnostics) -
                                                container_diagnostics_used) {
                container_diagnostics_used += (size_t)container_written;
                for (size_t field = 0; field < 16; ++field) {
                    container_written = snprintf(
                        container_diagnostics + container_diagnostics_used,
                        sizeof(container_diagnostics) -
                            container_diagnostics_used,
                        "%02X", metadata[base + field]);
                    if (container_written <= 0 ||
                        (size_t)container_written >=
                            sizeof(container_diagnostics) -
                                container_diagnostics_used) {
                        break;
                    }
                    container_diagnostics_used += (size_t)container_written;
                }
                if (container_diagnostics_used + 1 <
                    sizeof(container_diagnostics)) {
                    container_diagnostics[container_diagnostics_used++] = ';';
                    container_diagnostics[container_diagnostics_used] = '\0';
                }
            }

            uint16_t file_ids[2] = {
                (uint16_t)(((uint16_t)metadata[base + 5] << 8) |
                           metadata[base + 6]),
                (uint16_t)(((uint16_t)metadata[base + 9] << 8) |
                           metadata[base + 10])
            };
            int file_present[2] = {
                metadata[base + 4] != 0xff,
                metadata[base + 8] != 0xff
            };
            for (size_t which = 0; which < 2; ++which) {
                if (!file_present[which]) continue;
                uint16_t file_id = file_ids[which];
                uint8_t select_certificate[] = {
                    0x00, 0xa4, 0x00, 0x00, 0x02,
                    (uint8_t)(file_id >> 8), (uint8_t)file_id
                };
                uint8_t fci[256];
                size_t fci_length = 0;
                uint16_t fci_status = 0;
                int fci_result = apdu(
                    device, &state, select_certificate,
                    sizeof(select_certificate), fci, sizeof(fci),
                    &fci_length, &fci_status);
                if (fci_result != kIOReturnSuccess || fci_status != 0x9000 ||
                    fci_length < 4 || fci[0] != 0x6f || fci[1] != 0x05) {
                    continue;
                }
                size_t file_length = ((size_t)fci[2] << 8) | fci[3];
                if (file_length < 3 || file_length > APDU_RESPONSE_MAX) {
                    continue;
                }

                uint8_t file_data[APDU_RESPONSE_MAX];
                if (read_binary_file(device, &state, file_data,
                                     file_length) != kIOReturnSuccess) {
                    continue;
                }
                int valid_der = certificate_is_der(
                    file_data + 2, file_length - 2);
                int written = snprintf(
                    certificate_diagnostics + diagnostics_used,
                    sizeof(certificate_diagnostics) - diagnostics_used,
                    "%04X:%zu:%02X%02X%02X%02X:%d;", file_id,
                    file_length, file_data[0], file_data[1], file_data[2],
                    file_data[3], valid_der);
                if (written > 0 &&
                    (size_t)written < sizeof(certificate_diagnostics) -
                                          diagnostics_used) {
                    diagnostics_used += (size_t)written;
                }
                if (valid_der) {
                    certificate_files++;
                    certificate_count++;
                    certificate_bytes += file_length - 2;
                    if (certificate_count <= 2) {
                        size_t index = certificate_count - 1;
                        certificate_der_lengths[index] = file_length - 2;
                        certificate_der_file_ids[index] = file_id;
                        memcpy(certificate_ders[index], file_data + 2,
                               certificate_der_lengths[index]);
                    }
                    int id_written = snprintf(
                        certificate_file_ids + file_ids_used,
                        sizeof(certificate_file_ids) - file_ids_used,
                        "%04X;", file_id);
                    if (id_written > 0 &&
                        (size_t)id_written <
                            sizeof(certificate_file_ids) - file_ids_used) {
                        file_ids_used += (size_t)id_written;
                    }
                }
            }
        }
    }

    printf("{\"device_found\":true,\"open_status\":0,"
           "\"master_file_transport_status\":%d,"
           "\"master_file_sw\":\"%04X\",\"master_file_bytes\":%zu,"
           "\"df_list_transport_status\":%d,\"df_list_sw\":\"%04X\","
           "\"df_list_bytes\":%zu,\"selected_df\":\"%04X\","
           "\"select_transport_status\":%d,\"select_sw\":\"%04X\","
           "\"select_bytes\":%zu,\"read_transport_status\":%d,"
           "\"read_sw\":\"%04X\",\"metadata_bytes\":%zu,"
           "\"certificate_files\":%u,\"certificate_count\":%u,"
           "\"certificate_bytes\":%zu,\"certificate_file_ids\":\"%s\","
           "\"certificate_diagnostics\":\"%s\","
           "\"container_diagnostics\":\"%s\"",
           master_file_result, master_file_status, master_file_length,
           df_list_result, df_list_status, df_list_length, selected_df,
           select_result, select_status, select_length, read_result,
           read_status, metadata_length, certificate_files,
           certificate_count, certificate_bytes, certificate_file_ids,
           certificate_diagnostics, container_diagnostics);
    printf(",\"device_id\":\"%llx\",\"device_type\":47",
           (unsigned long long)ft_device_id(device));
    if (include_certificate && certificate_der_lengths[0] != 0) {
        fputs(",\"certificate_base64\":\"", stdout);
        print_base64(certificate_ders[0], certificate_der_lengths[0]);
        putchar('"');
        fputs(",\"certificates\":[", stdout);
        for (size_t index = 0; index < 2; ++index) {
            if (certificate_der_lengths[index] == 0) continue;
            if (index != 0) putchar(',');
            printf("{\"file_id\":\"%04X\",\"encode\":\"",
                   certificate_der_file_ids[index]);
            print_base64(certificate_ders[index],
                         certificate_der_lengths[index]);
            fputs("\"}", stdout);
        }
        putchar(']');
    }
    fputs("}\n", stdout);

    IOHIDDeviceUnscheduleFromRunLoop(device, CFRunLoopGetCurrent(),
                                     kCFRunLoopDefaultMode);
    IOHIDDeviceClose(device, kIOHIDOptionsTypeNone);
    CFRelease(device);
    IOHIDManagerClose(manager, kIOHIDOptionsTypeNone);
    CFRelease(manager);
    return master_file_result == kIOReturnSuccess &&
                   master_file_status == 0x9000 &&
                   select_result == kIOReturnSuccess && select_status == 0x9000 &&
                   read_result == kIOReturnSuccess && read_status == 0x9000 &&
                   metadata_length == METADATA_SIZE && certificate_count > 0
               ? 0
               : 1;
}
