/*
 * FT USB TOKEN 3000GM protected signing helper for macOS.
 *
 * Secret input is accepted only on stdin. Protected operations receive PIN
 * then Base64 data; authenticated-session reuse receives Base64 data only.
 *
 * The helper never prints the PIN, challenge response, derived key, encrypted
 * PIN proof, or data being signed. Its stdout is a single JSON object.
 *
 * Protocol notes recovered from FT3000GMProv.dll 4.3.22.124:
 *   - DF external authentication: GET CHALLENGE followed by 00 82 01 00 08
 *   - GET CHALLENGE: 00 84 00 00 08
 *   - PIN key: MD5(PIN bytes)
 *   - PIN proof: two-key 3DES-ECB(challenge), no padding
 *   - VERIFY user PIN: 00 20 00 00 08 || proof
 *   - RSA sign:    00 2A 80 86 Lc 80 01 01 21 || EM
 *   - RSA decrypt: 00 2A 80 86 Lc 82 01 02 22 || ciphertext
 */

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <IOKit/hid/IOHIDManager.h>
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
    MAX_SECRET_LINE = 16384
};

struct InputState {
    uint8_t report[HID_REPORT_SIZE];
    CFIndex report_length;
    int ready;
};

struct DeviceSession {
    IOHIDManagerRef manager;
    IOHIDDeviceRef device;
    struct InputState input;
    uint8_t callback_buffer[HID_REPORT_SIZE];
    uint16_t selected_df;
};

static void wipe(void *value, size_t length) {
    volatile uint8_t *cursor = value;
    while (cursor != NULL && length-- != 0) *cursor++ = 0;
}

static void input_report(void *context, IOReturn result, void *sender,
                         IOHIDReportType type, uint32_t report_id,
                         uint8_t *report, CFIndex report_length) {
    (void)sender;
    (void)type;
    (void)report_id;
    struct InputState *state = context;
    if (result != kIOReturnSuccess || report_length <= 0) return;
    if (report_length > HID_REPORT_SIZE) report_length = HID_REPORT_SIZE;
    memcpy(state->report, report, (size_t)report_length);
    state->report_length = report_length;
    state->ready = 1;
}

static CFMutableDictionaryRef make_matching(void) {
    CFMutableDictionaryRef matching = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (matching == NULL) return NULL;

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
    if (request_length > UINT16_MAX) return kIOReturnBadArgument;
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
        wipe(report, sizeof(report));
        if (result != kIOReturnSuccess) return result;
        offset += chunk;
    }

    size_t total = 0;
    size_t received = 0;
    do {
        IOReturn result = wait_for_report(state, 3.0);
        if (result != kIOReturnSuccess) return result;
        if (state->report_length < 6) return kIOReturnUnderrun;
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

static int apdu(struct DeviceSession *session, const uint8_t *command,
                size_t command_length, uint8_t *data, size_t data_capacity,
                size_t *data_length, uint16_t *status_word) {
    uint8_t response[APDU_RESPONSE_MAX];
    size_t response_length = 0;
    IOReturn result = hid_exchange(session->device, &session->input, command,
                                   command_length, response, sizeof(response),
                                   &response_length);
    if (result != kIOReturnSuccess || response_length < 2) {
        wipe(response, sizeof(response));
        return result == kIOReturnSuccess ? kIOReturnUnderrun : result;
    }
    size_t payload_length = response_length - 2;
    if (payload_length > data_capacity) {
        wipe(response, sizeof(response));
        return kIOReturnNoSpace;
    }
    if (data != NULL && payload_length != 0) {
        memcpy(data, response, payload_length);
    }
    *data_length = payload_length;
    *status_word = (uint16_t)(((uint16_t)response[payload_length] << 8) |
                             response[payload_length + 1]);
    wipe(response, sizeof(response));
    return kIOReturnSuccess;
}

static int hex_nibble(uint8_t value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static void close_session(struct DeviceSession *session) {
    if (session->device != NULL) {
        IOHIDDeviceUnscheduleFromRunLoop(session->device,
                                         CFRunLoopGetCurrent(),
                                         kCFRunLoopDefaultMode);
        IOHIDDeviceClose(session->device, kIOHIDOptionsTypeNone);
        CFRelease(session->device);
    }
    if (session->manager != NULL) {
        IOHIDManagerClose(session->manager, kIOHIDOptionsTypeNone);
        CFRelease(session->manager);
    }
    wipe(session, sizeof(*session));
}

static int open_session(struct DeviceSession *session, uint64_t device_id) {
    memset(session, 0, sizeof(*session));
    session->manager = IOHIDManagerCreate(kCFAllocatorDefault,
                                          kIOHIDOptionsTypeNone);
    CFMutableDictionaryRef matching = make_matching();
    if (session->manager == NULL || matching == NULL) {
        if (matching != NULL) CFRelease(matching);
        return kIOReturnNoResources;
    }
    IOHIDManagerSetDeviceMatching(session->manager, matching);
    CFRelease(matching);
    IOReturn result = IOHIDManagerOpen(session->manager,
                                       kIOHIDOptionsTypeNone);
    if (result != kIOReturnSuccess) return result;
    session->device = ft_select_device(session->manager, device_id);
    if (session->device == NULL) return kIOReturnNotFound;
    result = IOHIDDeviceOpen(session->device, kIOHIDOptionsTypeNone);
    if (result != kIOReturnSuccess) return result;
    IOHIDDeviceRegisterInputReportCallback(
        session->device, session->callback_buffer,
        sizeof(session->callback_buffer), input_report, &session->input);
    IOHIDDeviceScheduleWithRunLoop(session->device, CFRunLoopGetCurrent(),
                                   kCFRunLoopDefaultMode);

    static const uint8_t select_mf[] = {
        0x00, 0xa4, 0x00, 0x00, 0x02, 0x3f, 0x00
    };
    uint8_t data[512];
    size_t length = 0;
    uint16_t sw = 0;
    result = apdu(session, select_mf, sizeof(select_mf), data, sizeof(data),
                  &length, &sw);
    if (result != kIOReturnSuccess || sw != 0x9000) return kIOReturnError;

    static const uint8_t list_dfs[] = {0x80, 0xd9, 0x00, 0x00, 0x00};
    length = 0;
    sw = 0;
    result = apdu(session, list_dfs, sizeof(list_dfs), data, sizeof(data),
                  &length, &sw);
    if (result != kIOReturnSuccess || sw != 0x9000) return kIOReturnError;

    for (size_t i = 0; i + 7 <= length; ++i) {
        if (memcmp(data + i, "DF_", 3) != 0) continue;
        int a = hex_nibble(data[i + 3]);
        int b = hex_nibble(data[i + 4]);
        int c = hex_nibble(data[i + 5]);
        int d = hex_nibble(data[i + 6]);
        if (a < 0 || b < 0 || c < 0 || d < 0) continue;
        uint16_t candidate = (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
        uint8_t select_df[] = {
            0x00, 0xa4, 0x00, 0x00, 0x02,
            (uint8_t)(candidate >> 8), (uint8_t)candidate
        };
        size_t selected_length = 0;
        uint16_t selected_sw = 0;
        result = apdu(session, select_df, sizeof(select_df), data,
                      sizeof(data), &selected_length, &selected_sw);
        if (result == kIOReturnSuccess && selected_sw == 0x9000) {
            session->selected_df = candidate;
            return kIOReturnSuccess;
        }
    }
    return kIOReturnNotFound;
}

static int decode_base64(const char *text, uint8_t *output,
                         size_t output_capacity, size_t *output_length) {
    static const int8_t table[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
    };
    size_t used = 0;
    uint32_t accumulator = 0;
    unsigned bits = 0;
    int padding = 0;
    for (const unsigned char *cursor = (const unsigned char *)text;
         *cursor != '\0'; ++cursor) {
        if (*cursor == '=') {
            padding = 1;
            continue;
        }
        if (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' ||
            *cursor == '\n') continue;
        if (padding || (table[*cursor] == 0 && *cursor != 'A')) return 0;
        accumulator = (accumulator << 6) | (uint8_t)table[*cursor];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (used >= output_capacity) return 0;
            output[used++] = (uint8_t)(accumulator >> bits);
            accumulator &= bits == 0 ? 0 : ((1u << bits) - 1u);
        }
    }
    *output_length = used;
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

static int read_secret_line(char **line, size_t *capacity) {
    ssize_t count = getline(line, capacity, stdin);
    if (count < 0 || count > MAX_SECRET_LINE) return 0;
    while (count > 0 && ((*line)[count - 1] == '\n' ||
                         (*line)[count - 1] == '\r')) {
        (*line)[--count] = '\0';
    }
    return count > 0;
}

static int encrypt_2key_3des_ecb(const uint8_t key16[16],
                                 const uint8_t input[8],
                                 uint8_t output[8]) {
    uint8_t key24[24];
    memcpy(key24, key16, 16);
    memcpy(key24 + 16, key16, 8);
    size_t output_length = 0;
    CCCryptorStatus crypto = CCCrypt(
        kCCEncrypt, kCCAlgorithm3DES, kCCOptionECBMode, key24, sizeof(key24),
        NULL, input, 8, output, 8, &output_length);
    wipe(key24, sizeof(key24));
    return crypto == kCCSuccess && output_length == 8;
}

static int authenticate_df_master_key(struct DeviceSession *session,
                                      uint16_t *auth_sw) {
    static const uint8_t master_key[16] = {
        0x63, 0x1b, 0x51, 0xfc, 0x70, 0xe6, 0xd8, 0xc5,
        0x0a, 0xf8, 0x23, 0x3a, 0xe0, 0x8d, 0xf2, 0x6f
    };
    static const uint8_t get_challenge[] = {0x00, 0x84, 0x00, 0x00, 0x08};
    uint8_t challenge[8] = {0};
    size_t challenge_length = 0;
    uint16_t sw = 0;
    int result = apdu(session, get_challenge, sizeof(get_challenge), challenge,
                      sizeof(challenge), &challenge_length, &sw);
    if (result != kIOReturnSuccess || sw != 0x9000 ||
        challenge_length != sizeof(challenge)) {
        *auth_sw = sw;
        wipe(challenge, sizeof(challenge));
        return 0;
    }

    uint8_t proof[8] = {0};
    int encrypted = encrypt_2key_3des_ecb(master_key, challenge, proof);
    wipe(challenge, sizeof(challenge));
    if (!encrypted) {
        wipe(proof, sizeof(proof));
        return 0;
    }

    uint8_t authenticate[13] = {0x00, 0x82, 0x01, 0x00, 0x08};
    memcpy(authenticate + 5, proof, sizeof(proof));
    wipe(proof, sizeof(proof));
    uint8_t response[8] = {0};
    size_t response_length = 0;
    sw = 0;
    result = apdu(session, authenticate, sizeof(authenticate), response,
                  sizeof(response), &response_length, &sw);
    *auth_sw = sw;
    wipe(authenticate, sizeof(authenticate));
    wipe(response, sizeof(response));
    return result == kIOReturnSuccess && sw == 0x9000;
}

static int verify_user_pin(struct DeviceSession *session, const char *pin,
                           int *retries, uint16_t *verify_sw) {
    static const uint8_t get_challenge[] = {0x00, 0x84, 0x00, 0x00, 0x08};
    uint8_t challenge[8] = {0};
    size_t challenge_length = 0;
    uint16_t sw = 0;
    int result = apdu(session, get_challenge, sizeof(get_challenge), challenge,
                      sizeof(challenge), &challenge_length, &sw);
    if (result != kIOReturnSuccess || sw != 0x9000 ||
        challenge_length != sizeof(challenge)) {
        wipe(challenge, sizeof(challenge));
        return 0;
    }

    uint8_t md5[CC_MD5_DIGEST_LENGTH];
    uint8_t proof[8];
    CC_MD5(pin, (CC_LONG)strlen(pin), md5);
    int encrypted = encrypt_2key_3des_ecb(md5, challenge, proof);
    wipe(challenge, sizeof(challenge));
    wipe(md5, sizeof(md5));
    if (!encrypted) {
        wipe(proof, sizeof(proof));
        return 0;
    }

    uint8_t verify[13] = {0x00, 0x20, 0x00, 0x00, 0x08};
    memcpy(verify + 5, proof, sizeof(proof));
    wipe(proof, sizeof(proof));
    uint8_t response[8];
    size_t response_length = 0;
    sw = 0;
    result = apdu(session, verify, sizeof(verify), response,
                  sizeof(response), &response_length, &sw);
    wipe(verify, sizeof(verify));
    wipe(response, sizeof(response));
    *verify_sw = sw;
    *retries = -1;
    if ((sw & 0xfff0) == 0x63c0) *retries = sw & 0x000f;
    if (sw == 0x6983) *retries = 0;
    return result == kIOReturnSuccess && sw == 0x9000;
}

static int read_user_pin_retries(struct DeviceSession *session, int *retries,
                                 uint16_t *status_word) {
    /* DeviceGetPwdRetryNum(type=1), recovered from FT3000GMProv.dll. */
    static const uint8_t command[] = {0x80, 0xfc, 0x04, 0x0b, 0x01};
    uint8_t response[8] = {0};
    size_t response_length = 0;
    int result = apdu(session, command, sizeof(command), response,
                      sizeof(response), &response_length, status_word);
    *retries = -1;
    if (result == kIOReturnSuccess && *status_word == 0x9000 &&
        response_length >= 1) {
        *retries = response[0] & 0x0f;
    }
    wipe(response, sizeof(response));
    return result == kIOReturnSuccess && *status_word == 0x9000 &&
           *retries >= 0;
}

static int rsa_private_operation(struct DeviceSession *session,
                                 int decrypt,
                                 const uint8_t *digest_info,
                                 size_t digest_info_length,
                                 uint8_t *signature,
                                 size_t signature_capacity,
                                 size_t *signature_length,
                                 uint16_t *signature_sw) {
    enum { RSA_MODULUS_BYTES = 256, PKCS1_MIN_PADDING_BYTES = 8 };
    if ((decrypt && digest_info_length != RSA_MODULUS_BYTES) ||
        (!decrypt && (digest_info_length == 0 ||
        digest_info_length > RSA_MODULUS_BYTES - 3 - PKCS1_MIN_PADDING_BYTES))) {
        return 0;
    }

    uint8_t encoded_message[RSA_MODULUS_BYTES];
    if (decrypt) {
        memcpy(encoded_message, digest_info, sizeof(encoded_message));
    } else {
    size_t padding_length = RSA_MODULUS_BYTES - digest_info_length - 3;
    encoded_message[0] = 0x00;
    encoded_message[1] = 0x01;
    memset(encoded_message + 2, 0xff, padding_length);
    encoded_message[2 + padding_length] = 0x00;
    memcpy(encoded_message + 3 + padding_length, digest_info,
           digest_info_length);
    }

    size_t body_length = sizeof(encoded_message) + 4;
    size_t header_length = body_length < 256 ? 5 : 7;
    size_t command_length = header_length + body_length;
    uint8_t *command = calloc(command_length, 1);
    if (command == NULL) {
        wipe(encoded_message, sizeof(encoded_message));
        return 0;
    }
    command[0] = 0x00;
    command[1] = 0x2a;
    command[2] = 0x80;
    command[3] = 0x86;
    if (body_length < 256) {
        command[4] = (uint8_t)body_length;
    } else {
        command[4] = 0x00;
        command[5] = (uint8_t)(body_length >> 8);
        command[6] = (uint8_t)body_length;
    }
    size_t offset = header_length;
    /* FT3000GMProv DevicePrivateKeyDecrypt -> 0x1000b290:
     * 82 container-id encryption-key-id 22, followed by the RSA ciphertext.
     * Supported container metadata: id 01, signature key 01, encryption key 02.
     */
    command[offset++] = decrypt ? 0x82 : 0x80;
    command[offset++] = 0x01;
    command[offset++] = decrypt ? 0x02 : 0x01;
    command[offset++] = decrypt ? 0x22 : 0x21;
    memcpy(command + offset, encoded_message, sizeof(encoded_message));
    wipe(encoded_message, sizeof(encoded_message));
    int result = apdu(session, command, command_length, signature,
                      signature_capacity, signature_length, signature_sw);
    wipe(command, command_length);
    free(command);
    return result == kIOReturnSuccess && *signature_sw == 0x9000;
}

int main(int argc, char **argv) {
    uint64_t device_id = 0;
    if (argc == 4 && strcmp(argv[2], "--device-id") == 0 &&
        ft_parse_device_id(argv[3], &device_id)) argc = 2;
    int status_only = argc == 2 && strcmp(argv[1], "--status") == 0;
    int pin_status = argc == 2 && strcmp(argv[1], "--pin-status") == 0;
    int auth_status = argc == 2 && strcmp(argv[1], "--df-auth-status") == 0;
    int sign = argc == 2 && strcmp(argv[1], "--sign-digest-info") == 0;
    int decrypt_with_pin = argc == 2 &&
        strcmp(argv[1], "--decrypt-rsa-block") == 0;
    int decrypt_without_pin = argc == 2 &&
        strcmp(argv[1], "--decrypt-rsa-block-no-pin") == 0;
    int decrypt = decrypt_with_pin || decrypt_without_pin;
    int sign_without_pin = argc == 2 &&
        strcmp(argv[1], "--sign-digest-info-no-pin") == 0;
    if (!status_only && !pin_status && !auth_status && !sign &&
        !sign_without_pin && !decrypt) {
        fputs("{\"error\":\"usage: ft3000gm-signer --status | "
              "--pin-status | --df-auth-status | --sign-digest-info | "
              "--sign-digest-info-no-pin | --decrypt-rsa-block | "
              "--decrypt-rsa-block-no-pin\"}\n",
              stdout);
        return 2;
    }

    if (acquire_device_lock() < 0) {
        fputs("{\"device_found\":false,\"error\":\"USBKey device lock unavailable\"}\n", stdout);
        return 1;
    }

    struct DeviceSession session;
    int open_result = open_session(&session, device_id);
    if (open_result != kIOReturnSuccess) {
        printf("{\"device_found\":false,\"transport_status\":%d}\n",
               open_result);
        close_session(&session);
        return 1;
    }
    if (status_only) {
        printf("{\"device_found\":true,\"ready\":true,"
               "\"selected_df\":\"%04X\"}\n", session.selected_df);
        close_session(&session);
        return 0;
    }
    if (pin_status) {
        int retries = -1;
        uint16_t pin_status_sw = 0;
        int status_ok = read_user_pin_retries(&session, &retries,
                                              &pin_status_sw);
        printf("{\"device_found\":true,\"pin_status_read\":%s,"
               "\"pin_status_sw\":\"%04X\",\"retries\":%d}\n",
               status_ok ? "true" : "false", pin_status_sw, retries);
        close_session(&session);
        return status_ok ? 0 : 1;
    }
    if (auth_status) {
        uint16_t auth_sw = 0;
        int authenticated = authenticate_df_master_key(&session, &auth_sw);
        printf("{\"device_found\":true,\"df_authenticated\":%s,"
               "\"auth_sw\":\"%04X\"}\n",
               authenticated ? "true" : "false", auth_sw);
        close_session(&session);
        return authenticated ? 0 : 1;
    }

    char *pin = NULL;
    char *encoded = NULL;
    size_t pin_capacity = 0;
    size_t encoded_capacity = 0;
    int needs_user_pin = sign || decrypt_with_pin;
    int valid_input = needs_user_pin
        ? read_secret_line(&pin, &pin_capacity) &&
          read_secret_line(&encoded, &encoded_capacity)
        : read_secret_line(&encoded, &encoded_capacity);
    if (!valid_input) {
        fputs("{\"device_found\":true,\"error\":\"invalid stdin\"}\n",
              stdout);
        wipe(pin, pin_capacity);
        wipe(encoded, encoded_capacity);
        free(pin);
        free(encoded);
        close_session(&session);
        return 2;
    }

    uint8_t digest_info[1024];
    size_t digest_info_length = 0;
    if (!decode_base64(encoded, digest_info, sizeof(digest_info),
                       &digest_info_length)) {
        fputs("{\"device_found\":true,\"error\":\"invalid data\"}\n",
              stdout);
        wipe(pin, pin_capacity);
        wipe(encoded, encoded_capacity);
        wipe(digest_info, sizeof(digest_info));
        free(pin);
        free(encoded);
        close_session(&session);
        return 2;
    }
    wipe(encoded, encoded_capacity);
    free(encoded);

    uint16_t auth_sw = 0;
    int authenticated = authenticate_df_master_key(&session, &auth_sw);
    if (!authenticated) {
        printf("{\"device_found\":true,\"df_authenticated\":false,"
               "\"auth_sw\":\"%04X\"}\n", auth_sw);
        wipe(pin, pin_capacity);
        wipe(digest_info, sizeof(digest_info));
        free(pin);
        close_session(&session);
        return 3;
    }

    if (needs_user_pin) {
        int retries = -1;
        uint16_t verify_sw = 0;
        int verified = verify_user_pin(&session, pin, &retries, &verify_sw);
        wipe(pin, pin_capacity);
        free(pin);
        pin = NULL;
        if (!verified) {
            printf("{\"device_found\":true,\"pin_verified\":false,"
                   "\"verify_sw\":\"%04X\",\"retries\":%d}\n",
                   verify_sw, retries);
            wipe(digest_info, sizeof(digest_info));
            close_session(&session);
            return 3;
        }
    }

    uint8_t signature[512];
    size_t signature_length = 0;
    uint16_t signature_sw = 0;
    int signed_ok = rsa_private_operation(
        &session, decrypt, digest_info, digest_info_length, signature,
        sizeof(signature), &signature_length, &signature_sw);
    wipe(digest_info, sizeof(digest_info));
    if (!signed_ok) {
        printf("{\"device_found\":true,\"pin_verified\":%s,"
               "\"signed\":false,\"signature_sw\":\"%04X\"}\n",
               needs_user_pin ? "true" : "null", signature_sw);
        wipe(signature, sizeof(signature));
        close_session(&session);
        return 4;
    }

    printf("{\"device_found\":true,\"pin_verified\":%s,"
           "\"%s\":true,\"%s\":\"",
           needs_user_pin ? "true" : "null",
           decrypt ? "decrypted" : "signed",
           decrypt ? "rsa_block_base64" : "signature_base64");
    print_base64(signature, signature_length);
    printf("\",\"signature_bytes\":%zu}\n", signature_length);
    wipe(signature, sizeof(signature));
    close_session(&session);
    return 0;
}
