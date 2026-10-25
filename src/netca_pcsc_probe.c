/*
 * Read-only PC/SC capability probe for legacy NETCA-compatible USBKeys.
 *
 * This deliberately does not transmit APDUs, verify a PIN, sign, or write to
 * a token. It only asks macOS for registered readers and, where possible,
 * reads the ATR reported by PC/SC.
 */

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int32_t LONG;
typedef uint32_t DWORD;
typedef int32_t SCARDCONTEXT;
typedef int32_t SCARDHANDLE;

enum {
    SCARD_SCOPE_SYSTEM = 2,
    SCARD_SHARE_SHARED = 2,
    SCARD_PROTOCOL_T0 = 1,
    SCARD_PROTOCOL_T1 = 2,
    SCARD_LEAVE_CARD = 0,
    MAX_ATR_SIZE = 33
};

typedef LONG (*SCardEstablishContextFn)(DWORD, const void *, const void *, SCARDCONTEXT *);
typedef LONG (*SCardReleaseContextFn)(SCARDCONTEXT);
typedef LONG (*SCardListReadersFn)(SCARDCONTEXT, const char *, char *, DWORD *);
typedef LONG (*SCardConnectFn)(SCARDCONTEXT, const char *, DWORD, DWORD, SCARDHANDLE *, DWORD *);
typedef LONG (*SCardStatusFn)(SCARDHANDLE, char *, DWORD *, DWORD *, DWORD *, unsigned char *, DWORD *);
typedef LONG (*SCardDisconnectFn)(SCARDHANDLE, DWORD);

struct PcscApi {
    void *library;
    SCardEstablishContextFn establish_context;
    SCardReleaseContextFn release_context;
    SCardListReadersFn list_readers;
    SCardConnectFn connect;
    SCardStatusFn status;
    SCardDisconnectFn disconnect;
};

static void print_json_string(const char *value) {
    const unsigned char *p = (const unsigned char *)value;
    putchar('"');
    while (*p != '\0') {
        switch (*p) {
            case '"': fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\b': fputs("\\b", stdout); break;
            case '\f': fputs("\\f", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:
                if (*p < 0x20) {
                    printf("\\u%04x", *p);
                } else {
                    putchar(*p);
                }
        }
        ++p;
    }
    putchar('"');
}

static void print_hex(const unsigned char *bytes, DWORD length) {
    static const char digits[] = "0123456789ABCDEF";
    putchar('"');
    for (DWORD i = 0; i < length; ++i) {
        putchar(digits[(bytes[i] >> 4) & 0x0f]);
        putchar(digits[bytes[i] & 0x0f]);
    }
    putchar('"');
}

static int load_symbol(void *library, const char *name, void **target) {
    *target = dlsym(library, name);
    return *target != NULL;
}

static int load_pcsc(struct PcscApi *api) {
    static const char path[] =
        "/System/Library/Frameworks/PCSC.framework/Versions/A/PCSC";

    memset(api, 0, sizeof(*api));
    api->library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (api->library == NULL) {
        return 0;
    }

    return load_symbol(api->library, "SCardEstablishContext", (void **)&api->establish_context) &&
           load_symbol(api->library, "SCardReleaseContext", (void **)&api->release_context) &&
           load_symbol(api->library, "SCardListReaders", (void **)&api->list_readers) &&
           load_symbol(api->library, "SCardConnect", (void **)&api->connect) &&
           load_symbol(api->library, "SCardStatus", (void **)&api->status) &&
           load_symbol(api->library, "SCardDisconnect", (void **)&api->disconnect);
}

static void print_reader(struct PcscApi *api, SCARDCONTEXT context,
                         const char *reader, int *is_first) {
    SCARDHANDLE card = 0;
    DWORD active_protocol = 0;
    LONG result = api->connect(context, reader, SCARD_SHARE_SHARED,
                               SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                               &card, &active_protocol);

    if (!*is_first) {
        putchar(',');
    }
    *is_first = 0;

    fputs("{\"name\":", stdout);
    print_json_string(reader);
    printf(",\"connect_status\":%d", result);

    if (result == 0) {
        char reader_name[1024] = {0};
        DWORD reader_name_length = (DWORD)sizeof(reader_name);
        DWORD state = 0;
        DWORD protocol = 0;
        unsigned char atr[MAX_ATR_SIZE] = {0};
        DWORD atr_length = MAX_ATR_SIZE;
        LONG status_result = api->status(card, reader_name, &reader_name_length,
                                         &state, &protocol, atr, &atr_length);

        printf(",\"active_protocol\":%u,\"status_code\":%d",
               active_protocol, status_result);
        if (status_result == 0) {
            printf(",\"state\":%u,\"protocol\":%u,\"atr\":",
                   state, protocol);
            print_hex(atr, atr_length);
        }
        api->disconnect(card, SCARD_LEAVE_CARD);
    }

    putchar('}');
}

int main(void) {
    struct PcscApi api;
    if (!load_pcsc(&api)) {
        const char *error = dlerror();
        fputs("{\"pcsc_available\":false,\"error\":", stdout);
        print_json_string(error != NULL ? error : "PC/SC symbols unavailable");
        fputs(",\"readers\":[]}\n", stdout);
        return 2;
    }

    SCARDCONTEXT context = 0;
    LONG establish_result = api.establish_context(
        SCARD_SCOPE_SYSTEM, NULL, NULL, &context);

    if (establish_result != 0) {
        printf("{\"pcsc_available\":true,\"context_status\":%d,\"readers\":[]}\n",
               establish_result);
        dlclose(api.library);
        return 0;
    }

    DWORD readers_length = 0;
    LONG list_result = api.list_readers(context, NULL, NULL, &readers_length);

    printf("{\"pcsc_available\":true,\"context_status\":0,"
           "\"list_status\":%d,\"readers\":[", list_result);

    if (list_result == 0 && readers_length > 1) {
        char *readers = calloc(readers_length, 1);
        if (readers != NULL &&
            api.list_readers(context, NULL, readers, &readers_length) == 0) {
            int is_first = 1;
            for (const char *reader = readers; *reader != '\0';
                 reader += strlen(reader) + 1) {
                print_reader(&api, context, reader, &is_first);
            }
        }
        free(readers);
    }

    fputs("]}\n", stdout);
    api.release_context(context);
    dlclose(api.library);
    return 0;
}
