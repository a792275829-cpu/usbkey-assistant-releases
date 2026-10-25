/*
 * Read-only USB registry probe for known NETCA-compatible USBKeys.
 *
 * This only reads device descriptors from IOKit. It never opens an interface,
 * sends a USB transfer, verifies a PIN, signs, or writes to the token.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdint.h>
#include <stdio.h>

struct KnownDevice {
    uint32_t vendor_id;
    uint32_t product_id;
    const char *model;
};

static const struct KnownDevice known_devices[] = {
    {0x096e, 0x0317, "FT USB TOKEN 3000GM"},
    {0x2fd0, 0x1000, "DingXin SKF token (installer fallback)"},
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

static int read_number(io_registry_entry_t service, CFStringRef key,
                       uint32_t *value) {
    CFTypeRef property = IORegistryEntryCreateCFProperty(
        service, key, kCFAllocatorDefault, 0);
    if (property == NULL || CFGetTypeID(property) != CFNumberGetTypeID()) {
        if (property != NULL) {
            CFRelease(property);
        }
        return 0;
    }

    int32_t signed_value = 0;
    Boolean ok = CFNumberGetValue((CFNumberRef)property,
                                  kCFNumberSInt32Type, &signed_value);
    CFRelease(property);
    if (!ok) {
        return 0;
    }
    *value = (uint32_t)signed_value;
    return 1;
}

static void read_string(io_registry_entry_t service, CFStringRef key,
                        char *buffer, size_t buffer_size) {
    buffer[0] = '\0';
    CFTypeRef property = IORegistryEntryCreateCFProperty(
        service, key, kCFAllocatorDefault, 0);
    if (property != NULL && CFGetTypeID(property) == CFStringGetTypeID()) {
        CFStringGetCString((CFStringRef)property, buffer,
                           (CFIndex)buffer_size, kCFStringEncodingUTF8);
    }
    if (property != NULL) {
        CFRelease(property);
    }
}

static const char *known_model(uint32_t vendor_id, uint32_t product_id) {
    size_t count = sizeof(known_devices) / sizeof(known_devices[0]);
    for (size_t i = 0; i < count; ++i) {
        if (known_devices[i].vendor_id == vendor_id &&
            known_devices[i].product_id == product_id) {
            return known_devices[i].model;
        }
    }
    return NULL;
}

int main(void) {
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBHostDevice");
    if (matching == NULL) {
        fputs("{\"iokit_available\":false,\"devices\":[]}\n", stdout);
        return 2;
    }

    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t result = IOServiceGetMatchingServices(
        kIOMainPortDefault, matching, &iterator);
    printf("{\"iokit_available\":true,\"match_status\":%d,\"devices\":[",
           result);

    int first = 1;
    if (result == KERN_SUCCESS) {
        io_registry_entry_t service;
        while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
            uint32_t vendor_id = 0;
            uint32_t product_id = 0;
            if (read_number(service, CFSTR("idVendor"), &vendor_id) &&
                read_number(service, CFSTR("idProduct"), &product_id)) {
                const char *model = known_model(vendor_id, product_id);
                if (model != NULL) {
                    char product[512];
                    char manufacturer[512];
                    read_string(service, CFSTR("USB Product Name"), product,
                                sizeof(product));
                    read_string(service, CFSTR("USB Vendor Name"), manufacturer,
                                sizeof(manufacturer));

                    if (!first) {
                        putchar(',');
                    }
                    first = 0;
                    printf("{\"vendor_id\":\"%04X\",\"product_id\":\"%04X\","
                           "\"known_model\":", vendor_id, product_id);
                    print_json_string(model);
                    fputs(",\"product\":", stdout);
                    print_json_string(product);
                    fputs(",\"manufacturer\":", stdout);
                    print_json_string(manufacturer);
                    putchar('}');
                }
            }
            IOObjectRelease(service);
        }
    }

    fputs("]}\n", stdout);
    if (iterator != IO_OBJECT_NULL) {
        IOObjectRelease(iterator);
    }
    return 0;
}
