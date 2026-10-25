#ifndef FT3000GM_DEVICES_H
#define FT3000GM_DEVICES_H
#include <IOKit/IOKitLib.h>

/* Registry entry IDs identify this attachment, not a stable token serial.
 * A replug receives a new identity, invalidating any in-memory PIN lease. */
static uint64_t ft_device_id(IOHIDDeviceRef device) {
    uint64_t identifier = 0;
    io_service_t service = IOHIDDeviceGetService(device);
    if (service != IO_OBJECT_NULL)
        IORegistryEntryGetRegistryEntryID(service, &identifier);
    return identifier;
}

static IOHIDDeviceRef ft_select_device(IOHIDManagerRef manager, uint64_t wanted) {
    CFSetRef devices = IOHIDManagerCopyDevices(manager);
    CFIndex count = devices == NULL ? 0 : CFSetGetCount(devices);
    IOHIDDeviceRef selected = NULL;
    const void **values = count > 0 ? calloc((size_t)count, sizeof(*values)) : NULL;
    if (values != NULL) {
        CFSetGetValues(devices, values);
        for (CFIndex i = 0; i < count; i++) {
            IOHIDDeviceRef device = (IOHIDDeviceRef)values[i];
            if ((wanted != 0 && ft_device_id(device) == wanted) ||
                (wanted == 0 && count == 1)) {
                selected = device;
                CFRetain(selected);
                break;
            }
        }
        free(values);
    }
    if (devices != NULL) CFRelease(devices);
    return selected;
}

static int ft_parse_device_id(const char *text, uint64_t *value) {
    if (text == NULL || strlen(text) == 0 || strlen(text) > 16) return 0;
    for (const char *p = text; *p; p++)
        if (!( (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
               (*p >= 'A' && *p <= 'F') )) return 0;
    *value = strtoull(text, NULL, 16);
    return *value != 0;
}
#endif
