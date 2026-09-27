#pragma once
#include "targets.h"
#if defined(MURMUR_ENCRYPT)
#if defined(PLATFORM_ESP8266)
#include <interrupts.h>
#endif
// One shared recursive critical section protects keys and the small mailboxes.
// Never hold it during handshake HMAC/HKDF or hardware RNG calls.
#if defined(PLATFORM_ESP32)
extern portMUX_TYPE murmurMux;
#endif
class MurmurLock {
public:
    __attribute__((always_inline)) MurmurLock() {
#if defined(PLATFORM_ESP32)
        portENTER_CRITICAL(&murmurMux);
#endif
    }
    __attribute__((always_inline)) ~MurmurLock() {
#if defined(PLATFORM_ESP32)
        portEXIT_CRITICAL(&murmurMux);
#endif
    }
private:
#if defined(PLATFORM_ESP8266)
    esp8266::InterruptLock lock_;
#endif
};
#endif
