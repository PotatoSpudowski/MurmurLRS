#include "MurmurLink.h"
#if defined(MURMUR_ENCRYPT)
#include "vendor/SHA256.h"
#include "vendor/Crypto.h"
#if defined(PLATFORM_ESP32)
#include <esp_system.h>
#include <bootloader_random.h>
#elif defined(PLATFORM_ESP8266)
#include <ESP8266WiFi.h>
#endif

static uint8_t seed[32];
static uint64_t sequence;
static bool seeded;

void MurmurEntropyInit()
{
    // This is deliberately an early-boot operation, never a per-packet one.
    seeded = false;
#if defined(PLATFORM_ESP32)
    bootloader_random_enable();
    esp_fill_random(seed, sizeof(seed));
    bootloader_random_disable();
#elif defined(PLATFORM_ESP8266)
    // ESP8266's hardware RNG requires its RF subsystem to be awake. Never use
    // the WiFi-off PRNG to seed sessions. Do not persist or join a network.
    WiFi.persistent(false);
    WiFi.mode(WIFI_OFF);
    WiFi.forceSleepWake();
    if (!WiFi.mode(WIFI_STA)) return;
    WiFi.disconnect();
    delay(20);
    ESP.random(seed, sizeof(seed));
    WiFi.mode(WIFI_OFF);
#else
    return; // Native tests explicitly inject their deterministic fixture RNG.
#endif
    uint8_t nonzero = 0, different = 0;
    for (unsigned i = 0; i < sizeof(seed); ++i) {
        nonzero |= seed[i];
        different |= seed[i] ^ seed[i % 4];
    }
    seeded = nonzero && different;
    sequence = 0;
}

bool MurmurRandom(void *, uint8_t out[16])
{
    if (!seeded || sequence == UINT64_MAX) return false;
    uint8_t counter[8];
    ++sequence;
    for (unsigned i = 0; i < 8; ++i) counter[i] = sequence >> (i * 8);
    static const char domain[] = "MurmurLRS/challenge/v1";
    SHA256 hash;
    hash.resetHMAC(seed, sizeof(seed));
    hash.update(domain, sizeof(domain) - 1);
    hash.update(counter, sizeof(counter));
    hash.finalizeHMAC(seed, sizeof(seed), out, 16);
    return true;
}
#endif
