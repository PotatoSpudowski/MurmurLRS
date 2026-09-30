#include <cstdint>
#include <FHSS.h>
#include <unity.h>
extern "C" {
#include "murmur.h"
}

void setUp() {}
void tearDown() {}

void test_single_band_2g4_matches_dual_band_2g4_stream()
{
    const uint8_t key[16] = {1, 2, 3, 4};
    uint8_t fhssKey[16], peer[240];
    murmur_derive_fhss_key(key, fhssKey);
    // LR1121/LR2021 use domain 1 for their 80-channel 2.4 GHz band.
    murmur_fhss_fill_sequence(fhssKey, 1, peer, sizeof(peer), 80, 40);
    FHSSrandomiseFHSSsequenceSecure(key);
    TEST_ASSERT_EQUAL_UINT16(sizeof(peer), primaryBandCount);
    TEST_ASSERT_EQUAL_MEMORY(peer, FHSSsequence, sizeof(peer));
}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_single_band_2g4_matches_dual_band_2g4_stream);
    return UNITY_END();
}
