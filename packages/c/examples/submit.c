/**
 * L{CORE} C SDK Example: Submit Sensor Data
 *
 * Demonstrates signing and submitting sensor data to the attestor.
 *
 * Build:
 *   cmake -B build -DLCORE_USE_CURL=ON
 *   cmake --build build
 *
 * Run:
 *   ./build/example_submit
 */

#include <lcore/lcore.h>
#include <stdio.h>
#include <string.h>

/* Example device private key (32 bytes) */
/* WARNING: In production, use secure key storage! */
static const uint8_t DEVICE_PRIVKEY[32] = {
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89
};

int main(int argc, char** argv) {
    const char* attestor_url = "http://localhost:8001";

    /* Allow overriding attestor URL via command line */
    if (argc > 1) {
        attestor_url = argv[1];
    }

    printf("L{CORE} C SDK Example\n");
    printf("=====================\n\n");

    /* Step 1: Generate DID from private key */
    char did[128];
    int ret = lcore_did_from_privkey(DEVICE_PRIVKEY, did, sizeof(did));
    if (ret != LCORE_OK) {
        printf("Error generating DID: %d\n", ret);
        return 1;
    }
    printf("Device DID: %s\n\n", did);

    /* Step 2: Create sensor data payload */
    const char* payload = "{\"temperature\":23.4,\"humidity\":65,\"location\":\"office-1\"}";
    printf("Payload: %s\n\n", payload);

    /* Step 3: Create JWS signature */
    char jws[4096];
    ret = lcore_create_jws(payload, DEVICE_PRIVKEY, jws, sizeof(jws));
    if (ret != LCORE_OK) {
        printf("Error creating JWS: %d\n", ret);
        return 1;
    }
    printf("JWS: %.50s...\n\n", jws);

    /* Step 4: Submit to attestor */
    printf("Submitting to %s...\n", attestor_url);
    ret = lcore_submit(attestor_url, did, payload, jws);
    if (ret != LCORE_OK) {
        printf("Error submitting: %d\n", ret);
        printf("(Make sure attestor is running and curl is enabled)\n");
        return 1;
    }

    printf("Success!\n");
    return 0;
}
