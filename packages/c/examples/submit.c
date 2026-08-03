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

    /* Step 2: Create sensor data payload.
     * MUST be JCS-canonical JSON: keys sorted, no insignificant whitespace,
     * or the device and attestor will compute different hashes. */
    const char* payload = "{\"humidity\":65,\"location\":\"office-1\",\"temperature\":23.4}";
    printf("Payload: %s\n\n", payload);

    /* Step 3: Timestamp + per-submission random salt (both bound into the hash) */
    uint64_t ts = lcore_timestamp();
    char salt[33];
    ret = lcore_random_salt_hex(salt, sizeof(salt));
    if (ret != LCORE_OK) {
        printf("Error generating salt: %d\n", ret);
        return 1;
    }

    /* Step 4: Compute the salted data_hash and sign the hash (not the payload) */
    char data_hash[65];
    ret = lcore_compute_data_hash(payload, did, ts, salt, data_hash, sizeof(data_hash));
    if (ret != LCORE_OK) {
        printf("Error computing data_hash: %d\n", ret);
        return 1;
    }

    char jws[4096];
    ret = lcore_create_jws_over_hash(data_hash, DEVICE_PRIVKEY, jws, sizeof(jws));
    if (ret != LCORE_OK) {
        printf("Error creating JWS: %d\n", ret);
        return 1;
    }
    printf("JWS: %.50s...\n\n", jws);

    /* Step 5: Submit to attestor (same ts + salt that went into the hash) */
    printf("Submitting to %s...\n", attestor_url);
    ret = lcore_submit(attestor_url, did, payload, jws, ts, salt);
    if (ret != LCORE_OK) {
        printf("Error submitting: %d\n", ret);
        printf("(Make sure attestor is running and curl is enabled)\n");
        return 1;
    }

    printf("Success!\n");
    return 0;
}
