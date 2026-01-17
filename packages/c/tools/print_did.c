/**
 * Simple tool to print DID for a given private key.
 * Used for cross-SDK compatibility testing.
 *
 * Build: cc -o print_did print_did.c ../build/liblcore.a -I../include -lmbedtls -lmbedcrypto
 */

#include <lcore/lcore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Default test key (same as test_lcore.c) */
static const uint8_t DEFAULT_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

int hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;

    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

int main(int argc, char** argv) {
    uint8_t privkey[32];

    if (argc > 1) {
        /* Parse hex key from command line */
        if (hex_to_bytes(argv[1], privkey, 32) != 0) {
            fprintf(stderr, "Invalid hex key (need 64 hex chars)\n");
            return 1;
        }
    } else {
        /* Use default test key */
        memcpy(privkey, DEFAULT_KEY, 32);
    }

    char did[128];
    int ret = lcore_did_from_privkey(privkey, did, sizeof(did));
    if (ret != LCORE_OK) {
        fprintf(stderr, "Error: %d\n", ret);
        return 1;
    }

    printf("%s\n", did);
    return 0;
}
