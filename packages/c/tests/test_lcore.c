/**
 * L{CORE} C SDK Tests
 *
 * Tests for DID generation and JWS creation.
 * Run: ./build/test_lcore
 */

#include <lcore/lcore.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Test private key (32 bytes) */
static const uint8_t TEST_PRIVKEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/* Track test results */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        printf("  Testing %s... ", #name); \
        tests_run++; \
        if (test_##name()) { \
            printf("PASS\n"); \
            tests_passed++; \
        } else { \
            printf("FAIL\n"); \
        } \
    } while(0)

/* ============================================================================
 * DID Tests
 * ============================================================================ */

static int test_did_from_privkey_returns_ok(void) {
    char did[128];
    int ret = lcore_did_from_privkey(TEST_PRIVKEY, did, sizeof(did));
    return ret == LCORE_OK;
}

static int test_did_starts_with_prefix(void) {
    char did[128];
    lcore_did_from_privkey(TEST_PRIVKEY, did, sizeof(did));
    return strncmp(did, "did:key:z", 9) == 0;
}

static int test_did_is_deterministic(void) {
    char did1[128], did2[128];
    lcore_did_from_privkey(TEST_PRIVKEY, did1, sizeof(did1));
    lcore_did_from_privkey(TEST_PRIVKEY, did2, sizeof(did2));
    return strcmp(did1, did2) == 0;
}

static int test_different_keys_different_dids(void) {
    uint8_t key2[32];
    memcpy(key2, TEST_PRIVKEY, 32);
    key2[0] = 0xff;  /* Change first byte */

    char did1[128], did2[128];
    lcore_did_from_privkey(TEST_PRIVKEY, did1, sizeof(did1));
    lcore_did_from_privkey(key2, did2, sizeof(did2));
    return strcmp(did1, did2) != 0;
}

static int test_did_rejects_null_input(void) {
    char did[128];
    int ret = lcore_did_from_privkey(NULL, did, sizeof(did));
    return ret == LCORE_ERR_INVALID;
}

static int test_did_rejects_small_buffer(void) {
    char did[10];  /* Too small */
    int ret = lcore_did_from_privkey(TEST_PRIVKEY, did, sizeof(did));
    return ret == LCORE_ERR_BUFFER;
}

/* ============================================================================
 * JWS Tests
 * ============================================================================ */

static int test_jws_returns_ok(void) {
    const char* payload = "{\"test\":true}";
    char jws[2048];
    int ret = lcore_create_jws(payload, TEST_PRIVKEY, jws, sizeof(jws));
    return ret == LCORE_OK;
}

static int test_jws_has_three_parts(void) {
    const char* payload = "{\"test\":true}";
    char jws[2048];
    lcore_create_jws(payload, TEST_PRIVKEY, jws, sizeof(jws));

    /* Count dots */
    int dots = 0;
    for (size_t i = 0; i < strlen(jws); i++) {
        if (jws[i] == '.') dots++;
    }
    return dots == 2;
}

static int test_jws_is_deterministic(void) {
    /* Note: ECDSA signatures include randomness, so same input may produce
     * different signatures. This test just verifies the format is consistent. */
    const char* payload = "{\"test\":true}";
    char jws1[2048], jws2[2048];
    lcore_create_jws(payload, TEST_PRIVKEY, jws1, sizeof(jws1));
    lcore_create_jws(payload, TEST_PRIVKEY, jws2, sizeof(jws2));

    /* Headers should be identical (first part before first dot) */
    char* dot1 = strchr(jws1, '.');
    char* dot2 = strchr(jws2, '.');
    if (!dot1 || !dot2) return 0;

    size_t header_len1 = dot1 - jws1;
    size_t header_len2 = dot2 - jws2;
    if (header_len1 != header_len2) return 0;

    return strncmp(jws1, jws2, header_len1) == 0;
}

static int test_jws_different_payloads_different_signatures(void) {
    char jws1[2048], jws2[2048];
    lcore_create_jws("{\"a\":1}", TEST_PRIVKEY, jws1, sizeof(jws1));
    lcore_create_jws("{\"b\":2}", TEST_PRIVKEY, jws2, sizeof(jws2));
    return strcmp(jws1, jws2) != 0;
}

static int test_jws_rejects_null_payload(void) {
    char jws[2048];
    int ret = lcore_create_jws(NULL, TEST_PRIVKEY, jws, sizeof(jws));
    return ret == LCORE_ERR_INVALID;
}

static int test_jws_rejects_null_key(void) {
    char jws[2048];
    int ret = lcore_create_jws("{\"test\":true}", NULL, jws, sizeof(jws));
    return ret == LCORE_ERR_INVALID;
}

/* ============================================================================
 * Base64url Tests
 * ============================================================================ */

static int test_base64url_encode_simple(void) {
    const uint8_t data[] = "hello";
    char out[32];
    int len = lcore_base64url_encode(data, 5, out, sizeof(out));
    /* "hello" -> "aGVsbG8" in base64url */
    return len > 0 && strcmp(out, "aGVsbG8") == 0;
}

static int test_base64url_no_padding(void) {
    const uint8_t data[] = "a";  /* Would have "==" padding in base64 */
    char out[32];
    int len = lcore_base64url_encode(data, 1, out, sizeof(out));
    /* Should not contain '=' */
    return len > 0 && strchr(out, '=') == NULL;
}

/* ============================================================================
 * Base58btc Tests
 * ============================================================================ */

static int test_base58btc_encode_simple(void) {
    const uint8_t data[] = { 0x00, 0x00, 0x01 };
    char out[32];
    int len = lcore_base58btc_encode(data, 3, out, sizeof(out));
    /* Leading zeros become '1's in base58 */
    return len > 0 && out[0] == '1' && out[1] == '1';
}

/* ============================================================================
 * Timestamp Tests
 * ============================================================================ */

static int test_timestamp_is_reasonable(void) {
    uint64_t ts = lcore_timestamp();
    /* Should be after 2024-01-01 and before 2030-01-01 */
    return ts > 1704067200 && ts < 1893456000;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("\nL{CORE} C SDK Tests\n");
    printf("===================\n\n");

    printf("DID Tests:\n");
    TEST(did_from_privkey_returns_ok);
    TEST(did_starts_with_prefix);
    TEST(did_is_deterministic);
    TEST(different_keys_different_dids);
    TEST(did_rejects_null_input);
    TEST(did_rejects_small_buffer);

    printf("\nJWS Tests:\n");
    TEST(jws_returns_ok);
    TEST(jws_has_three_parts);
    TEST(jws_is_deterministic);
    TEST(jws_different_payloads_different_signatures);
    TEST(jws_rejects_null_payload);
    TEST(jws_rejects_null_key);

    printf("\nBase64url Tests:\n");
    TEST(base64url_encode_simple);
    TEST(base64url_no_padding);

    printf("\nBase58btc Tests:\n");
    TEST(base58btc_encode_simple);

    printf("\nTimestamp Tests:\n");
    TEST(timestamp_is_reasonable);

    printf("\n===================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
