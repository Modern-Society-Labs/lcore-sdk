/**
 * L{CORE} Minimal C SDK Implementation
 *
 * ~300 lines of C for did:key + JWS + HTTP submission
 */

#include "lcore/lcore.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* MbedTLS includes */
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>

/* Optional: libcurl for HTTP */
#ifdef LCORE_USE_CURL
#include <curl/curl.h>
#endif

/* ============================================================================
 * Base58btc Encoding (Bitcoin alphabet)
 * ============================================================================ */

static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int lcore_base58btc_encode(const uint8_t* data, size_t data_len, char* out, size_t out_size) {
    if (!data || !out || out_size == 0) return LCORE_ERR_INVALID;

    /* Count leading zeros */
    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0) zeros++;

    /* Allocate enough space for base58 result */
    size_t size = (data_len - zeros) * 138 / 100 + 1;
    uint8_t* buf = calloc(size, 1);
    if (!buf) return LCORE_ERR_BUFFER;

    /* Convert to base58 */
    for (size_t i = zeros; i < data_len; i++) {
        int carry = data[i];
        for (size_t j = 0; j < size; j++) {
            carry += 256 * buf[size - 1 - j];
            buf[size - 1 - j] = carry % 58;
            carry /= 58;
        }
    }

    /* Skip leading zeros in base58 result */
    size_t start = 0;
    while (start < size && buf[start] == 0) start++;

    /* Output: leading '1's for zero bytes + encoded data */
    size_t out_len = zeros + (size - start);
    if (out_len >= out_size) {
        free(buf);
        return LCORE_ERR_BUFFER;
    }

    for (size_t i = 0; i < zeros; i++) out[i] = '1';
    for (size_t i = 0; i < size - start; i++) {
        out[zeros + i] = BASE58_ALPHABET[buf[start + i]];
    }
    out[out_len] = '\0';

    free(buf);
    return (int)out_len;
}

/* ============================================================================
 * Base64url Encoding (no padding)
 * ============================================================================ */

int lcore_base64url_encode(const uint8_t* data, size_t data_len, char* out, size_t out_size) {
    if (!data || !out) return LCORE_ERR_INVALID;

    size_t olen = 0;
    int ret = mbedtls_base64_encode((unsigned char*)out, out_size, &olen, data, data_len);
    if (ret != 0) return LCORE_ERR_BUFFER;

    /* Convert to base64url and remove padding */
    for (size_t i = 0; i < olen; i++) {
        if (out[i] == '+') out[i] = '-';
        else if (out[i] == '/') out[i] = '_';
        else if (out[i] == '=') { out[i] = '\0'; break; }
    }

    return (int)strlen(out);
}

/* ============================================================================
 * did:key Generation
 * ============================================================================ */

/* Multicodec prefix for secp256k1-pub: 0xe7 0x01 */
static const uint8_t SECP256K1_MULTICODEC[2] = { 0xe7, 0x01 };

int lcore_did_from_pubkey(const uint8_t pubkey[33], char* did_out, size_t did_size) {
    if (!pubkey || !did_out) return LCORE_ERR_INVALID;
    if (did_size < 64) return LCORE_ERR_BUFFER;

    /* Prepend multicodec prefix to public key */
    uint8_t multicodec_key[35];
    memcpy(multicodec_key, SECP256K1_MULTICODEC, 2);
    memcpy(multicodec_key + 2, pubkey, 33);

    /* Base58btc encode */
    char encoded[64];
    int len = lcore_base58btc_encode(multicodec_key, 35, encoded, sizeof(encoded));
    if (len < 0) return len;

    /* Format as did:key:z<encoded> */
    int written = snprintf(did_out, did_size, "did:key:z%s", encoded);
    if (written < 0 || (size_t)written >= did_size) return LCORE_ERR_BUFFER;

    return LCORE_OK;
}

int lcore_did_from_privkey(const uint8_t privkey[32], char* did_out, size_t did_size) {
    if (!privkey || !did_out) return LCORE_ERR_INVALID;

    /* Initialize MbedTLS */
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret = LCORE_ERR_CRYPTO;

    /* Seed RNG (required for side-channel protection in ecp_mul) */
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) goto cleanup;

    /* Load secp256k1 curve */
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) goto cleanup;

    /* Import private key */
    if (mbedtls_mpi_read_binary(&d, privkey, 32) != 0) goto cleanup;

    /* Compute public key: Q = d * G (RNG needed for side-channel protection) */
    if (mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) goto cleanup;

    /* Export compressed public key (33 bytes) */
    uint8_t pubkey[33];
    size_t pubkey_len = 0;
    if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED,
                                        &pubkey_len, pubkey, sizeof(pubkey)) != 0) goto cleanup;

    /* Generate did:key from public key */
    ret = lcore_did_from_pubkey(pubkey, did_out, did_size);

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

/* ============================================================================
 * JWS Creation (ES256K - ECDSA with secp256k1)
 * ============================================================================ */

int lcore_create_jws(const char* payload_json, const uint8_t privkey[32],
                     char* jws_out, size_t jws_size) {
    if (!payload_json || !privkey || !jws_out) return LCORE_ERR_INVALID;

    /* JWS header for ES256K */
    const char* header = "{\"alg\":\"ES256K\",\"typ\":\"JWS\"}";

    /* Base64url encode header */
    char header_b64[128];
    int header_len = lcore_base64url_encode((const uint8_t*)header, strlen(header),
                                            header_b64, sizeof(header_b64));
    if (header_len < 0) return header_len;

    /* Base64url encode payload */
    char payload_b64[2048];
    int payload_len = lcore_base64url_encode((const uint8_t*)payload_json, strlen(payload_json),
                                             payload_b64, sizeof(payload_b64));
    if (payload_len < 0) return payload_len;

    /* Create signing input: header.payload */
    char signing_input[4096];
    int input_len = snprintf(signing_input, sizeof(signing_input), "%s.%s", header_b64, payload_b64);
    if (input_len < 0 || (size_t)input_len >= sizeof(signing_input)) return LCORE_ERR_BUFFER;

    /* SHA256 hash of signing input */
    uint8_t hash[32];
    mbedtls_sha256((const uint8_t*)signing_input, input_len, hash, 0);

    /* Initialize ECP group and MPI for key */
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret = LCORE_ERR_CRYPTO;

    /* Seed random number generator */
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) goto cleanup;

    /* Load secp256k1 curve */
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) goto cleanup;

    /* Import private key */
    if (mbedtls_mpi_read_binary(&d, privkey, 32) != 0) goto cleanup;

    /* Sign hash */
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, 32,
                           mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        goto cleanup;
    }

    /* Normalize s to low-s form (s <= n/2) for compatibility with strict verifiers
     * If s > n/2, replace s with n - s
     * secp256k1 n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 */
    mbedtls_mpi half_n;
    mbedtls_mpi_init(&half_n);
    mbedtls_mpi_copy(&half_n, &grp.N);
    mbedtls_mpi_shift_r(&half_n, 1);  /* half_n = n / 2 */

    if (mbedtls_mpi_cmp_mpi(&s, &half_n) > 0) {
        /* s = n - s */
        mbedtls_mpi_sub_mpi(&s, &grp.N, &s);
    }
    mbedtls_mpi_free(&half_n);

    /* Export signature as 64-byte r||s */
    uint8_t signature[64];
    mbedtls_mpi_write_binary(&r, signature, 32);
    mbedtls_mpi_write_binary(&s, signature + 32, 32);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    /* Base64url encode signature */
    char sig_b64[128];
    int sig_len = lcore_base64url_encode(signature, 64, sig_b64, sizeof(sig_b64));
    if (sig_len < 0) { ret = sig_len; goto cleanup; }

    /* Assemble JWS: header.payload.signature */
    int jws_len = snprintf(jws_out, jws_size, "%s.%s.%s", header_b64, payload_b64, sig_b64);
    if (jws_len < 0 || (size_t)jws_len >= jws_size) { ret = LCORE_ERR_BUFFER; goto cleanup; }

    ret = LCORE_OK;

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

/* ============================================================================
 * HTTP Submission
 * ============================================================================ */

uint64_t lcore_timestamp(void) {
    return (uint64_t)time(NULL);
}

#ifdef LCORE_USE_CURL

int lcore_submit(const char* attestor_url, const char* did,
                 const char* payload_json, const char* jws) {
    if (!attestor_url || !did || !payload_json || !jws) return LCORE_ERR_INVALID;

    /* Build endpoint URL */
    char url[512];
    snprintf(url, sizeof(url), "%s/api/device/submit", attestor_url);

    /* Build JSON body */
    char body[8192];
    uint64_t ts = lcore_timestamp();
    int body_len = snprintf(body, sizeof(body),
        "{\"did\":\"%s\",\"payload\":%s,\"signature\":\"%s\",\"timestamp\":%llu}",
        did, payload_json, jws, (unsigned long long)ts);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) return LCORE_ERR_BUFFER;

    /* Initialize curl */
    CURL* curl = curl_easy_init();
    if (!curl) return LCORE_ERR_HTTP;

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? LCORE_OK : LCORE_ERR_HTTP;
}

#else

/* Stub when curl is not available */
int lcore_submit(const char* attestor_url, const char* did,
                 const char* payload_json, const char* jws) {
    (void)attestor_url; (void)did; (void)payload_json; (void)jws;
    /* User must implement HTTP POST or compile with -DLCORE_USE_CURL */
    return LCORE_ERR_HTTP;
}

#endif /* LCORE_USE_CURL */

/* ============================================================================
 * Convenience Function
 * ============================================================================ */

int lcore_sign_and_submit(const char* attestor_url, const uint8_t privkey[32],
                          const char* payload_json) {
    if (!attestor_url || !privkey || !payload_json) return LCORE_ERR_INVALID;

    /* Generate DID */
    char did[128];
    int ret = lcore_did_from_privkey(privkey, did, sizeof(did));
    if (ret != LCORE_OK) return ret;

    /* Create JWS */
    char jws[4096];
    ret = lcore_create_jws(payload_json, privkey, jws, sizeof(jws));
    if (ret != LCORE_OK) return ret;

    /* Submit */
    return lcore_submit(attestor_url, did, payload_json, jws);
}
