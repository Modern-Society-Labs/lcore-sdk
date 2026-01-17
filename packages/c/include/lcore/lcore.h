/**
 * L{CORE} Minimal C SDK
 *
 * Minimal SDK for IoT devices to submit signed sensor data to L{CORE} attestor.
 *
 * Features:
 *   - did:key generation (secp256k1 + multicodec + base58btc)
 *   - JWS creation (ES256K algorithm)
 *   - HTTP POST to attestor endpoint
 *
 * Dependencies:
 *   - MbedTLS 3.x (secp256k1, SHA256)
 *   - libcurl (optional, for HTTP)
 *
 * Usage:
 *   uint8_t privkey[32] = { ... };  // Your device private key
 *
 *   // Generate DID from private key
 *   char did[128];
 *   lcore_did_from_privkey(privkey, did, sizeof(did));
 *
 *   // Sign sensor data
 *   const char* payload = "{\"temperature\":23.4}";
 *   char jws[1024];
 *   lcore_create_jws(payload, privkey, jws, sizeof(jws));
 *
 *   // Submit to attestor
 *   lcore_submit("http://localhost:8001", did, payload, jws);
 */

#ifndef LCORE_H
#define LCORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define LCORE_OK              0
#define LCORE_ERR_INVALID    -1
#define LCORE_ERR_BUFFER     -2
#define LCORE_ERR_CRYPTO     -3
#define LCORE_ERR_HTTP       -4

/**
 * Generate did:key string from secp256k1 private key.
 *
 * @param privkey   32-byte secp256k1 private key
 * @param did_out   Output buffer for did:key string
 * @param did_size  Size of output buffer (recommend 128 bytes)
 * @return          LCORE_OK on success, error code on failure
 */
int lcore_did_from_privkey(const uint8_t privkey[32], char* did_out, size_t did_size);

/**
 * Generate did:key string from secp256k1 compressed public key.
 *
 * @param pubkey    33-byte compressed secp256k1 public key
 * @param did_out   Output buffer for did:key string
 * @param did_size  Size of output buffer (recommend 128 bytes)
 * @return          LCORE_OK on success, error code on failure
 */
int lcore_did_from_pubkey(const uint8_t pubkey[33], char* did_out, size_t did_size);

/**
 * Create JWS compact serialization (ES256K algorithm).
 *
 * @param payload_json  JSON payload string to sign
 * @param privkey       32-byte secp256k1 private key
 * @param jws_out       Output buffer for JWS string
 * @param jws_size      Size of output buffer
 * @return              LCORE_OK on success, error code on failure
 */
int lcore_create_jws(const char* payload_json, const uint8_t privkey[32],
                     char* jws_out, size_t jws_size);

/**
 * Submit signed device data to L{CORE} attestor.
 *
 * Sends POST request to /api/device/submit with:
 *   { "did": "...", "payload": {...}, "signature": "...", "timestamp": ... }
 *
 * @param attestor_url  Base URL of attestor (e.g., "http://localhost:8001")
 * @param did           Device DID string (did:key:z...)
 * @param payload_json  JSON payload that was signed
 * @param jws           JWS signature string
 * @return              LCORE_OK on success, error code on failure
 */
int lcore_submit(const char* attestor_url, const char* did,
                 const char* payload_json, const char* jws);

/**
 * Convenience function: sign and submit in one call.
 *
 * @param attestor_url  Base URL of attestor
 * @param privkey       32-byte secp256k1 private key
 * @param payload_json  JSON payload to sign and submit
 * @return              LCORE_OK on success, error code on failure
 */
int lcore_sign_and_submit(const char* attestor_url, const uint8_t privkey[32],
                          const char* payload_json);

/* Utility functions */

/**
 * Get current Unix timestamp.
 */
uint64_t lcore_timestamp(void);

/**
 * Base58btc encode data (with 'z' multibase prefix for did:key).
 *
 * @param data      Input data
 * @param data_len  Length of input data
 * @param out       Output buffer
 * @param out_size  Size of output buffer
 * @return          Length of encoded string, or negative on error
 */
int lcore_base58btc_encode(const uint8_t* data, size_t data_len,
                           char* out, size_t out_size);

/**
 * Base64url encode data (no padding).
 *
 * @param data      Input data
 * @param data_len  Length of input data
 * @param out       Output buffer
 * @param out_size  Size of output buffer
 * @return          Length of encoded string, or negative on error
 */
int lcore_base64url_encode(const uint8_t* data, size_t data_len,
                           char* out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* LCORE_H */
