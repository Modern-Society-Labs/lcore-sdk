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
 * Usage (convenience — handles salt, hash, and signing for you):
 *   uint8_t privkey[32] = { ... };  // Your device private key
 *   // payload MUST be JCS-canonical JSON: keys sorted, no extra whitespace
 *   const char* payload = "{\"humidity\":65,\"temperature\":23.4}";
 *   lcore_sign_and_submit("http://localhost:8001", privkey, payload);
 *
 * Or step-by-step:
 *   char did[128];  lcore_did_from_privkey(privkey, did, sizeof(did));
 *   uint64_t ts = lcore_timestamp();
 *   char salt[33]; lcore_random_salt_hex(salt, sizeof(salt));
 *   char hash[65]; lcore_compute_data_hash(payload, did, ts, salt, hash, sizeof(hash));
 *   char jws[4096]; lcore_create_jws_over_hash(hash, privkey, jws, sizeof(jws));
 *   lcore_submit("http://localhost:8001", did, payload, jws, ts, salt);
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
#define LCORE_ERR_TLS        -5

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
 * Create JWS compact serialization (ES256K) over an arbitrary string.
 *
 * NOTE: For device submissions, do NOT sign the raw payload — the attestor
 * verifies the JWS over the salted data_hash. Use lcore_create_jws_over_hash
 * (or lcore_sign_and_submit) instead. This function is kept as the low-level
 * signer that both paths build on.
 *
 * @param payload_json  String to sign (base64url-encoded into the JWS payload)
 * @param privkey       32-byte secp256k1 private key
 * @param jws_out       Output buffer for JWS string
 * @param jws_size      Size of output buffer
 * @return              LCORE_OK on success, error code on failure
 */
int lcore_create_jws(const char* payload_json, const uint8_t privkey[32],
                     char* jws_out, size_t jws_size);

/**
 * Generate a per-submission random salt as lowercase hex (16 bytes -> 32 chars).
 *
 * @param salt_hex_out  Output buffer for the hex salt (NUL-terminated)
 * @param size          Size of output buffer (must be >= 33)
 * @return              LCORE_OK on success, error code on failure
 */
int lcore_random_salt_hex(char* salt_hex_out, size_t size);

/**
 * Compute the deterministic, salted data_hash the attestor verifies:
 *   data_hash = sha256( payload_json + did + timestamp + salt_hex )
 *
 * IMPORTANT: payload_json MUST be RFC 8785 (JCS) canonical JSON — keys sorted,
 * no insignificant whitespace — or the hash will not match the attestor's.
 * This minimal SDK does not parse/canonicalize JSON; that is the caller's job.
 *
 * @param payload_json  Canonical JSON payload string
 * @param did           Device DID string (did:key:z...)
 * @param timestamp     Unix timestamp (must match the value submitted)
 * @param salt_hex      Hex salt from lcore_random_salt_hex
 * @param hash_out      Output buffer for the 64-char hex hash (NUL-terminated)
 * @param hash_size     Size of output buffer (must be >= 65)
 * @return              LCORE_OK on success, error code on failure
 */
int lcore_compute_data_hash(const char* payload_json, const char* did,
                            uint64_t timestamp, const char* salt_hex,
                            char* hash_out, size_t hash_size);

/**
 * Create a JWS (ES256K) whose payload segment is the data_hash string.
 * This is what the attestor's verifyJWSOverHash checks.
 *
 * @param hash_hex   The data_hash string to sign (64-char hex)
 * @param privkey    32-byte secp256k1 private key
 * @param jws_out    Output buffer for JWS string
 * @param jws_size   Size of output buffer
 * @return           LCORE_OK on success, error code on failure
 */
int lcore_create_jws_over_hash(const char* hash_hex, const uint8_t privkey[32],
                               char* jws_out, size_t jws_size);

/**
 * Submit signed device data to L{CORE} attestor.
 *
 * Sends POST request to /api/device/submit with:
 *   { "did": "...", "payload": {...}, "signature": "...",
 *     "timestamp": ..., "salt": "..." }
 *
 * timestamp and salt_hex MUST be the same values folded into the signed
 * data_hash, or the attestor rejects the JWS.
 *
 * @param attestor_url  Base URL of attestor (e.g., "http://localhost:8001")
 * @param did           Device DID string (did:key:z...)
 * @param payload_json  Canonical JSON payload that was signed
 * @param jws           JWS signature string (over the data_hash)
 * @param timestamp     Unix timestamp used in the hash
 * @param salt_hex      Hex salt used in the hash (32 chars)
 * @return              LCORE_OK on success, error code on failure
 */
int lcore_submit(const char* attestor_url, const char* did,
                 const char* payload_json, const char* jws,
                 uint64_t timestamp, const char* salt_hex);

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

/* ============================================================================
 * TLS configuration
 *
 * When the attestor URL uses https://, transports verify the server certificate
 * against a CA certificate you supply. Sensor data and device DIDs would
 * otherwise travel in the clear, and a JWS signature protects against tampering
 * but NOT against disclosure or replay.
 *
 * If an https:// URL is used and neither a CA certificate nor the explicit
 * insecure opt-in has been set, submission fails with LCORE_ERR_TLS rather than
 * silently falling back to plaintext.
 * ============================================================================ */

/**
 * Set the PEM-encoded CA certificate used to verify the attestor's certificate.
 * The string is stored by pointer and must remain valid for the program's
 * lifetime (a string literal in flash is ideal on embedded targets).
 *
 * @param pem  PEM-encoded CA certificate, or NULL to clear
 * @return     LCORE_OK on success
 */
int lcore_set_ca_cert(const char* pem);

/**
 * Allow TLS without certificate verification. DEVELOPMENT ONLY — this accepts
 * any certificate and provides no protection against an active attacker.
 *
 * @param allow  non-zero to permit unverified TLS
 */
void lcore_tls_allow_insecure(int allow);

/** Get the configured CA certificate, or NULL if unset. (Used by transports.) */
const char* lcore_get_ca_cert(void);

/** Non-zero if unverified TLS has been explicitly permitted. (Used by transports.) */
int lcore_tls_insecure_allowed(void);

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
