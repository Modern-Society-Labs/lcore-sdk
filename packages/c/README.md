# L{CORE} C SDK

Minimal C SDK for IoT devices to submit signed sensor data to L{CORE} attestor.

## Features

- **did:key generation** - secp256k1 + multicodec + base58btc
- **JWS creation** - ES256K algorithm (ECDSA with secp256k1)
- **HTTP submission** - POST to `/api/device/submit`
- **~300 lines of C** - minimal, auditable, portable

## Dependencies

| Library | Purpose | Required |
|---------|---------|----------|
| MbedTLS 3.x | secp256k1, SHA256, base64 | Yes |
| libcurl | HTTP client | Optional |

## Build

```bash
cd packages/c

# With curl (recommended)
cmake -B build -DLCORE_USE_CURL=ON
cmake --build build

# Without curl (HTTP stub - implement your own)
cmake -B build -DLCORE_USE_CURL=OFF
cmake --build build
```

## Usage

```c
#include <lcore/lcore.h>

int main() {
    // Your device's 32-byte secp256k1 private key
    uint8_t privkey[32] = { /* ... */ };

    // Sensor data as JSON
    const char* payload = "{\"temperature\":23.4,\"humidity\":65}";

    // Option 1: One-liner
    int ret = lcore_sign_and_submit("http://localhost:8001", privkey, payload);

    // Option 2: Step by step
    char did[128];
    lcore_did_from_privkey(privkey, did, sizeof(did));

    char jws[4096];
    lcore_create_jws(payload, privkey, jws, sizeof(jws));

    lcore_submit("http://localhost:8001", did, payload, jws);

    return 0;
}
```

## API Reference

### Core Functions

```c
// Generate did:key from private key
int lcore_did_from_privkey(const uint8_t privkey[32], char* did_out, size_t did_size);

// Generate did:key from public key
int lcore_did_from_pubkey(const uint8_t pubkey[33], char* did_out, size_t did_size);

// Create JWS signature
int lcore_create_jws(const char* payload_json, const uint8_t privkey[32],
                     char* jws_out, size_t jws_size);

// Submit to attestor
int lcore_submit(const char* attestor_url, const char* did,
                 const char* payload_json, const char* jws);

// Convenience: sign and submit in one call
int lcore_sign_and_submit(const char* attestor_url, const uint8_t privkey[32],
                          const char* payload_json);
```

### Error Codes

| Code | Value | Description |
|------|-------|-------------|
| `LCORE_OK` | 0 | Success |
| `LCORE_ERR_INVALID` | -1 | Invalid parameters |
| `LCORE_ERR_BUFFER` | -2 | Buffer too small |
| `LCORE_ERR_CRYPTO` | -3 | Cryptographic error |
| `LCORE_ERR_HTTP` | -4 | HTTP request failed |

## Platform Support

| Platform | Status | HTTP Transport |
|----------|--------|----------------|
| Linux (x86_64) | ✅ Tested | libcurl |
| Linux (ARM64) | ✅ Tested | libcurl |
| macOS | ✅ Tested | libcurl |
| ESP32 (ESP-IDF) | ✅ Supported | esp_http_client |
| ESP8266 (Arduino) | ✅ Supported | ESP8266HTTPClient |
| Arduino (WiFi) | ✅ Supported | HTTPClient / ArduinoHttpClient |

## ESP32 (ESP-IDF)

For ESP32 using ESP-IDF framework:

```bash
# In your ESP-IDF project, add lcore as a component
cp -r packages/c components/lcore

# Or reference it in your CMakeLists.txt
set(EXTRA_COMPONENT_DIRS "/path/to/lcore-sdk/packages/c")
```

**CMakeLists.txt** for ESP-IDF component:
```cmake
idf_component_register(
    SRCS "src/lcore.c" "src/transport_esp32.c"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls esp_http_client
)
target_compile_definitions(${COMPONENT_LIB} PRIVATE LCORE_PLATFORM_ESP32)
```

**Example usage:**
```c
#include "lcore/lcore.h"

void submit_sensor_data(void) {
    uint8_t privkey[32] = { /* from NVS or secure storage */ };
    const char* payload = "{\"temperature\":23.4}";

    int ret = lcore_sign_and_submit("http://your-attestor:8001", privkey, payload);
    if (ret == LCORE_OK) {
        ESP_LOGI("app", "Submission successful");
    }
}
```

## Arduino (ESP8266/ESP32/WiFi boards)

For Arduino IDE or PlatformIO:

1. Copy `include/lcore/lcore.h`, `src/lcore.c`, and `src/transport_arduino.cpp` to your project
2. Install dependencies:
   - **ESP8266**: Built-in `ESP8266WiFi` and `ESP8266HTTPClient`
   - **ESP32 Arduino**: Built-in `WiFi` and `HTTPClient`
   - **Other boards**: `WiFi` + `ArduinoHttpClient` library

**platformio.ini:**
```ini
[env:esp32]
platform = espressif32
board = esp32dev
framework = arduino
build_flags = -DLCORE_PLATFORM_ARDUINO
lib_deps =
    ; ArduinoHttpClient (only needed for non-ESP boards)
```

**Example sketch:**
```cpp
#include <WiFi.h>  // or ESP8266WiFi.h
#include "lcore/lcore.h"

const uint8_t DEVICE_KEY[32] = { /* your key */ };

void setup() {
    Serial.begin(115200);
    WiFi.begin("SSID", "password");
    while (WiFi.status() != WL_CONNECTED) delay(500);
}

void loop() {
    const char* payload = "{\"temperature\":23.4}";
    int ret = lcore_sign_and_submit("http://attestor:8001", DEVICE_KEY, payload);
    Serial.printf("Submit result: %d\n", ret);
    delay(60000);  // Submit every minute
}
```

## Without libcurl (Custom HTTP)

If you can't use libcurl (embedded systems), compile without it and implement HTTP yourself:

```c
// Compile without curl
cmake -B build -DLCORE_USE_CURL=OFF

// In your code, call lcore functions for DID/JWS, then POST manually:
char did[128];
lcore_did_from_privkey(privkey, did, sizeof(did));

char jws[4096];
lcore_create_jws(payload, privkey, jws, sizeof(jws));

// Build JSON body yourself
char body[8192];
snprintf(body, sizeof(body),
    "{\"did\":\"%s\",\"payload\":%s,\"signature\":\"%s\",\"timestamp\":%llu}",
    did, payload, jws, (unsigned long long)lcore_timestamp());

// POST to /api/device/submit using your HTTP library
your_http_post(attestor_url, "/api/device/submit", body);
```

## Security Notes

- **Key Storage**: Use platform-specific secure storage (ARM TrustZone, secure enclave, etc.)
- **Transport**: Always use HTTPS in production
- **Timestamps**: Server rejects timestamps >5 minutes from current time

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        C SDK (~300 lines)                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Device Key (secp256k1)  +  Sensor Data (JSON)                │
│            │                        │                           │
│            ▼                        ▼                           │
│   ┌─────────────────────────────────────────────┐              │
│   │  lcore_did_from_privkey()                   │              │
│   │  → Compute public key                        │              │
│   │  → Prepend multicodec (0xe7 0x01)           │              │
│   │  → Base58btc encode                          │              │
│   │  → "did:key:zQ3sh..."                       │              │
│   └─────────────────────────────────────────────┘              │
│                      │                                          │
│                      ▼                                          │
│   ┌─────────────────────────────────────────────┐              │
│   │  lcore_create_jws()                         │              │
│   │  → Header: {"alg":"ES256K","typ":"JWS"}     │              │
│   │  → Base64url(header).Base64url(payload)    │              │
│   │  → SHA256 → secp256k1_sign                  │              │
│   │  → "eyJhbGci..."                            │              │
│   └─────────────────────────────────────────────┘              │
│                      │                                          │
│                      ▼                                          │
│   ┌─────────────────────────────────────────────┐              │
│   │  lcore_submit()                             │              │
│   │  → POST /api/device/submit                  │              │
│   │  → { did, payload, signature, timestamp }   │              │
│   └─────────────────────────────────────────────┘              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    Attestor Server
                    (Verifies signature, submits to Cartesi)
```
