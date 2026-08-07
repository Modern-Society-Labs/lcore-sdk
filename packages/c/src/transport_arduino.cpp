/**
 * L{CORE} Arduino HTTP Transport
 *
 * HTTP client implementation using Arduino WiFiClient + HTTPClient.
 * Works with ESP8266, ESP32 Arduino core, and other WiFi-capable boards.
 *
 * Requires:
 *   - WiFi.h (or WiFiNINA.h for MKR boards)
 *   - HTTPClient.h (ESP8266HTTPClient or ESP32 HTTPClient)
 */

#ifdef LCORE_PLATFORM_ARDUINO

#include <Arduino.h>

#if defined(ESP8266)
#include <ESP8266WiFi.h>
#include <WiFiClientSecure.h>
#include <ESP8266HTTPClient.h>
#elif defined(ESP32)
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#else
#include <WiFi.h>
#if defined(WIFININA_H) || defined(WIFI101_H) || defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT)
#include <WiFiSSLClient.h>
#endif
#include <ArduinoHttpClient.h>
#endif

extern "C" {
#include "lcore/lcore.h"
}

extern "C" int lcore_submit(const char* attestor_url, const char* did,
                            const char* payload_json, const char* jws,
                            uint64_t timestamp, const char* salt_hex) {
    if (!attestor_url || !did || !payload_json || !jws || !salt_hex) return LCORE_ERR_INVALID;

    /* Build endpoint URL */
    char url[512];
    snprintf(url, sizeof(url), "%s/api/device/submit", attestor_url);

    /* Build JSON body. timestamp and salt MUST match those used in the hash. */
    char body[8192];
    int body_len = snprintf(body, sizeof(body),
        "{\"did\":\"%s\",\"payload\":%s,\"signature\":\"%s\",\"timestamp\":%llu,\"salt\":\"%s\"}",
        did, payload_json, jws, (unsigned long long)timestamp, salt_hex);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) return LCORE_ERR_BUFFER;

    const bool useTls = (strncmp(attestor_url, "https://", 8) == 0);
    const char* caCert = lcore_get_ca_cert();

    /* Fail closed: an https:// URL with no trust anchor must not silently fall
     * back to plaintext. Call lcore_set_ca_cert(), or lcore_tls_allow_insecure(1)
     * for development only. */
    if (useTls && !caCert && !lcore_tls_insecure_allowed()) {
        Serial.println("[lcore] https:// requires a CA cert - call lcore_set_ca_cert()");
        return LCORE_ERR_TLS;
    }

#if defined(ESP8266) || defined(ESP32)
    /* ESP8266/ESP32 Arduino core has built-in HTTPClient */
    HTTPClient http;
    WiFiClient plainClient;
    WiFiClientSecure secureClient;

    if (useTls) {
        if (caCert) {
#if defined(ESP8266)
            /* Static so the trust anchor is parsed once. Allocating per call
             * would leak heap on every submission and eventually brick a
             * long-running device. */
            static BearSSL::X509List trustAnchor(caCert);
            secureClient.setTrustAnchors(&trustAnchor);
#else
            secureClient.setCACert(caCert);
#endif
        } else {
            secureClient.setInsecure(); /* explicitly opted in above */
        }
    }

    WiFiClient& client = useTls
        ? static_cast<WiFiClient&>(secureClient)
        : plainClient;

    if (!http.begin(client, url)) {
        Serial.println("[lcore] HTTP begin failed");
        return LCORE_ERR_HTTP;
    }

    http.addHeader("Content-Type", "application/json");
    http.setTimeout(10000);

    int httpCode = http.POST(body);
    http.end();

    if (httpCode < 200 || httpCode >= 300) {
        Serial.printf("[lcore] HTTP POST failed: %d\n", httpCode);
        return LCORE_ERR_HTTP;
    }

    Serial.printf("[lcore] Submission successful (HTTP %d)\n", httpCode);
    return LCORE_OK;

#else
    /* Generic Arduino with ArduinoHttpClient library */
    /* Parse host and port from URL (simplified - assumes http://host:port/path) */
    char host[128];
    int port = 80;
    const char* path = "/api/device/submit";

    /* Skip http:// or https:// */
    const char* hostStart = attestor_url;
    if (strncmp(hostStart, "http://", 7) == 0) hostStart += 7;
    else if (strncmp(hostStart, "https://", 8) == 0) { hostStart += 8; port = 443; }

    /* Find port separator or path */
    const char* colonPos = strchr(hostStart, ':');
    const char* slashPos = strchr(hostStart, '/');

    if (colonPos && (!slashPos || colonPos < slashPos)) {
        size_t hostLen = colonPos - hostStart;
        if (hostLen >= sizeof(host)) return LCORE_ERR_BUFFER;
        strncpy(host, hostStart, hostLen);
        host[hostLen] = '\0';
        port = atoi(colonPos + 1);
    } else if (slashPos) {
        size_t hostLen = slashPos - hostStart;
        if (hostLen >= sizeof(host)) return LCORE_ERR_BUFFER;
        strncpy(host, hostStart, hostLen);
        host[hostLen] = '\0';
    } else {
        strncpy(host, hostStart, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }

    /* WiFiSSLClient ships with WiFiNINA/WiFi101 and verifies against the CA store
     * burned into the board's WiFi module (upload roots with the Arduino
     * Firmware Updater). Cores without WiFiSSLClient must supply their own secure
     * client — refuse TLS rather than quietly sending plaintext. */
    WiFiClient plainClient;
#if defined(WIFI_SSL_CLIENT_AVAILABLE) || defined(WIFININA_H) || defined(WIFI101_H) || defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT)
    WiFiSSLClient sslClient;
    Client& netClient = useTls
        ? static_cast<Client&>(sslClient)
        : static_cast<Client&>(plainClient);
#else
    if (useTls) {
        Serial.println("[lcore] TLS unsupported on this core - no WiFiSSLClient");
        return LCORE_ERR_TLS;
    }
    Client& netClient = static_cast<Client&>(plainClient);
#endif

    HttpClient http(netClient, host, port);

    http.beginRequest();
    http.post(path);
    http.sendHeader("Content-Type", "application/json");
    http.sendHeader("Content-Length", body_len);
    http.beginBody();
    http.print(body);
    http.endRequest();

    int statusCode = http.responseStatusCode();

    if (statusCode < 200 || statusCode >= 300) {
        Serial.print("[lcore] HTTP POST failed: ");
        Serial.println(statusCode);
        return LCORE_ERR_HTTP;
    }

    Serial.print("[lcore] Submission successful (HTTP ");
    Serial.print(statusCode);
    Serial.println(")");
    return LCORE_OK;
#endif
}

#endif /* LCORE_PLATFORM_ARDUINO */
