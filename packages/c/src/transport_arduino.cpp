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
#include <ESP8266HTTPClient.h>
#elif defined(ESP32)
#include <WiFi.h>
#include <HTTPClient.h>
#else
#include <WiFi.h>
#include <ArduinoHttpClient.h>
#endif

extern "C" {
#include "lcore/lcore.h"
}

extern "C" int lcore_submit(const char* attestor_url, const char* did,
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

#if defined(ESP8266) || defined(ESP32)
    /* ESP8266/ESP32 Arduino core has built-in HTTPClient */
    HTTPClient http;
    WiFiClient client;

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

    WiFiClient wifiClient;
    HttpClient http(wifiClient, host, port);

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
