/**
 * L{CORE} ESP32 HTTP Transport
 *
 * HTTP client implementation using ESP-IDF's esp_http_client.
 * Compile with: idf.py build (in ESP-IDF environment)
 */

#ifdef LCORE_PLATFORM_ESP32

#include "lcore/lcore.h"
#include <string.h>
#include <stdio.h>
#include "esp_http_client.h"
#include "esp_log.h"

static const char* TAG = "lcore";

/* Response handler - we don't need the response body for now */
static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGE(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            break;
        default:
            break;
    }
    return ESP_OK;
}

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

    /* Configure HTTP client */
    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .event_handler = http_event_handler,
        .timeout_ms = 10000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return LCORE_ERR_HTTP;
    }

    /* Set headers and body */
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, body_len);

    /* Perform request */
    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);

    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP POST failed: %s", esp_err_to_name(err));
        return LCORE_ERR_HTTP;
    }

    if (status_code < 200 || status_code >= 300) {
        ESP_LOGE(TAG, "HTTP status %d", status_code);
        return LCORE_ERR_HTTP;
    }

    ESP_LOGI(TAG, "Submission successful (HTTP %d)", status_code);
    return LCORE_OK;
}

#endif /* LCORE_PLATFORM_ESP32 */
