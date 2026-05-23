/*
 * Signet ESP32-C3 edge agent — Phase 0 reference firmware.
 *
 * Plan B path per PRD §15:
 *   I2S audio capture (TRWS2014B mic, 16 kHz mono)
 *      -> energy-threshold trigger
 *      -> SHA-256 fingerprint of the trigger window
 *      -> HTTPS POST to the edge gateway, which signs ML-DSA-44 and submits
 *
 * Build with ESP-IDF 5.3+:
 *   idf.py set-target esp32c3 && idf.py menuconfig && idf.py build flash monitor
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_event.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "driver/i2s_std.h"
#include "mbedtls/sha256.h"
#include "nvs_flash.h"

#define WIFI_SSID         CONFIG_SIGNET_WIFI_SSID
#define WIFI_PASS         CONFIG_SIGNET_WIFI_PASS
#define GATEWAY_URL       CONFIG_SIGNET_GATEWAY_URL  /* e.g. http://10.0.0.10:8001/edge/trigger */
#define DEVICE_AGENT_ID   CONFIG_SIGNET_DEVICE_AGENT_ID
#define SAMPLE_RATE_HZ    16000
#define I2S_BCK           4
#define I2S_WS            5
#define I2S_DIN           6
#define WIN_MS            200
#define WIN_SAMPLES       (SAMPLE_RATE_HZ * WIN_MS / 1000)
#define TRIGGER_RMS_THR   2000.0f
#define COOLDOWN_MS       1500

static const char *TAG = "signet-edge";
static EventGroupHandle_t s_wifi_evt;
static const int WIFI_CONNECTED_BIT = BIT0;

static i2s_chan_handle_t s_rx_handle = NULL;

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "wifi disconnected, retrying");
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_wifi_evt, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    s_wifi_evt = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    wifi_config_t wc = {0};
    strncpy((char *)wc.sta.ssid, WIFI_SSID, sizeof(wc.sta.ssid));
    strncpy((char *)wc.sta.password, WIFI_PASS, sizeof(wc.sta.password));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
    xEventGroupWaitBits(s_wifi_evt, WIFI_CONNECTED_BIT, false, true, portMAX_DELAY);
    ESP_LOGI(TAG, "wifi connected");
}

static void i2s_init(void) {
    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    ESP_ERROR_CHECK(i2s_new_channel(&chan_cfg, NULL, &s_rx_handle));
    i2s_std_config_t std_cfg = {
        .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(SAMPLE_RATE_HZ),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_MONO),
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = I2S_BCK,
            .ws   = I2S_WS,
            .dout = I2S_GPIO_UNUSED,
            .din  = I2S_DIN,
            .invert_flags = { 0 },
        },
    };
    ESP_ERROR_CHECK(i2s_channel_init_std_mode(s_rx_handle, &std_cfg));
    ESP_ERROR_CHECK(i2s_channel_enable(s_rx_handle));
}

static float window_rms(const int16_t *buf, size_t n) {
    double acc = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double v = (double)buf[i];
        acc += v * v;
    }
    return (float)sqrt(acc / (double)n);
}

static void hex_lower(const uint8_t *bytes, size_t n, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[2 * i] = hex[(bytes[i] >> 4) & 0xF];
        out[2 * i + 1] = hex[bytes[i] & 0xF];
    }
    out[2 * n] = '\0';
}

static void post_trigger(const uint8_t *fingerprint, float rms_value) {
    char fingerprint_hex[2 * 32 + 1];
    hex_lower(fingerprint, 32, fingerprint_hex);

    uint64_t nonce = ((uint64_t)esp_random() << 32) | esp_random();

    char body[512];
    int n = snprintf(body, sizeof(body),
        "{\"agent_id\":\"%s\",\"source\":\"esp32c3\",\"action_name\":\"voice_trigger\","
        "\"params\":{\"fingerprint_sha256\":\"%s\",\"rms\":%.1f,\"sample_rate\":%d,\"nonce\":\"%llu\"}}",
        DEVICE_AGENT_ID, fingerprint_hex, rms_value, SAMPLE_RATE_HZ, (unsigned long long)nonce);
    if (n < 0 || n >= (int)sizeof(body)) {
        ESP_LOGE(TAG, "payload truncated");
        return;
    }

    esp_http_client_config_t cfg = {
        .url = GATEWAY_URL,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 5000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, n);
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "gateway responded %d", esp_http_client_get_status_code(client));
    } else {
        ESP_LOGW(TAG, "POST failed: %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

static void edge_task(void *arg) {
    const size_t bytes_per_win = WIN_SAMPLES * sizeof(int16_t);
    int16_t *buf = malloc(bytes_per_win);
    if (!buf) {
        ESP_LOGE(TAG, "alloc failed");
        vTaskDelete(NULL);
        return;
    }

    int64_t last_trigger_us = 0;

    while (1) {
        size_t read_bytes = 0;
        esp_err_t err = i2s_channel_read(s_rx_handle, buf, bytes_per_win, &read_bytes, portMAX_DELAY);
        if (err != ESP_OK || read_bytes == 0) {
            ESP_LOGW(TAG, "i2s read err=%d bytes=%u", err, (unsigned)read_bytes);
            continue;
        }

        float rms = window_rms(buf, read_bytes / sizeof(int16_t));
        int64_t now = esp_timer_get_time();

        if (rms >= TRIGGER_RMS_THR && (now - last_trigger_us) > (COOLDOWN_MS * 1000)) {
            uint8_t fingerprint[32];
            mbedtls_sha256((const unsigned char *)buf, read_bytes, fingerprint, 0);
            ESP_LOGI(TAG, "trigger rms=%.1f -> POST", rms);
            post_trigger(fingerprint, rms);
            last_trigger_us = now;
        }
    }
}

void app_main(void) {
    esp_err_t r = nvs_flash_init();
    if (r == ESP_ERR_NVS_NO_FREE_PAGES || r == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    wifi_init();
    i2s_init();
    xTaskCreate(edge_task, "signet-edge", 8192, NULL, 5, NULL);
}
