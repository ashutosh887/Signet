#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

#include "config.h"

static const uint32_t DEBOUNCE_MS = 60;
static const uint32_t COOLDOWN_MS = 1200;

static uint32_t lastTriggerMs = 0;
static int lastButtonState = HIGH;

static void connectWiFi() {
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.printf("[signet] connecting to %s\n", WIFI_SSID);
    while (WiFi.status() != WL_CONNECTED) {
        delay(250);
        Serial.print('.');
    }
    Serial.printf("\n[signet] wifi up, ip=%s\n", WiFi.localIP().toString().c_str());
}

static void blink(uint16_t ms, uint8_t times = 1) {
    for (uint8_t i = 0; i < times; ++i) {
        digitalWrite(LED_GPIO, HIGH);
        delay(ms);
        digitalWrite(LED_GPIO, LOW);
        if (i + 1 < times) delay(ms);
    }
}

static void fireTrigger() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[signet] wifi down, skipping trigger");
        blink(80, 3);
        return;
    }

    StaticJsonDocument<256> doc;
    doc["source"] = "esp32s3";
    doc["action_name"] = "button_press";
    JsonObject params = doc["params"].to<JsonObject>();
    params["nonce"] = String(esp_random(), HEX) + String(esp_random(), HEX);
    params["uptime_ms"] = millis();

    String body;
    serializeJson(doc, body);

    HTTPClient http;
    http.setTimeout(4000);
    http.begin(GATEWAY_URL);
    http.addHeader("Content-Type", "application/json");
    int status = http.POST(body);
    String resp = http.getString();
    http.end();

    Serial.printf("[signet] POST %s -> %d\n", GATEWAY_URL, status);
    Serial.printf("[signet] response: %s\n", resp.c_str());

    if (status >= 200 && status < 300) {
        blink(200, 1);
    } else {
        blink(80, 4);
    }
}

void setup() {
    Serial.begin(115200);
    delay(200);
    Serial.println("\n[signet] esp32-s3 boot-button trigger");

    pinMode(BUTTON_GPIO, INPUT_PULLUP);
    pinMode(LED_GPIO, OUTPUT);
    digitalWrite(LED_GPIO, LOW);

    connectWiFi();
    blink(120, 2);
    Serial.println("[signet] ready — press BOOT to fire an envelope");
}

void loop() {
    int state = digitalRead(BUTTON_GPIO);

    if (state == LOW && lastButtonState == HIGH) {
        delay(DEBOUNCE_MS);
        if (digitalRead(BUTTON_GPIO) == LOW) {
            uint32_t now = millis();
            if (now - lastTriggerMs > COOLDOWN_MS) {
                lastTriggerMs = now;
                Serial.println("[signet] button pressed -> trigger");
                fireTrigger();
            }
        }
    }
    lastButtonState = state;
    delay(8);
}
