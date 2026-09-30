#pragma once
#if defined(MURMUR_ENCRYPT)
#include <ESPAsyncWebServer.h>
#include <cstring>
#include <strings.h>

// Attach first: denied requests must never reach upload or JSON body callbacks.
class MurmurWifiGuard : public AsyncWebHandler
{
    const char *password_;
    const char *hostname_;
    const char *address_;

    static bool route(const char *url, const char *path)
    {
        const size_t n = strlen(path);
        return strncmp(url, path, n) == 0 && (url[n] == '\0' || url[n] == '/');
    }

    bool validHost(const char *host) const
    {
        size_t n = strlen(host);
        if (n >= 3 && strcmp(host + n - 3, ":80") == 0) n -= 3;
        if ((n == strlen(address_) && strncasecmp(host, address_, n) == 0) ||
            (n == strlen(hostname_) && strncasecmp(host, hostname_, n) == 0)) return true;
        const size_t h = strlen(hostname_);
        return n == h + 6 && strncasecmp(host, hostname_, h) == 0 &&
               strncasecmp(host + h, ".local", 6) == 0;
    }

    static bool sameOrigin(const char *value, const char *host, bool referer)
    {
        if (strncmp(value, "http://", 7) != 0) return false;
        const size_t n = strlen(host);
        const char *authority = value + 7;
        return strncasecmp(authority, host, n) == 0 &&
               (authority[n] == '\0' || (referer && authority[n] == '/'));
    }

    enum Decision { Allow, Disabled, Forbidden, Login };
    Decision decision(AsyncWebServerRequest *request) const
    {
        if (!password_[0]) return Disabled;
        if (!validHost(request->host().c_str())) return Forbidden;
        const auto &url = request->url();
        if (route(url.c_str(), "/firmware.bin") || route(url.c_str(), "/udpcontrol") ||
            route(url.c_str(), "/sethome") || route(url.c_str(), "/connect")) return Forbidden;
        if ((request->hasHeader("Origin") &&
             !sameOrigin(request->header("Origin").c_str(), request->host().c_str(), false)) ||
            (request->hasHeader("Referer") &&
             !sameOrigin(request->header("Referer").c_str(), request->host().c_str(), true)) ||
            (request->hasHeader("Sec-Fetch-Site") && request->header("Sec-Fetch-Site") == "cross-site"))
            return Forbidden;
        if (!request->authenticate("admin", password_)) return Login;
        // Legacy handlers accept any HTTP method. Keep mutations POST-only.
        if ((route(url.c_str(), "/reboot") || route(url.c_str(), "/reset") ||
             route(url.c_str(), "/forceupdate") || route(url.c_str(), "/forget") ||
             route(url.c_str(), "/access") || (route(url.c_str(), "/cw") && request->hasArg("radio"))) &&
            request->method() != HTTP_POST) return Forbidden;
        // Browser mutations must carry same-origin metadata. CLI clients use an
        // explicit header that cross-origin browser forms cannot provide.
        if (request->method() != HTTP_GET && request->method() != HTTP_HEAD && request->method() != HTTP_OPTIONS &&
            !request->hasHeader("Origin") && !request->hasHeader("Referer") &&
            (!request->hasHeader("X-Murmur-Request") || request->header("X-Murmur-Request") != "1"))
            return Forbidden;
        return Allow;
    }

public:
    MurmurWifiGuard(const char *password, const char *hostname, const char *address)
        : password_(password), hostname_(hostname), address_(address) {}

    bool canHandle(AsyncWebServerRequest *request) const override
    {
        return decision(request) != Allow;
    }

    void handleRequest(AsyncWebServerRequest *request) override
    {
        switch (decision(request)) {
        case Disabled: request->send(503, "text/plain", "Wi-Fi management is not provisioned"); break;
        case Forbidden: request->send(403, "text/plain", "Management request forbidden"); break;
        case Login: request->requestAuthentication("MurmurLRS", false); break;
        case Allow: break;
        }
    }
    // Inherited trivial/no-op body and upload handlers discard denied payloads.
};
#endif
