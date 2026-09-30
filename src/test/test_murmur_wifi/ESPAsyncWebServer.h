// Host double for the request/handler boundary used by the production guard.
#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
using String = std::string;
enum { HTTP_GET = 1, HTTP_POST = 2, HTTP_HEAD = 4, HTTP_OPTIONS = 32 };

struct AsyncWebServerRequest {
    String path = "/config", hostname = "10.0.0.1", username, password;
    std::map<String, String> headers;
    std::set<String> args;
    int verb = HTTP_GET;
    int status = 0;
    bool challenged = false;
    String url() const { return path; }
    String host() const { return hostname; }
    int method() const { return verb; }
    bool hasArg(const char *name) const { return args.count(name); }
    bool hasHeader(const char *name) const { return headers.count(name); }
    String header(const char *name) const { return headers.at(name); }
    bool authenticate(const char *user, const char *pass) const {
        return username == user && password == pass;
    }
    void send(int code, const char *, const char *) { status = code; }
    void requestAuthentication(const char *, bool digest) {
        challenged = !digest;
        status = 401;
    }
};

class AsyncWebHandler {
public:
    virtual ~AsyncWebHandler() {}
    virtual bool canHandle(AsyncWebServerRequest *) const { return false; }
    virtual void handleRequest(AsyncWebServerRequest *) {}
    virtual void handleBody(AsyncWebServerRequest *, uint8_t *, size_t, size_t, size_t) {}
    virtual void handleUpload(AsyncWebServerRequest *, const String &, size_t, uint8_t *, size_t, bool) {}
    virtual bool isRequestHandlerTrivial() const { return true; }
};
