#include <unity.h>
#include "../../lib/WIFI/MurmurWifiGuard.h"

static const char credential[] = "0123456789abcdef0123456789abcdef";
void setUp() {}
void tearDown() {}

static AsyncWebServerRequest authenticated(const char *path = "/config")
{
    AsyncWebServerRequest request;
    request.path = path;
    request.username = "admin";
    request.password = credential;
    return request;
}

void test_missing_credential_fails_closed()
{
    MurmurWifiGuard guard("", "elrs_rx", "10.0.0.1");
    auto request = authenticated();
    TEST_ASSERT_TRUE(guard.canHandle(&request));
    guard.handleRequest(&request);
    TEST_ASSERT_EQUAL(503, request.status);
}

void test_all_management_routes_require_authentication()
{
    MurmurWifiGuard guard(credential, "elrs_rx", "10.0.0.1");
    for (const char *path : {"/", "/index.html", "/config", "/options.json", "/hardware.json",
         "/update", "/forceupdate", "/reboot", "/reset", "/cw", "/lr1121", "/buttons",
         "/import", "/voltage-sample", "/gps", "/networks.json", "/forget", "/access"}) {
        AsyncWebServerRequest request;
        request.path = path;
        TEST_ASSERT_TRUE(guard.canHandle(&request));
        guard.handleRequest(&request);
        TEST_ASSERT_EQUAL(401, request.status);
        TEST_ASSERT_TRUE(request.challenged);
    }
}

void test_wrong_password_and_username_are_rejected()
{
    MurmurWifiGuard guard(credential, "elrs_rx", "10.0.0.1");
    auto request = authenticated();
    request.password = "wrong";
    TEST_ASSERT_TRUE(guard.canHandle(&request));
    request = authenticated();
    request.username = "other";
    TEST_ASSERT_TRUE(guard.canHandle(&request));
}

void test_authenticated_local_requests_reach_normal_handlers()
{
    MurmurWifiGuard guard(credential, "elrs_rx", "10.0.0.1");
    auto request = authenticated("/update");
    for (const char *host : {"10.0.0.1", "10.0.0.1:80", "elrs_rx", "elrs_rx.local", "ELRS_RX.LOCAL:80"}) {
        request.hostname = host;
        request.headers["Origin"] = String("http://") + host;
        request.headers["Referer"] = String("http://") + host + "/index.html";
        TEST_ASSERT_FALSE(guard.canHandle(&request));
    }
}

void test_cross_origin_requests_are_rejected_even_with_credentials()
{
    MurmurWifiGuard guard(credential, "elrs_rx", "10.0.0.1");
    for (const char *origin : {"null", "https://10.0.0.1", "http://evil.test", "http://10.0.0.1.evil.test",
                               "http://10.0.0.1:81", "http://10.0.0.1/path", "http://10.0.0.1@evil.test"}) {
        auto request = authenticated("/reset");
        request.headers["Origin"] = origin;
        TEST_ASSERT_TRUE(guard.canHandle(&request));
        guard.handleRequest(&request);
        TEST_ASSERT_EQUAL(403, request.status);
    }
}

void test_cross_site_referer_fetch_metadata_and_host_are_rejected()
{
    MurmurWifiGuard guard(credential, "elrs_rx", "10.0.0.1");
    auto request = authenticated();
    request.headers["Referer"] = "http://evil.test/page";
    TEST_ASSERT_TRUE(guard.canHandle(&request));
    request = authenticated();
    request.headers["Sec-Fetch-Site"] = "cross-site";
    TEST_ASSERT_TRUE(guard.canHandle(&request));
    request = authenticated();
    request.hostname = "elrs_rx.local.evil.test";
    TEST_ASSERT_TRUE(guard.canHandle(&request));
}

void test_export_and_unsupported_services_are_denied_to_admin()
{
    MurmurWifiGuard guard(credential, "elrs_rx", "10.0.0.1");
    for (const char *path : {"/firmware.bin", "/firmware.bin/extra", "/udpcontrol", "/sethome", "/connect"}) {
        auto request = authenticated(path);
        TEST_ASSERT_TRUE(guard.canHandle(&request));
        guard.handleRequest(&request);
        TEST_ASSERT_EQUAL(403, request.status);
    }
    for (const char *path : {"/reboot", "/reset", "/forceupdate", "/forget", "/access"}) {
        auto request = authenticated(path);
        TEST_ASSERT_TRUE(guard.canHandle(&request)); // GET must not mutate.
        request.verb = HTTP_POST;
        TEST_ASSERT_TRUE(guard.canHandle(&request)); // No origin or CLI marker.
        request.headers["X-Murmur-Request"] = "1";
        TEST_ASSERT_FALSE(guard.canHandle(&request));
        request.headers["Origin"] = "http://evil.test";
        TEST_ASSERT_TRUE(guard.canHandle(&request)); // Marker cannot bypass origin.
    }
    auto request = authenticated("/cw");
    TEST_ASSERT_FALSE(guard.canHandle(&request)); // Read-only radio information.
    request.args.insert("radio");
    TEST_ASSERT_TRUE(guard.canHandle(&request)); // CW transmission needs POST.
}

class WritingHandler : public AsyncWebHandler {
public:
    int writes = 0;
    void handleBody(AsyncWebServerRequest *, uint8_t *, size_t, size_t, size_t) override { ++writes; }
    void handleUpload(AsyncWebServerRequest *, const String &, size_t, uint8_t *, size_t, bool) override { ++writes; }
};

void test_denied_bodies_and_upload_chunks_do_not_reach_writers()
{
    MurmurWifiGuard guard(credential, "elrs_rx", "10.0.0.1");
    WritingHandler writer;
    AsyncWebServerRequest request;
    request.path = "/update";
    // The actual server selects the first matching handler before body parsing.
    AsyncWebHandler *selected = guard.canHandle(&request) ? static_cast<AsyncWebHandler *>(&guard) : &writer;
    uint8_t payload[4] = {1, 2, 3, 4};
    TEST_ASSERT_TRUE(selected->isRequestHandlerTrivial());
    for (unsigned i = 0; i < 4; ++i) {
        selected->handleBody(&request, payload, 4, i * 4, 16);
        selected->handleUpload(&request, "firmware.bin", i * 4, payload, 4, i == 3);
    }
    selected->handleRequest(&request);
    TEST_ASSERT_EQUAL(0, writer.writes);
    TEST_ASSERT_EQUAL(401, request.status);
    request = authenticated("/update");
    request.verb = HTTP_POST;
    request.headers["X-Murmur-Request"] = "1";
    selected = guard.canHandle(&request) ? static_cast<AsyncWebHandler *>(&guard) : &writer;
    selected->handleUpload(&request, "firmware.bin", 0, payload, 4, true);
    TEST_ASSERT_EQUAL(1, writer.writes);
}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_missing_credential_fails_closed);
    RUN_TEST(test_all_management_routes_require_authentication);
    RUN_TEST(test_wrong_password_and_username_are_rejected);
    RUN_TEST(test_authenticated_local_requests_reach_normal_handlers);
    RUN_TEST(test_cross_origin_requests_are_rejected_even_with_credentials);
    RUN_TEST(test_cross_site_referer_fetch_metadata_and_host_are_rejected);
    RUN_TEST(test_export_and_unsupported_services_are_denied_to_admin);
    RUN_TEST(test_denied_bodies_and_upload_chunks_do_not_reach_writers);
    return UNITY_END();
}
