#pragma once

#include <windows.h>
#include <winhttp.h>
#include <wininet.h>

#include <atomic>
#include <functional>
#include <initializer_list>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "json.hpp"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")

#ifndef SECURITY_FLAG_IGNORE_REVOCATION
#define SECURITY_FLAG_IGNORE_REVOCATION 0x80
#endif

namespace mfa {

enum class MessageType {
    Success = 1,
    Failure = 2,
    Info = 3,
};

using MessageListener = std::function<void(MessageType messageType, const std::string& text)>;

class Error : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

class AlreadyRunningError : public Error {
  public:
    AlreadyRunningError() : Error("session is already running") {}
};

class LockfileError : public Error {
  public:
    using Error::Error;
};

class AuthFetchError : public Error {
  public:
    using Error::Error;
};

class ClientVersionError : public Error {
  public:
    using Error::Error;
};

class PartySessionError : public Error {
  public:
    using Error::Error;
};

class HttpTransportError : public Error {
  public:
    using Error::Error;
};

class JsonParseError : public Error {
  public:
    using Error::Error;
};

inline void discard_message(MessageType, const std::string&) {}

inline MessageListener& message_listener_slot() {
    static MessageListener listener = discard_message;
    return listener;
}

inline std::atomic<bool>& running_flag() {
    static std::atomic<bool> running{false};
    return running;
}

inline bool is_running() {
    return running_flag().load();
}

inline void set_message_listener(MessageListener listener) {
    message_listener_slot() = listener ? std::move(listener) : MessageListener(discard_message);
}

inline void start_session();

inline void init() {
    start_session();
}

namespace detail {
static const char* const kClientPlatformBase64 =
    "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2"
    "lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIkludGVsIg0KfQ==";
static const char* const kRiotClientUserAgent = "RiotClient/1.0 (Windows; x64)";
static const wchar_t* const kRiotClientUserAgentWide = L"RiotClient/1.0 (Windows; x64)";
static const char* const kShooterUserAgent = "ShooterGame/13 Windows/10.0.19042.1.256.64bit";

static constexpr DWORD kHttpTimeoutMs = 15000;
static constexpr DWORD kPartyWaitTimeoutMs = 45000;
static constexpr DWORD kPartyPollIntervalMs = 2000;
static constexpr size_t kLogTailMaxBytes = 512 * 1024;
static constexpr size_t kHttpReadChunkBytes = 4096;
static constexpr size_t kLockfileReadMaxBytes = 512;

enum class TransportSecurity {
    PlainHttp,
    Tls,
};

struct RegionMapping {
    const char* region;
    const char* shard;
};

static const RegionMapping kRegions[] = {
    {"ap", "ap"}, {"na", "na"}, {"eu", "eu"}, {"kr", "kr"}, {"latam", "na"}, {"br", "na"},
};

static constexpr int kRegionCount = static_cast<int>(sizeof(kRegions) / sizeof(kRegions[0]));

static void emit_message(MessageType messageType, const std::string& text) {
    message_listener_slot()(messageType, text);
}

static std::string encode_base64(const std::string& input) {
    static const char* const kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    int accumulator = 0;
    int bits_stored = -6;

    for (unsigned char byte : input) {
        accumulator = (accumulator << 8) + byte;
        bits_stored += 8;
        while (bits_stored >= 0) {
            encoded.push_back(kAlphabet[(accumulator >> bits_stored) & 63]);
            bits_stored -= 6;
        }
    }

    if (bits_stored > -6)
        encoded.push_back(kAlphabet[((accumulator << 8) >> (bits_stored + 8)) & 63]);

    while (encoded.size() % 4)
        encoded.push_back('=');

    return encoded;
}

static std::wstring to_wide_string(const std::string& narrow) {
    if (narrow.empty())
        return {};

    const int required = MultiByteToWideChar(CP_ACP, 0, narrow.c_str(), -1, nullptr, 0);
    if (required <= 1)
        return {};

    std::wstring wide(static_cast<size_t>(required - 1), L'\0');
    MultiByteToWideChar(CP_ACP, 0, narrow.c_str(), -1, &wide[0], required);
    return wide;
}

static std::string local_app_data_path() {
    char buffer[MAX_PATH] = {};
    if (!GetEnvironmentVariableA("LOCALAPPDATA", buffer, MAX_PATH))
        throw LockfileError("LOCALAPPDATA is not set");
    return buffer;
}

class JsonObject {
  public:
    static JsonObject parse(const std::string& body) {
        try {
            return JsonObject(nlohmann::json::parse(body));
        } catch (const nlohmann::json::exception& cause) {
            throw JsonParseError(std::string("JSON parse failed: ") + cause.what());
        }
    }

    std::string string_or_empty(const char* key) const {
        if (!data_.contains(key) || !data_[key].is_string())
            return {};
        return data_[key].get<std::string>();
    }

    std::string string_or_empty(std::initializer_list<const char*> keys) const {
        for (const char* key : keys) {
            std::string value = string_or_empty(key);
            if (!value.empty())
                return value;
        }
        return {};
    }

    std::string nested_string_or_empty(std::initializer_list<const char*> path) const {
        const nlohmann::json* cursor = &data_;
        for (const char* segment : path) {
            if (!cursor->contains(segment))
                return {};
            cursor = &(*cursor)[segment];
        }
        if (!cursor->is_string())
            return {};
        return cursor->get<std::string>();
    }

  private:
    explicit JsonObject(nlohmann::json data) : data_(std::move(data)) {}

    nlohmann::json data_;
};

struct HttpResponse {
    int status_code = 0;
    std::string body;

    bool ok() const { return status_code >= 200 && status_code < 300; }

    bool has_body() const { return !body.empty(); }
};

struct HttpEndpoint {
    std::string host;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
    TransportSecurity security = TransportSecurity::Tls;
    std::string path = "/";
};

struct HttpRequest {
    std::string method = "GET";
    HttpEndpoint endpoint;
    std::string headers;
    std::string body;
};

class WinInetHandle {
  public:
    WinInetHandle() = default;
    explicit WinInetHandle(HINTERNET handle) : handle_(handle) {}
    ~WinInetHandle() { reset(); }

    WinInetHandle(const WinInetHandle&) = delete;
    WinInetHandle& operator=(const WinInetHandle&) = delete;

    WinInetHandle(WinInetHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    HINTERNET get() const { return handle_; }
    explicit operator bool() const { return handle_ != nullptr; }

    void reset(HINTERNET handle = nullptr) {
        if (handle_)
            InternetCloseHandle(handle_);
        handle_ = handle;
    }

  private:
    HINTERNET handle_ = nullptr;
};

class WinHttpHandle {
  public:
    WinHttpHandle() = default;
    explicit WinHttpHandle(HINTERNET handle) : handle_(handle) {}
    ~WinHttpHandle() { reset(); }

    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

    WinHttpHandle(WinHttpHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    HINTERNET get() const { return handle_; }
    explicit operator bool() const { return handle_ != nullptr; }

    void reset(HINTERNET handle = nullptr) {
        if (handle_)
            WinHttpCloseHandle(handle_);
        handle_ = handle;
    }

  private:
    HINTERNET handle_ = nullptr;
};

static DWORD wininet_ignore_certificate_flags() {
    return SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
           SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE |
           SECURITY_FLAG_IGNORE_REVOCATION;
}

static DWORD winhttp_ignore_certificate_flags() {
    return SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
           SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
}

static void apply_wininet_certificate_bypass(HINTERNET request) {
    DWORD flags = 0;
    DWORD flags_size = sizeof(flags);
    InternetQueryOptionA(request, INTERNET_OPTION_SECURITY_FLAGS, &flags, &flags_size);
    flags |= wininet_ignore_certificate_flags();
    InternetSetOptionA(request, INTERNET_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
}

static void apply_winhttp_certificate_bypass(HINTERNET request) {
    DWORD flags = winhttp_ignore_certificate_flags();
    WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
}

static void set_wininet_timeouts(HINTERNET session) {
    DWORD timeout_ms = kHttpTimeoutMs;
    InternetSetOptionA(session, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
    InternetSetOptionA(session, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
    InternetSetOptionA(session, INTERNET_OPTION_SEND_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
}

static std::string fetch_wininet_body(HINTERNET request) {
    std::string body;
    char buffer[kHttpReadChunkBytes];
    DWORD bytes_read = 0;
    while (InternetReadFile(request, buffer, sizeof(buffer), &bytes_read) && bytes_read)
        body.append(buffer, bytes_read);
    return body;
}

static std::string fetch_winhttp_body(HINTERNET request) {
    std::string body;
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(request, &available) && available) {
        std::string chunk(available, '\0');
        DWORD bytes_read = 0;
        if (!WinHttpReadData(request, &chunk[0], available, &bytes_read) || !bytes_read)
            break;
        body.append(chunk.data(), bytes_read);
    }
    return body;
}

static HttpResponse send_wininet_request(const HttpRequest& request) {
    HttpResponse response;

    WinInetHandle session(
        InternetOpenA(kRiotClientUserAgent, INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0));
    if (!session)
        throw HttpTransportError("WinINet InternetOpen failed (" + std::to_string(GetLastError()) +
                                 ")");

    set_wininet_timeouts(session.get());

    WinInetHandle connection(InternetConnectA(session.get(), request.endpoint.host.c_str(),
                                              request.endpoint.port, nullptr, nullptr,
                                              INTERNET_SERVICE_HTTP, 0, 0));
    if (!connection)
        throw HttpTransportError("WinINet InternetConnect failed for host " +
                                 request.endpoint.host);

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI |
                  INTERNET_FLAG_PRAGMA_NOCACHE;
    if (request.endpoint.security == TransportSecurity::Tls) {
        flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                 INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    WinInetHandle http_request(HttpOpenRequestA(connection.get(), request.method.c_str(),
                                                request.endpoint.path.c_str(), "HTTP/1.1", nullptr,
                                                nullptr, flags, 0));
    if (!http_request)
        throw HttpTransportError("WinINet HttpOpenRequest failed for " + request.endpoint.path);

    if (request.endpoint.security == TransportSecurity::Tls)
        apply_wininet_certificate_bypass(http_request.get());

    if (!request.headers.empty()) {
        HttpAddRequestHeadersA(http_request.get(), request.headers.c_str(), static_cast<DWORD>(-1),
                               HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
    }

    LPVOID body_data = request.body.empty() ? nullptr : const_cast<char*>(request.body.data());
    const DWORD body_size = static_cast<DWORD>(request.body.size());

    BOOL sent = HttpSendRequestA(http_request.get(), nullptr, 0, body_data, body_size);
    if (!sent && request.endpoint.security == TransportSecurity::Tls) {
        apply_wininet_certificate_bypass(http_request.get());
        sent = HttpSendRequestA(http_request.get(), nullptr, 0, body_data, body_size);
    }
    if (!sent)
        throw HttpTransportError("WinINet HttpSendRequest failed (" +
                                 std::to_string(GetLastError()) + ")");

    char status_text[16] = {};
    DWORD status_size = sizeof(status_text);
    if (HttpQueryInfoA(http_request.get(), HTTP_QUERY_STATUS_CODE, status_text, &status_size,
                       nullptr))
        response.status_code = atoi(status_text);

    response.body = fetch_wininet_body(http_request.get());
    return response;
}

static HttpResponse send_winhttp_request(const HttpRequest& request) {
    HttpResponse response;

    WinHttpHandle session(WinHttpOpen(kRiotClientUserAgentWide, WINHTTP_ACCESS_TYPE_NO_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session)
        throw HttpTransportError("WinHTTP WinHttpOpen failed (" + std::to_string(GetLastError()) +
                                 ")");

    WinHttpSetTimeouts(session.get(), kHttpTimeoutMs, kHttpTimeoutMs, kHttpTimeoutMs,
                       kHttpTimeoutMs);

    const std::wstring wide_host = to_wide_string(request.endpoint.host);
    WinHttpHandle connection(
        WinHttpConnect(session.get(), wide_host.c_str(), request.endpoint.port, 0));
    if (!connection)
        throw HttpTransportError("WinHTTP WinHttpConnect failed for host " + request.endpoint.host);

    const std::wstring wide_method = to_wide_string(request.method);
    const std::wstring wide_path = to_wide_string(request.endpoint.path);
    const DWORD open_flags =
        request.endpoint.security == TransportSecurity::Tls ? WINHTTP_FLAG_SECURE : 0;

    WinHttpHandle http_request(WinHttpOpenRequest(connection.get(), wide_method.c_str(),
                                                  wide_path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                                  WINHTTP_DEFAULT_ACCEPT_TYPES, open_flags));
    if (!http_request)
        throw HttpTransportError("WinHTTP WinHttpOpenRequest failed for " + request.endpoint.path);

    if (request.endpoint.security == TransportSecurity::Tls)
        apply_winhttp_certificate_bypass(http_request.get());

    const std::wstring wide_headers = to_wide_string(request.headers);
    LPVOID body_data =
        request.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(request.body.data());
    const DWORD body_size = static_cast<DWORD>(request.body.size());

    auto send_once = [&]() -> BOOL {
        return WinHttpSendRequest(
            http_request.get(),
            wide_headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : wide_headers.c_str(),
            wide_headers.empty() ? 0 : static_cast<DWORD>(-1), body_data, body_size, body_size, 0);
    };

    BOOL sent = send_once();
    if (!sent && request.endpoint.security == TransportSecurity::Tls) {
        apply_winhttp_certificate_bypass(http_request.get());
        sent = send_once();
    }
    if (!sent)
        throw HttpTransportError("WinHTTP WinHttpSendRequest failed (" +
                                 std::to_string(GetLastError()) + ")");

    if (!WinHttpReceiveResponse(http_request.get(), nullptr))
        throw HttpTransportError("WinHTTP WinHttpReceiveResponse failed (" +
                                 std::to_string(GetLastError()) + ")");

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (WinHttpQueryHeaders(
            http_request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        response.status_code = static_cast<int>(status);
    }

    response.body = fetch_winhttp_body(http_request.get());
    return response;
}

using TransportSender = HttpResponse (*)(const HttpRequest&);

static HttpResponse try_transports_in_order(const HttpRequest& request,
                                            const TransportSender* senders, size_t sender_count) {
    HttpTransportError last_error("all HTTP transports failed");
    bool saw_error = false;

    for (size_t i = 0; i < sender_count; ++i) {
        try {
            HttpResponse response = senders[i](request);
            if (response.status_code != 0)
                return response;
        } catch (const HttpTransportError& error) {
            last_error = error;
            saw_error = true;
        }
    }

    if (saw_error)
        throw last_error;
    throw HttpTransportError("HTTP transports returned no status for " + request.endpoint.host);
}

// LRC uses a self signed cert
static HttpResponse local_http_get(int port, const std::string& path,
                                   const std::string& basic_auth_header,
                                   TransportSecurity security) {
    static const TransportSender kSenders[] = {
        send_winhttp_request,
        send_wininet_request,
    };
    static const char* const kHosts[] = {"127.0.0.1", "localhost"};

    HttpRequest request;
    request.method = "GET";
    request.endpoint.port = static_cast<INTERNET_PORT>(port);
    request.endpoint.security = security;
    request.endpoint.path = path;
    request.headers = basic_auth_header;

    HttpTransportError last_error("local HTTP GET failed");
    for (const char* host : kHosts) {
        request.endpoint.host = host;
        try {
            return try_transports_in_order(request, kSenders, 2);
        } catch (const HttpTransportError& error) {
            last_error = error;
        }
    }
    throw last_error;
}

static std::optional<HttpResponse> try_local_http_get(int port, const std::string& path,
                                                      const std::string& basic_auth_header,
                                                      TransportSecurity security) {
    try {
        return local_http_get(port, path, basic_auth_header, security);
    } catch (const HttpTransportError&) {
        return std::nullopt;
    }
}

static HttpResponse remote_https_get(const std::string& host, const std::string& path,
                                     const std::string& headers = {}) {
    HttpRequest request;
    request.method = "GET";
    request.endpoint.host = host;
    request.endpoint.port = INTERNET_DEFAULT_HTTPS_PORT;
    request.endpoint.security = TransportSecurity::Tls;
    request.endpoint.path = path;
    request.headers = headers;
    return send_wininet_request(request);
}

static std::optional<HttpResponse> try_remote_https_get(const std::string& host,
                                                        const std::string& path,
                                                        const std::string& headers = {}) {
    try {
        return remote_https_get(host, path, headers);
    } catch (const HttpTransportError&) {
        return std::nullopt;
    }
}

static std::optional<JsonObject> try_parse_json(const std::string& body) {
    try {
        return JsonObject::parse(body);
    } catch (const JsonParseError&) {
        return std::nullopt;
    }
}

struct LockfileContents {
    int port = 0;
    std::string password;
    std::string protocol;

    TransportSecurity security() const {
        return _stricmp(protocol.c_str(), "http") == 0 ? TransportSecurity::PlainHttp
                                                       : TransportSecurity::Tls;
    }

    std::string basic_auth_header() const {
        return "Authorization: Basic " + encode_base64("riot:" + password) + "\r\n";
    }
};

static std::string trim_trailing_whitespace(std::string line) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
        line.pop_back();
    }
    return line;
}

static std::string strip_utf8_bom(std::string line) {
    if (line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF)
        line.erase(0, 3);
    return line;
}

static std::vector<std::string> split_colon_fields(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream stream(line);
    std::string field;
    while (std::getline(stream, field, ':'))
        fields.push_back(field);
    return fields;
}

static LockfileContents fetch_riot_lockfile() {
    const std::string path = local_app_data_path() + "\\Riot Games\\Riot Client\\Config\\lockfile";

    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        throw LockfileError("Riot Client lockfile is missing or unreadable");

    char buffer[kLockfileReadMaxBytes] = {};
    DWORD bytes_read = 0;
    ReadFile(file, buffer, sizeof(buffer) - 1, &bytes_read, nullptr);
    CloseHandle(file);

    const std::string line =
        strip_utf8_bom(trim_trailing_whitespace(std::string(buffer, bytes_read)));
    const std::vector<std::string> fields = split_colon_fields(line);
    if (fields.size() < 5)
        throw LockfileError("Riot Client lockfile is malformed");

    LockfileContents contents;
    contents.port = atoi(fields[2].c_str());
    contents.password = fields[3];
    contents.protocol = fields[4];
    if (contents.port <= 0 || contents.password.empty())
        throw LockfileError("Riot Client lockfile is missing port or password");
    return contents;
}

static std::string fetch_optional_file_tail(const std::string& path,
                                           size_t max_bytes = kLogTailMaxBytes) {
    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return {};

    LARGE_INTEGER file_size = {};
    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart <= 0) {
        CloseHandle(file);
        return {};
    }

    size_t bytes_to_read = static_cast<size_t>(file_size.QuadPart);
    if (bytes_to_read > max_bytes) {
        LARGE_INTEGER offset;
        offset.QuadPart = file_size.QuadPart - static_cast<LONGLONG>(max_bytes);
        SetFilePointerEx(file, offset, nullptr, FILE_BEGIN);
        bytes_to_read = max_bytes;
    }

    std::string contents(bytes_to_read, '\0');
    DWORD bytes_read = 0;
    DWORD total_read = 0;
    while (total_read < bytes_to_read &&
           ReadFile(file, &contents[total_read], static_cast<DWORD>(bytes_to_read - total_read),
                    &bytes_read, nullptr) &&
           bytes_read) {
        total_read += bytes_read;
    }

    CloseHandle(file);
    contents.resize(total_read);
    return contents;
}

static std::string fetch_client_version_string(const std::string& text) {
    static const std::regex version_pattern(R"(release-\d+\.\d+-shipping-\d+-\d+)");
    std::smatch match;
    std::string latest;
    auto cursor = text.cbegin();
    while (std::regex_search(cursor, text.cend(), match, version_pattern)) {
        latest = match.str();
        cursor = match.suffix().first;
    }
    return latest;
}

class SessionAuth {
  public:
    static SessionAuth fetch() {
        SessionAuth auth;
        auth.fetch_from_lockfile();
        auth.fetch_entitlements();
        auth.fetch_chat_session_hints();
        auth.fetch_region_fallbacks();
        auth.require_tokens();
        auth.fetch_puuid_if_needed();
        auth.require_identity();
        return auth;
    }

    const std::string& access_token() const { return access_token_; }
    const std::string& entitlement_token() const { return entitlement_token_; }
    const std::string& puuid() const { return puuid_; }
    const std::string& region() const { return region_; }
    int local_port() const { return local_port_; }
    TransportSecurity security() const { return security_; }
    const std::string& basic_auth_header() const { return basic_auth_header_; }

    bool has_tokens() const { return !access_token_.empty() && !entitlement_token_.empty(); }

    bool has_identity() const { return !puuid_.empty(); }

    bool has_region() const { return !region_.empty(); }

    std::string bearer_authorization_header() const {
        return "Authorization: Bearer " + access_token_ + "\r\n";
    }

    std::string build_pvp_headers(const std::string& client_version) const {
        std::string headers;
        headers += bearer_authorization_header();
        headers += "X-Riot-Entitlements-JWT: " + entitlement_token_ + "\r\n";
        headers += "X-Riot-ClientPlatform: ";
        headers += kClientPlatformBase64;
        headers += "\r\n";
        if (!client_version.empty())
            headers += "X-Riot-ClientVersion: " + client_version + "\r\n";
        headers += "User-Agent: ";
        headers += kShooterUserAgent;
        headers += "\r\n";
        headers += "Content-Type: application/json\r\n";
        return headers;
    }

  private:
    void fetch_from_lockfile() {
        const LockfileContents lockfile = fetch_riot_lockfile();
        local_port_ = lockfile.port;
        security_ = lockfile.security();
        basic_auth_header_ = lockfile.basic_auth_header();
    }

    void fetch_entitlements() {
        const HttpResponse response =
            local_http_get(local_port_, "/entitlements/v1/token", basic_auth_header_, security_);
        if (!response.ok() || !response.has_body())
            throw AuthFetchError("entitlements token request failed");

        const JsonObject json = JsonObject::parse(response.body);
        access_token_ = json.string_or_empty("accessToken");
        entitlement_token_ = json.string_or_empty({"token", "entitlements_token"});
        puuid_ = json.string_or_empty("subject");
    }

    void apply_session_hints(const JsonObject& json) {
        if (puuid_.empty())
            puuid_ = json.string_or_empty("puuid");
        if (region_.empty())
            region_ = json.string_or_empty("region");
        if (region_.empty())
            region_ = json.nested_string_or_empty({"affinities", "live"});
    }

    void try_apply_optional_local_hints(const char* path) {
        const std::optional<HttpResponse> response =
            try_local_http_get(local_port_, path, basic_auth_header_, security_);
        if (!response || !response->ok() || !response->has_body())
            return;

        if (const std::optional<JsonObject> json = try_parse_json(response->body))
            apply_session_hints(*json);
    }

    void fetch_chat_session_hints() { try_apply_optional_local_hints("/chat/v1/session"); }

    void fetch_region_fallbacks() {
        static const char* const kFallbackRegionEndpoints[] = {
            "/riotclient/region-locale",
            "/player-affinity/v1/session",
        };

        for (const char* path : kFallbackRegionEndpoints) {
            if (has_region())
                return;
            try_apply_optional_local_hints(path);
        }
    }

    void require_tokens() const {
        if (!has_tokens())
            throw AuthFetchError("access or entitlement token missing after entitlements fetch");
    }

    void fetch_puuid_if_needed() {
        if (has_identity())
            return;

        const HttpResponse response =
            remote_https_get("auth.riotgames.com", "/userinfo", bearer_authorization_header());
        if (!response.ok() || !response.has_body())
            throw AuthFetchError("userinfo request failed while fetching puuid");

        puuid_ = JsonObject::parse(response.body).string_or_empty("sub");
    }

    void require_identity() const {
        if (!has_identity())
            throw AuthFetchError("puuid could not be fetched");
    }

    std::string access_token_;
    std::string entitlement_token_;
    std::string puuid_;
    std::string region_;
    int local_port_ = 0;
    TransportSecurity security_ = TransportSecurity::Tls;
    std::string basic_auth_header_;
};

static std::string fetch_client_version_from_logs() {
    try {
        const std::string log_dir = local_app_data_path() + "\\VALORANT\\Saved\\Logs\\";
        std::string version =
            fetch_client_version_string(fetch_optional_file_tail(log_dir + "ShooterGame.log"));
        if (!version.empty())
            return version;
        return fetch_client_version_string(fetch_optional_file_tail(log_dir + "ShooterGame.log.1"));
    } catch (const LockfileError&) {
        return {};
    }
}

static std::string fetch_client_version_from_local_client(const SessionAuth& auth) {
    if (auth.local_port() == 0)
        return {};

    const std::optional<HttpResponse> response = try_local_http_get(
        auth.local_port(), "/riotclient/get_info", auth.basic_auth_header(), auth.security());
    if (!response || !response->ok())
        return {};
    return fetch_client_version_string(response->body);
}

static std::string fetch_client_version_from_public_api() {
    const std::optional<HttpResponse> response =
        try_remote_https_get("valorant-api.com", "/v1/version");
    if (!response || !response->ok() || !response->has_body())
        return {};

    const std::optional<JsonObject> json = try_parse_json(response->body);
    if (!json)
        return {};
    return json->nested_string_or_empty({"data", "riotClientVersion"});
}

static std::string fetch_client_version(const SessionAuth& auth) {
    using VersionSource = std::string (*)(const SessionAuth&);
    static const VersionSource kSources[] = {
        [](const SessionAuth&) { return fetch_client_version_from_logs(); },
        fetch_client_version_from_local_client,
        [](const SessionAuth&) { return fetch_client_version_from_public_api(); },
    };

    for (VersionSource source : kSources) {
        std::string version = source(auth);
        if (!version.empty())
            return version;
    }

    throw ClientVersionError("client version could not be fetched from logs, client, or API");
}

struct PartySession {
    std::string region;
    std::string shard;
    std::string party_id;
    std::string host;
};

static std::vector<RegionMapping> region_search_order(const std::string& preferred_region) {
    std::vector<RegionMapping> ordered;
    ordered.reserve(static_cast<size_t>(kRegionCount));

    if (!preferred_region.empty()) {
        for (const RegionMapping& mapping : kRegions) {
            if (!_stricmp(mapping.region, preferred_region.c_str()))
                ordered.push_back(mapping);
        }
    }

    for (const RegionMapping& mapping : kRegions) {
        bool already_listed = false;
        for (const RegionMapping& existing : ordered) {
            if (existing.region == mapping.region) {
                already_listed = true;
                break;
            }
        }
        if (!already_listed)
            ordered.push_back(mapping);
    }

    return ordered;
}

static std::string glz_host_for(const RegionMapping& mapping) {
    return std::string("glz-") + mapping.region + "-1." + mapping.shard + ".a.pvp.net";
}

static std::optional<PartySession> try_fetch_party_on_region(const RegionMapping& mapping,
                                                       const std::string& path,
                                                       const std::string& headers) {
    const std::string host = glz_host_for(mapping);
    const std::optional<HttpResponse> response = try_remote_https_get(host, path, headers);
    if (!response || !response->ok() || !response->has_body())
        return std::nullopt;

    const std::optional<JsonObject> json = try_parse_json(response->body);
    if (!json)
        return std::nullopt;

    const std::string party_id = json->string_or_empty({"CurrentPartyID", "CurrentPartyId"});
    if (party_id.empty())
        return std::nullopt;

    PartySession party;
    party.region = mapping.region;
    party.shard = mapping.shard;
    party.party_id = party_id;
    party.host = host;
    return party;
}

static PartySession fetch_party_session(const SessionAuth& auth, const std::string& headers) {
    const std::string path = "/parties/v1/players/" + auth.puuid();
    const std::vector<RegionMapping> regions = region_search_order(auth.region());

    for (const RegionMapping& mapping : regions) {
        if (const std::optional<PartySession> party = try_fetch_party_on_region(mapping, path, headers))
            return *party;
    }

    throw PartySessionError("party session not found in any region");
}

static PartySession fetch_party_session_with_wait(const SessionAuth& auth, const std::string& headers) {
    const DWORD deadline = GetTickCount() + kPartyWaitTimeoutMs;
    PartySessionError last_error("party session wait timed out");

    while (GetTickCount() < deadline) {
        try {
            return fetch_party_session(auth, headers);
        } catch (const PartySessionError& error) {
            last_error = error;
            Sleep(kPartyPollIntervalMs);
        }
    }

    throw last_error;
}

static void run_session_workflow() {
    const SessionAuth auth = SessionAuth::fetch();
    const std::string client_version = fetch_client_version(auth);

    emit_message(MessageType::Info, "Fetching sesh");
    const std::string headers = auth.build_pvp_headers(client_version);
    const PartySession party = fetch_party_session_with_wait(auth, headers);
    (void)party;

    emit_message(MessageType::Info, "sesh ready");
}

static void report_session_workflow_failures_to_listener() {
    try {
        run_session_workflow();
    } catch (const Error& error) {
        emit_message(MessageType::Failure, error.what());
    } catch (const std::exception& error) {
        emit_message(MessageType::Failure, std::string("unexpected failure: ") + error.what());
    }
}

}

inline void start_session() {
    bool expected = false;
    if (!running_flag().compare_exchange_strong(expected, true))
        throw AlreadyRunningError();
    
        std::thread([] {
        detail::report_session_workflow_failures_to_listener();
        running_flag() = false;
    }).detach();
}

}
