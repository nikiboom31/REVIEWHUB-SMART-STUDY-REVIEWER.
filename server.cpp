#include <httplib.h>
#include <libpq-fe.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;
using PgResult = std::unique_ptr<PGresult, decltype(&PQclear)>;

static std::mutex dbMutex;

std::string randomHex(int bytes = 32) {
    if (bytes <= 0 || bytes > 64) throw std::runtime_error("Invalid random byte count");
    unsigned char buffer[64];
    if (RAND_bytes(buffer, bytes) != 1) throw std::runtime_error("Secure random generator failed");
    std::ostringstream out;
    for (int i = 0; i < bytes; ++i)
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    return out.str();
}

std::string hashPassword(const std::string& password, const std::string& salt) {
    unsigned char hash[32];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()), static_cast<int>(salt.size()),
        210000, EVP_sha256(), sizeof(hash), hash) != 1)
        throw std::runtime_error("Password hashing failed");
    std::ostringstream out;
    for (unsigned char c : hash)
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    return out.str();
}

std::string cookieValue(const httplib::Request& req, const std::string& name) {
    auto it = req.headers.find("Cookie");
    if (it == req.headers.end()) return "";
    const std::string& all = it->second;
    const std::string key = name + "=";
    size_t p = all.find(key);
    if (p == std::string::npos) return "";
    // Ensure cookie name begins at cookie boundary.
    if (p != 0 && all[p - 1] != ';') return "";
    p += key.size();
    size_t e = all.find(';', p);
    return all.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

void jsonResponse(httplib::Response& res, int status, const json& body) {
    res.status = status;
    res.set_content(body.dump(), "application/json; charset=utf-8");
}

bool validEmail(const std::string& email) {
    return email.size() <= 254 &&
           email.find('@') != std::string::npos &&
           email.find('.') != std::string::npos;
}

PgResult query(PGconn* db, const char* sql, const std::vector<std::string>& values = {}) {
    std::lock_guard<std::mutex> lock(dbMutex);
    std::vector<const char*> params;
    params.reserve(values.size());
    for (const auto& v : values) params.push_back(v.c_str());

    PGresult* raw = PQexecParams(db, sql, static_cast<int>(params.size()), nullptr,
        params.empty() ? nullptr : params.data(), nullptr, nullptr, 0);
    PgResult result(raw, PQclear);
    if (!raw || (PQresultStatus(raw) != PGRES_TUPLES_OK &&
                 PQresultStatus(raw) != PGRES_COMMAND_OK))
        throw std::runtime_error(raw ? PQresultErrorMessage(raw) : PQerrorMessage(db));
    return result;
}

long long signedInUser(PGconn* db, const httplib::Request& req) {
    std::string token = cookieValue(req, "rh_session");
    if (token.empty()) return 0;
    auto r = query(db, "SELECT user_id FROM rh_sessions WHERE token=$1 AND expires_at>NOW()", {token});
    return PQntuples(r.get()) ? std::stoll(PQgetvalue(r.get(), 0, 0)) : 0;
}

int main() {
    const char* dbUrl = std::getenv("DATABASE_URL");
    if (!dbUrl || !*dbUrl) {
        std::cerr << "DATABASE_URL is not set. Configure it in Render Environment.\n";
