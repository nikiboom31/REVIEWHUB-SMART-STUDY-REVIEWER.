#include <openssl/rand.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <string>

using json = nlohmann::json;
static std::unordered_map<std::string, long long> sessions;
@@ -51,8 +51,19 @@ bool validEmail(const std::string& email) {
return email.size()<=254 && email.find('@')!=std::string::npos && email.find('.')!=std::string::npos;
}
int main() {
    // Render's filesystem is temporary unless a persistent disk is attached.
    // Set DATABASE_PATH=/var/data/reviewhub.db in Render after attaching a disk
    // mounted at /var/data. Locally, this defaults to ./reviewhub.db.
    const char* configuredDbPath = std::getenv("DATABASE_PATH");
    const char* dbPath = (configuredDbPath && *configuredDbPath)
        ? configuredDbPath : "reviewhub.db";
sqlite3* db=nullptr;
    if(sqlite3_open("reviewhub.db",&db)!=SQLITE_OK){std::cerr<<"Cannot open database\n";return 1;}
    if(sqlite3_open(dbPath,&db)!=SQLITE_OK){
        std::cerr<<"Cannot open database at "<<dbPath<<"\n";
        if(db) sqlite3_close(db);
        return 1;
    }
    sqlite3_busy_timeout(db, 5000);
const char* schema =
"PRAGMA foreign_keys=ON;"
"CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,salt TEXT NOT NULL,password_hash TEXT NOT NULL);"
@@ -86,16 +97,16 @@ int main() {
sqlite3_finalize(st);if(!uid){jsonResponse(res,401,{{"error","Incorrect email or password."}});return;}
}
std::string token=randomHex(32);{std::lock_guard<std::mutex> lock(sessions_mutex);sessions[token]=uid;}
            // For a public HTTPS deployment, add the Secure cookie attribute.
            res.set_header("Set-Cookie","rh_session="+token+"; HttpOnly; SameSite=Lax; Path=/");
            // Render serves this site over HTTPS, so mark the session cookie Secure.
            res.set_header("Set-Cookie","rh_session="+token+"; HttpOnly; Secure; SameSite=Lax; Path=/");
jsonResponse(res,200,{{"email",email}});
}catch(const std::exception&){jsonResponse(res,400,{{"error","Invalid request."}});}
};
server.Post("/api/register",[&](const httplib::Request& r,httplib::Response& s){auth(r,s,true);});
server.Post("/api/login",[&](const httplib::Request& r,httplib::Response& s){auth(r,s,false);});
server.Post("/api/logout",[&](const httplib::Request& req,httplib::Response& res){
std::string token=cookieValue(req,"rh_session");{std::lock_guard<std::mutex> lock(sessions_mutex);sessions.erase(token);}
        res.set_header("Set-Cookie","rh_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
        res.set_header("Set-Cookie","rh_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
jsonResponse(res,200,{{"ok",true}});
});
server.Get("/api/topics",[&](const httplib::Request& req,httplib::Response& res){
@@ -118,21 +129,15 @@ int main() {
jsonResponse(res,201,{{"topic",{{"id",id},{"title",title},{"subject",subject},{"content",content},{"question",question},{"answer",answer},{"quizQuestion",quiz},{"choices",choices},{"correct",correct}}}});
}catch(...){jsonResponse(res,400,{{"error","Invalid reviewer data."}});}
});

    server.set_mount_point("/", ".");

    const char* port_env = std::getenv("PORT");
    int port = port_env ? std::stoi(port_env) : 8080;

    std::cout << "REVIEWHUB server running on port " << port << "\n";

    if (!server.listen("0.0.0.0", port)) {
        std::cerr << "Could not start server.\n";
        sqlite3_close(db);
        return 1;
    server.set_mount_point("/",".");
    const char* portEnv = std::getenv("PORT");
    int port = 8080;
    if(portEnv && *portEnv){
        try { port = std::stoi(portEnv); }
        catch(...) { std::cerr<<"Invalid PORT environment variable\n"; sqlite3_close(db); return 1; }
}

    sqlite3_close(db);
    return 0;
    std::cout<<"REVIEWHUB server listening on port "<<port
             <<" with database "<<dbPath<<"\n";
    if(!server.listen("0.0.0.0",port)){std::cerr<<"Could not start server on port "<<port<<"\n";sqlite3_close(db);return 1;}
    sqlite3_close(db);return 0;
}
