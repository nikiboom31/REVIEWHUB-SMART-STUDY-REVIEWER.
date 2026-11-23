#include "httplib.h"
#include <libpq-fe.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <vector>
#include <mutex>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using PgResult = std::unique_ptr<PGresult, decltype(&PQclear)>;
static std::mutex dbMutex;

std::string randomHex(int bytes=32) {
    unsigned char buffer[64];
    if (bytes > 64 || RAND_bytes(buffer, bytes) != 1) throw std::runtime_error("Secure random generator failed");
    std::ostringstream out;
    for (int i=0;i<bytes;i++) out << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
    return out.str();
}
std::string hashPassword(const std::string& password, const std::string& salt) {
    unsigned char hash[32];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
        reinterpret_cast<const unsigned char*>(salt.data()), (int)salt.size(),
        210000, EVP_sha256(), sizeof(hash), hash) != 1) throw std::runtime_error("Password hashing failed");
    std::ostringstream out;
    for (unsigned char c : hash) out << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return out.str();
}
std::string cookieValue(const httplib::Request& req, const std::string& name) {
    auto it=req.headers.find("Cookie"); if(it==req.headers.end()) return "";
    std::string all=it->second, key=name+"="; size_t p=all.find(key);
    if(p==std::string::npos) return ""; p+=key.size(); size_t e=all.find(';',p);
    return all.substr(p,e==std::string::npos?e:e-p);
}
void jsonResponse(httplib::Response& res, int status, const json& body) {
    res.status=status; res.set_content(body.dump(),"application/json; charset=utf-8");
}
bool validEmail(const std::string& email) {
    return email.size()<=254 && email.find('@')!=std::string::npos && email.find('.')!=std::string::npos;
}
PgResult query(PGconn* db, const char* sql, const std::vector<std::string>& values={}) {
    std::lock_guard<std::mutex> lock(dbMutex); // libpq connections must not be used concurrently
    std::vector<const char*> params; params.reserve(values.size());
    for (const auto& v : values) params.push_back(v.c_str());
    PGresult* raw=PQexecParams(db,sql,(int)params.size(),nullptr,params.empty()?nullptr:params.data(),nullptr,nullptr,0);
    PgResult result(raw, PQclear);
    if (!raw || (PQresultStatus(raw)!=PGRES_TUPLES_OK && PQresultStatus(raw)!=PGRES_COMMAND_OK))
        throw std::runtime_error(raw?PQresultErrorMessage(raw):PQerrorMessage(db));
    return result;
}
long long signedInUser(PGconn* db, const httplib::Request& req) {
    std::string token=cookieValue(req,"rh_session"); if(token.empty()) return 0;
    auto r=query(db,"SELECT user_id FROM rh_sessions WHERE token=$1 AND expires_at>NOW()",{token});
    return PQntuples(r.get()) ? std::stoll(PQgetvalue(r.get(),0,0)) : 0;
}
int main() {
    const char* dbUrl=std::getenv("DATABASE_URL");
    if(!dbUrl || !*dbUrl){std::cerr<<"DATABASE_URL is not set. Add your Supabase connection string in Render Environment.\n";return 1;}
    PGconn* db=PQconnectdb(dbUrl);
    if(PQstatus(db)!=CONNECTION_OK){std::cerr<<"Could not connect to Supabase: "<<PQerrorMessage(db)<<"\n";PQfinish(db);return 1;}
    try {
        query(db,"CREATE TABLE IF NOT EXISTS rh_users(id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,salt TEXT NOT NULL,password_hash TEXT NOT NULL)");
        query(db,"CREATE TABLE IF NOT EXISTS rh_topics(id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES rh_users(id) ON DELETE CASCADE,title TEXT NOT NULL,subject TEXT NOT NULL,content TEXT NOT NULL,question TEXT NOT NULL,answer TEXT NOT NULL,quiz_question TEXT NOT NULL,choices TEXT NOT NULL,correct TEXT NOT NULL)");
        query(db,"CREATE TABLE IF NOT EXISTS rh_sessions(token TEXT PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES rh_users(id) ON DELETE CASCADE,expires_at TIMESTAMPTZ NOT NULL)");
        query(db,"CREATE INDEX IF NOT EXISTS rh_topics_user_id_idx ON rh_topics(user_id)");
        query(db,"CREATE INDEX IF NOT EXISTS rh_sessions_expiry_idx ON rh_sessions(expires_at)");
    } catch(const std::exception& e){std::cerr<<"Database setup failed: "<<e.what()<<"\n";PQfinish(db);return 1;}

    httplib::Server server;
    server.set_default_headers({{"X-Content-Type-Options","nosniff"},{"X-Frame-Options","DENY"},{"Referrer-Policy","strict-origin-when-cross-origin"}});
    server.Get("/api/me",[&](const httplib::Request& req,httplib::Response& res){
        try {long long uid=signedInUser(db,req);if(!uid){jsonResponse(res,401,{{"error","Not signed in"}});return;}
            auto r=query(db,"SELECT email FROM rh_users WHERE id=$1",{std::to_string(uid)});
            if(!PQntuples(r.get())){jsonResponse(res,401,{{"error","Not signed in"}});return;}
            jsonResponse(res,200,{{"email",PQgetvalue(r.get(),0,0)}});
        }catch(...){jsonResponse(res,500,{{"error","Could not check your session."}});}
    });
    auto auth=[&](const httplib::Request& req,httplib::Response& res,bool registering){
        try{
            auto body=json::parse(req.body);std::string email=body.value("email",std::string()),password=body.value("password",std::string());
            std::transform(email.begin(),email.end(),email.begin(),[](unsigned char c){return (char)std::tolower(c);});
            if(!validEmail(email)||password.size()<8||password.size()>200){jsonResponse(res,400,{{"error","Enter a valid email and a password with at least 8 characters."}});return;}
            long long uid=0;
            if(registering){
                std::string salt=randomHex(16),hash=hashPassword(password,salt);
                auto r=query(db,"INSERT INTO rh_users(email,salt,password_hash) VALUES($1,$2,$3) ON CONFLICT(email) DO NOTHING RETURNING id",{email,salt,hash});
                if(!PQntuples(r.get())){jsonResponse(res,409,{{"error","That email is already registered. Please log in."}});return;}
                uid=std::stoll(PQgetvalue(r.get(),0,0));
            }else{
                auto r=query(db,"SELECT id,salt,password_hash FROM rh_users WHERE email=$1",{email});
                if(PQntuples(r.get())){uid=std::stoll(PQgetvalue(r.get(),0,0));std::string salt=PQgetvalue(r.get(),0,1),stored=PQgetvalue(r.get(),0,2);if(hashPassword(password,salt)!=stored)uid=0;}
                if(!uid){jsonResponse(res,401,{{"error","Incorrect email or password."}});return;}
            }
            std::string token=randomHex(32);
            query(db,"INSERT INTO rh_sessions(token,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 days')",{token,std::to_string(uid)});
            query(db,"DELETE FROM rh_sessions WHERE expires_at<NOW()");
            res.set_header("Set-Cookie","rh_session="+token+"; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000");
            jsonResponse(res,200,{{"email",email}});
        }catch(const std::exception& e){std::cerr<<"Authentication error: "<<e.what()<<"\n";jsonResponse(res,500,{{"error","Could not complete login. Please try again."}});}
    };
    server.Post("/api/register",[&](const httplib::Request& r,httplib::Response& s){auth(r,s,true);});
    server.Post("/api/login",[&](const httplib::Request& r,httplib::Response& s){auth(r,s,false);});
    server.Post("/api/logout",[&](const httplib::Request& req,httplib::Response& res){
        try {std::string token=cookieValue(req,"rh_session");if(!token.empty())query(db,"DELETE FROM rh_sessions WHERE token=$1",{token});}
        catch(...){ }
        res.set_header("Set-Cookie","rh_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");jsonResponse(res,200,{{"ok",true}});
    });
    server.Get("/api/topics",[&](const httplib::Request& req,httplib::Response& res){
        try {long long uid=signedInUser(db,req);if(!uid){jsonResponse(res,401,{{"error","Please log in first."}});return;}
            auto r=query(db,"SELECT id,title,subject,content,question,answer,quiz_question,choices,correct FROM rh_topics WHERE user_id=$1 ORDER BY id DESC",{std::to_string(uid)});
            json arr=json::array();for(int i=0;i<PQntuples(r.get());++i){arr.push_back({{"id",std::stoll(PQgetvalue(r.get(),i,0))},{"title",PQgetvalue(r.get(),i,1)},{"subject",PQgetvalue(r.get(),i,2)},{"content",PQgetvalue(r.get(),i,3)},{"question",PQgetvalue(r.get(),i,4)},{"answer",PQgetvalue(r.get(),i,5)},{"quizQuestion",PQgetvalue(r.get(),i,6)},{"choices",json::parse(PQgetvalue(r.get(),i,7))},{"correct",PQgetvalue(r.get(),i,8)}});}
            jsonResponse(res,200,{{"topics",arr}});
        }catch(const std::exception& e){std::cerr<<"Load topics error: "<<e.what()<<"\n";jsonResponse(res,500,{{"error","Could not load your reviewers."}});}
    });
    server.Post("/api/topics",[&](const httplib::Request& req,httplib::Response& res){
        try{
            long long uid=signedInUser(db,req);if(!uid){jsonResponse(res,401,{{"error","Please log in first."}});return;}
            auto b=json::parse(req.body);std::string title=b.at("title"),subject=b.at("subject"),content=b.at("content"),question=b.at("question"),answer=b.at("answer"),quiz=b.at("quizQuestion"),correct=b.at("correct");auto choices=b.at("choices");
            if(title.empty()||subject.empty()||content.empty()||!choices.is_array()||choices.size()<2||choices.size()>8||std::find(choices.begin(),choices.end(),json(correct))==choices.end()){jsonResponse(res,400,{{"error","Please complete the fields and provide 2–8 choices including the correct answer."}});return;}
            auto r=query(db,"INSERT INTO rh_topics(user_id,title,subject,content,question,answer,quiz_question,choices,correct) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id",{std::to_string(uid),title,subject,content,question,answer,quiz,choices.dump(),correct});
            long long id=std::stoll(PQgetvalue(r.get(),0,0));
            jsonResponse(res,201,{{"topic",{{"id",id},{"title",title},{"subject",subject},{"content",content},{"question",question},{"answer",answer},{"quizQuestion",quiz},{"choices",choices},{"correct",correct}}}});
        }catch(const std::exception& e){std::cerr<<"Save topic error: "<<e.what()<<"\n";jsonResponse(res,400,{{"error","Invalid reviewer data or database error."}});}
    });
    server.set_mount_point("/", ".");
    const char* portEnv=std::getenv("PORT");int port=8080;
    if(portEnv&&*portEnv){try{port=std::stoi(portEnv);}catch(...){std::cerr<<"Invalid PORT environment variable\n";PQfinish(db);return 1;}}
    std::cout<<"REVIEWHUB connected to Supabase; listening on port "<<port<<"\n";
    if(!server.listen("0.0.0.0",port)){std::cerr<<"Could not start server on port "<<port<<"\n";PQfinish(db);return 1;}
    PQfinish(db);return 0;
}
