#include "httplib.h"
#include <sqlite3.h>
#include <openssl/evp.h>
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
static std::mutex sessions_mutex;

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
long long signedInUser(const httplib::Request& req) {
    std::string token=cookieValue(req,"rh_session"); if(token.empty()) return 0;
    std::lock_guard<std::mutex> lock(sessions_mutex);
    auto it=sessions.find(token); return it==sessions.end()?0:it->second;
}
void jsonResponse(httplib::Response& res, int status, const json& body) {
    res.status=status; res.set_content(body.dump(),"application/json; charset=utf-8");
}
bool validEmail(const std::string& email) {
    return email.size()<=254 && email.find('@')!=std::string::npos && email.find('.')!=std::string::npos;
}
int main() {
    sqlite3* db=nullptr;
    if(sqlite3_open("reviewhub.db",&db)!=SQLITE_OK){std::cerr<<"Cannot open database\n";return 1;}
    const char* schema =
      "PRAGMA foreign_keys=ON;"
      "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,salt TEXT NOT NULL,password_hash TEXT NOT NULL);"
      "CREATE TABLE IF NOT EXISTS topics(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,title TEXT NOT NULL,subject TEXT NOT NULL,content TEXT NOT NULL,question TEXT NOT NULL,answer TEXT NOT NULL,quiz_question TEXT NOT NULL,choices TEXT NOT NULL,correct TEXT NOT NULL);";
    char* err=nullptr;
    if(sqlite3_exec(db,schema,nullptr,nullptr,&err)!=SQLITE_OK){std::cerr<<err<<"\n";sqlite3_free(err);return 1;}

    httplib::Server server;
    server.set_default_headers({{"X-Content-Type-Options","nosniff"},{"X-Frame-Options","DENY"},{"Referrer-Policy","strict-origin-when-cross-origin"}});
    server.Get("/api/me",[&](const httplib::Request& req,httplib::Response& res){
        long long uid=signedInUser(req); if(!uid){jsonResponse(res,401,{{"error","Not signed in"}});return;}
        sqlite3_stmt* st=nullptr;sqlite3_prepare_v2(db,"SELECT email FROM users WHERE id=?",-1,&st,nullptr);sqlite3_bind_int64(st,1,uid);
        std::string email;if(sqlite3_step(st)==SQLITE_ROW)email=(const char*)sqlite3_column_text(st,0);sqlite3_finalize(st);
        jsonResponse(res,200,{{"email",email}});
    });
    auto auth=[&](const httplib::Request& req,httplib::Response& res,bool registering){
        try{
            auto body=json::parse(req.body);std::string email=body.value("email",std::string()),password=body.value("password",std::string());
            std::transform(email.begin(),email.end(),email.begin(),[](unsigned char c){return (char)std::tolower(c);});
            if(!validEmail(email)||password.size()<8||password.size()>200){jsonResponse(res,400,{{"error","Enter a valid email and a password with at least 8 characters."}});return;}
            sqlite3_stmt* st=nullptr;long long uid=0;
            if(registering){
                std::string salt=randomHex(16),hash=hashPassword(password,salt);
                sqlite3_prepare_v2(db,"INSERT INTO users(email,salt,password_hash) VALUES(?,?,?)",-1,&st,nullptr);
                sqlite3_bind_text(st,1,email.c_str(),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,salt.c_str(),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,hash.c_str(),-1,SQLITE_TRANSIENT);
                if(sqlite3_step(st)!=SQLITE_DONE){sqlite3_finalize(st);jsonResponse(res,409,{{"error","That email is already registered. Please log in."}});return;}
                sqlite3_finalize(st);uid=sqlite3_last_insert_rowid(db);
            }else{
                sqlite3_prepare_v2(db,"SELECT id,salt,password_hash FROM users WHERE email=?",-1,&st,nullptr);sqlite3_bind_text(st,1,email.c_str(),-1,SQLITE_TRANSIENT);
                if(sqlite3_step(st)==SQLITE_ROW){uid=sqlite3_column_int64(st,0);std::string salt=(const char*)sqlite3_column_text(st,1),stored=(const char*)sqlite3_column_text(st,2);if(hashPassword(password,salt)!=stored)uid=0;}
                sqlite3_finalize(st);if(!uid){jsonResponse(res,401,{{"error","Incorrect email or password."}});return;}
            }
            std::string token=randomHex(32);{std::lock_guard<std::mutex> lock(sessions_mutex);sessions[token]=uid;}
            // For a public HTTPS deployment, add the Secure cookie attribute.
            res.set_header("Set-Cookie","rh_session="+token+"; HttpOnly; SameSite=Lax; Path=/");
            jsonResponse(res,200,{{"email",email}});
        }catch(const std::exception&){jsonResponse(res,400,{{"error","Invalid request."}});}
    };
    server.Post("/api/register",[&](const httplib::Request& r,httplib::Response& s){auth(r,s,true);});
    server.Post("/api/login",[&](const httplib::Request& r,httplib::Response& s){auth(r,s,false);});
    server.Post("/api/logout",[&](const httplib::Request& req,httplib::Response& res){
        std::string token=cookieValue(req,"rh_session");{std::lock_guard<std::mutex> lock(sessions_mutex);sessions.erase(token);}
        res.set_header("Set-Cookie","rh_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
        jsonResponse(res,200,{{"ok",true}});
    });
    server.Get("/api/topics",[&](const httplib::Request& req,httplib::Response& res){
        long long uid=signedInUser(req);if(!uid){jsonResponse(res,401,{{"error","Please log in first."}});return;}
        sqlite3_stmt* st=nullptr;sqlite3_prepare_v2(db,"SELECT id,title,subject,content,question,answer,quiz_question,choices,correct FROM topics WHERE user_id=? ORDER BY id DESC",-1,&st,nullptr);sqlite3_bind_int64(st,1,uid);
        json arr=json::array();while(sqlite3_step(st)==SQLITE_ROW){arr.push_back({{"id",sqlite3_column_int64(st,0)},{"title",(const char*)sqlite3_column_text(st,1)},{"subject",(const char*)sqlite3_column_text(st,2)},{"content",(const char*)sqlite3_column_text(st,3)},{"question",(const char*)sqlite3_column_text(st,4)},{"answer",(const char*)sqlite3_column_text(st,5)},{"quizQuestion",(const char*)sqlite3_column_text(st,6)},{"choices",json::parse((const char*)sqlite3_column_text(st,7))},{"correct",(const char*)sqlite3_column_text(st,8)}});}
        sqlite3_finalize(st);jsonResponse(res,200,{{"topics",arr}});
    });
    server.Post("/api/topics",[&](const httplib::Request& req,httplib::Response& res){
        long long uid=signedInUser(req);if(!uid){jsonResponse(res,401,{{"error","Please log in first."}});return;}
        try{
            auto b=json::parse(req.body);std::string title=b.at("title"),subject=b.at("subject"),content=b.at("content"),question=b.at("question"),answer=b.at("answer"),quiz=b.at("quizQuestion"),correct=b.at("correct");auto choices=b.at("choices");
            if(title.empty()||subject.empty()||content.empty()||!choices.is_array()||choices.size()<2||choices.size()>8||std::find(choices.begin(),choices.end(),json(correct))==choices.end()){jsonResponse(res,400,{{"error","Please complete the fields and provide 2–8 choices including the correct answer."}});return;}
            sqlite3_stmt* st=nullptr;const char* sql="INSERT INTO topics(user_id,title,subject,content,question,answer,quiz_question,choices,correct) VALUES(?,?,?,?,?,?,?,?,?)";
            sqlite3_prepare_v2(db,sql,-1,&st,nullptr);sqlite3_bind_int64(st,1,uid);
            std::string values[]={title,subject,content,question,answer,quiz,choices.dump(),correct};
            for(int i=0;i<8;i++)sqlite3_bind_text(st,i+2,values[i].c_str(),-1,SQLITE_TRANSIENT);
            if(sqlite3_step(st)!=SQLITE_DONE){sqlite3_finalize(st);jsonResponse(res,500,{{"error","Could not save reviewer."}});return;}
            long long id=sqlite3_last_insert_rowid(db);sqlite3_finalize(st);
            jsonResponse(res,201,{{"topic",{{"id",id},{"title",title},{"subject",subject},{"content",content},{"question",question},{"answer",answer},{"quizQuestion",quiz},{"choices",choices},{"correct",correct}}}});
        }catch(...){jsonResponse(res,400,{{"error","Invalid reviewer data."}});}
    });
    server.set_mount_point("/",".");
    std::cout<<"REVIEWHUB server running at http://localhost:8080\nPress Ctrl+C to stop.\n";
    if(!server.const char* port_env = std::getenv("PORT");
int port = port_env ? std::stoi(port_env) : 8080;

server.listen("0.0.0.0", port);{std::cerr<<"Could not start server. Is port 8080 already in use?\n";sqlite3_close(db);return 1;}
    sqlite3_close(db);return 0;
}
