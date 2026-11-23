                uid = std::stoll(PQgetvalue(r.get(), 0, 0));
            } else {
                auto r = query(db, "SELECT id,salt,password_hash FROM rh_users WHERE email=$1", {email});
                if (PQntuples(r.get())) {
                    uid = std::stoll(PQgetvalue(r.get(), 0, 0));
                    std::string salt = PQgetvalue(r.get(), 0, 1);
                    std::string stored = PQgetvalue(r.get(), 0, 2);
                    if (hashPassword(password, salt) != stored) uid = 0;
                }
                if (!uid) { jsonResponse(res, 401, {{"error", "Incorrect email or password."}}); return; }
            }

            std::string token = randomHex(32);
            query(db, "INSERT INTO rh_sessions(token,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 days')", {token, std::to_string(uid)});
            query(db, "DELETE FROM rh_sessions WHERE expires_at<NOW()");
            res.set_header("Set-Cookie", "rh_session=" + token + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000");
            jsonResponse(res, 200, {{"email", email}});
        } catch (const std::exception& e) {
            std::cerr << "Authentication error: " << e.what() << "\n";
            jsonResponse(res, 500, {{"error", "Could not complete login. Please try again."}});
        }
    };

    server.Post("/api/register", [&](const httplib::Request& r, httplib::Response& s) { auth(r, s, true); });
    server.Post("/api/login", [&](const httplib::Request& r, httplib::Response& s) { auth(r, s, false); });

    server.Post("/api/logout", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            std::string token = cookieValue(req, "rh_session");
            if (!token.empty()) query(db, "DELETE FROM rh_sessions WHERE token=$1", {token});
        } catch (...) {}
        res.set_header("Set-Cookie", "rh_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
        jsonResponse(res, 200, {{"ok", true}});
    });

    server.Get("/api/topics", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            long long uid = signedInUser(db, req);
            if (!uid) { jsonResponse(res, 401, {{"error", "Please log in first."}}); return; }
            auto r = query(db, "SELECT id,title,subject,content,question,answer,quiz_question,choices,correct FROM rh_topics WHERE user_id=$1 ORDER BY id DESC", {std::to_string(uid)});
            json arr = json::array();
            for (int i = 0; i < PQntuples(r.get()); ++i) {
                arr.push_back({
                    {"id", std::stoll(PQgetvalue(r.get(), i, 0))},
                    {"title", PQgetvalue(r.get(), i, 1)},
                    {"subject", PQgetvalue(r.get(), i, 2)},
                    {"content", PQgetvalue(r.get(), i, 3)},
                    {"question", PQgetvalue(r.get(), i, 4)},
                    {"answer", PQgetvalue(r.get(), i, 5)},
                    {"quizQuestion", PQgetvalue(r.get(), i, 6)},
                    {"choices", json::parse(PQgetvalue(r.get(), i, 7))},
                    {"correct", PQgetvalue(r.get(), i, 8)}
                });
            }
            jsonResponse(res, 200, {{"topics", arr}});
        } catch (const std::exception& e) {
            std::cerr << "Load topics error: " << e.what() << "\n";
            jsonResponse(res, 500, {{"error", "Could not load your reviewers."}});
        }
    });

    server.Post("/api/topics", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            long long uid = signedInUser(db, req);
            if (!uid) { jsonResponse(res, 401, {{"error", "Please log in first."}}); return; }
            auto b = json::parse(req.body);
            std::string title = b.at("title"), subject = b.at("subject"), content = b.at("content");
            std::string question = b.at("question"), answer = b.at("answer");
            std::string quiz = b.at("quizQuestion"), correct = b.at("correct");
            auto choices = b.at("choices");

            if (title.empty() || subject.empty() || content.empty() || !choices.is_array() ||
                choices.size() < 2 || choices.size() > 8 ||
                std::find(choices.begin(), choices.end(), json(correct)) == choices.end()) {
                jsonResponse(res, 400, {{"error", "Please complete the fields and provide 2–8 choices including the correct answer."}});
                return;
            }
            auto r = query(db, "INSERT INTO rh_topics(user_id,title,subject,content,question,answer,quiz_question,choices,correct) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id",
                {std::to_string(uid), title, subject, content, question, answer, quiz, choices.dump(), correct});
            long long id = std::stoll(PQgetvalue(r.get(), 0, 0));
            jsonResponse(res, 201, {{"topic", {
                {"id", id}, {"title", title}, {"subject", subject}, {"content", content},
                {"question", question}, {"answer", answer}, {"quizQuestion", quiz},
                {"choices", choices}, {"correct", correct}
            }}});
        } catch (const std::exception& e) {
            std::cerr << "Save topic error: " << e.what() << "\n";
            jsonResponse(res, 400, {{"error", "Invalid reviewer data or database error."}});
        }
    });

    // Serve frontend assets from ./public only. Avoid exposing source files and secrets.
    server.set_mount_point("/", "./public");

    const char* portEnv = std::getenv("PORT");
    int port = 10000;
    if (portEnv && *portEnv) {
        try { port = std::stoi(portEnv); }
        catch (...) { std::cerr << "Invalid PORT environment variable\n"; PQfinish(db); return 1; }
    }

    std::cout << "ReviewHub connected to database; listening on port " << port << "\n";
    if (!server.listen("0.0.0.0", port)) {
        std::cerr << "Could not start server on port " << port << "\n";
        PQfinish(db);
        return 1;
    }
    PQfinish(db);
    return 0;
}
