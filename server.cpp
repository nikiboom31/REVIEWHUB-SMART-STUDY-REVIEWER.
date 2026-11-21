#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server server;

    // Serve the website files from the same folder as this program.
    server.set_mount_point("/", "./");

    std::cout << "ReviewerHub is running!\n";
    std::cout << "Open this address in your browser: http://localhost:8080\n";
    std::cout << "Press Ctrl + C to stop the server.\n";

    if (!server.listen("0.0.0.0", 8080)) {
        std::cerr << "Could not start server. Port 8080 may already be in use.\n";
        return 1;
    }
    return 0;
}
