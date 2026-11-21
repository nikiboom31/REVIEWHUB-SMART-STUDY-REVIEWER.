REVIEWERHUB — SMART STUDY REVIEWER
=================================

FILES
- index.html : website (HTML, CSS, JavaScript)
- server.cpp : small C++ web server
- httplib.h  : download this dependency (instructions below)

EASIEST WAY TO OPEN THE WEBSITE
1. Open index.html by double-clicking it.
2. It works in your browser without compiling C++.
3. Your added reviewers are saved in that browser.

RUN USING C++
1. Install a C++ compiler such as MinGW-w64 (g++).
2. Download the single header file httplib.h from:
   https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
   Save it in the same folder as server.cpp and index.html.
3. Open Command Prompt in this folder.
4. Compile on Windows with MinGW:
   g++ server.cpp -o reviewerhub.exe -std=c++17 -lws2_32
5. Run:
   reviewerhub.exe
6. Open this in your browser:
   http://localhost:8080

IMPORTANT
- The C++ program serves the website. The interactive reviewer features run
  in the browser using JavaScript.
- localhost means the website is available on your own computer.
- To make it searchable/public on the internet and accessible from other
  devices anywhere, you must deploy it to a hosting service and use a public
  domain or hosting URL. This starter project does not automatically publish
  itself to the internet.
