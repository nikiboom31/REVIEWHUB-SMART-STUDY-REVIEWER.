FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    make \
    libssl-dev \
    libpq-dev \
    libcpp-httplib-dev \
    nlohmann-json3-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
-
RUN mkdir -p public && \
    g++ server.cpp -o reviewhub \
-       -std=c++17 -O2 -pthread \
-      -std=c++17 -O2 -pthread \
-      -I/usr/include/postgresql \
-     -lcpp-httplib -lssl -lcrypto -lpq

CMD ["./reviewhub"]
