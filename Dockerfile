
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    g++ \
    make \
    libssl-dev \
    libpq-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN g++ server.cpp -o reviewhub \
    -std=c++17 -O2 -pthread \
    -I/usr/include/postgresql \
    -lssl -lcrypto -lpq

CMD ["./reviewhub"]
