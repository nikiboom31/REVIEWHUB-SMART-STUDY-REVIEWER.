FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    g++ \
    libcpp-httplib-dev \
    libpq-dev \
    libssl-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN g++ server.cpp -o reviewhub \
    -std=c++17 -O2 -pthread \
    -I/usr/include \
    -lssl -lcrypto -lpq

EXPOSE 10000
CMD ["./reviewhub"]
