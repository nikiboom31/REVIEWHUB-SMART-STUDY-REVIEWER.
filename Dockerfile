FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    g++ \
    libsqlite3-dev \
    libssl-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN mkdir -p public && \
    g++ -std=c++17 -O2 server.cpp -o reviewhub \
      -I/usr/include/postgresql \
      -pthread -lssl -lcrypto -lpq
EXPOSE 10000

CMD ["./reviewhub"]
