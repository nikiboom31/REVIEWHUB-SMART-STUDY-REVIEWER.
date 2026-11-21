
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    g++ cmake make \
    libsqlite3-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN g++ server.cpp -o reviewhub \
    -std=c++17 -lsqlite3 -lssl -lcrypto -pthread

EXPOSE 10000

CMD ["./reviewhub"]
