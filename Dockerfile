FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    make \
    curl \
    libssl-dev \
    libpq-dev \
    libcpp-httplib-dev \
    nlohmann-json3-dev \
    ca-certificates \
    && curl -fsSL https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h -o /usr/local/include/httplib.h \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN mkdir -p public && \
    g++ -std=c++17 -O2 server.cpp -o reviewhub \
      -I/usr/include/postgresql \
      -pthread -lssl -lcrypto -lpq

EXPOSE 10000
CMD ["./reviewhub"]
