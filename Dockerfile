FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    g++ \
    make \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y \
    g++ \
    libpq-dev \
    libssl-dev \
    nlohmann-json3-dev
    
CMD ["./reviewhub"]
