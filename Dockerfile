FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake libpcap-dev libpq-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt db_migration_add_dhcp.sql ./
COPY src/ ./src/
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF && cmake --build build --parallel

FROM builder AS tests
COPY tests/ ./tests/
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
RUN cmake -S . -B build -DBUILD_TESTING=ON && cmake --build build --parallel && ctest --test-dir build --output-on-failure

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 libpq5 ca-certificates && rm -rf /var/lib/apt/lists/* && mkdir /state
WORKDIR /app
COPY --from=builder /src/build/sniffer /app/sniffer
ENV SNIFFER_STATE_DIR=/state
ENTRYPOINT ["/app/sniffer"]
CMD ["--help"]
