# AgileNet 测试镜像：anet-svc 单产物（serve / client / cli 子命令）
# 构建：docker build -f .docker/Dockerfile -t anet:dev .

FROM rust:1-bookworm AS builder
WORKDIR /src

# 先拷贝清单，利用依赖层缓存
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/node/Cargo.toml crates/node/Cargo.toml
COPY crates/client/Cargo.toml crates/client/Cargo.toml

# 占位源码预编译依赖（加速后续源码变更的重构）
RUN mkdir -p crates/core/src crates/node/src crates/client/src \
    && echo 'fn main(){}' > crates/core/src/lib.rs \
    && echo 'fn main(){}' > crates/node/src/main.rs \
    && echo 'fn main(){}' > crates/node/src/lib.rs \
    && echo 'fn main(){}' > crates/client/src/lib.rs \
    && cargo build --release -p agile-net-node || true

# 真实源码构建
COPY crates ./crates
RUN touch crates/core/src/lib.rs crates/node/src/lib.rs crates/client/src/lib.rs \
    && cargo build --release -p agile-net-node

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl jq procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/anet-svc /usr/local/bin/
RUN mkdir -p /data/certs && chmod 700 /data

ENV RUST_LOG=info
CMD ["anet-svc", "serve"]
