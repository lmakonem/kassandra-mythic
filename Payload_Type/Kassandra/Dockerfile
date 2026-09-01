# ---- Stage 1: catalog-builder ----
# Clones TSEC CS-SA-BOF, Outflank C2-Tool-Collection, Flangvik SharpCollection at pinned
# commits, compiles BOFs with mingw-w64 + .NET tools with dotnet SDK, emits /catalog.
FROM ubuntu:22.04 AS catalog-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      git make mingw-w64 nasm \
      python3 curl ca-certificates gnupg && \
    curl -sSL https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -o /tmp/ms.deb && \
    dpkg -i /tmp/ms.deb && \
    apt-get update && \
    apt-get install -y --no-install-recommends dotnet-sdk-8.0 && \
    rm -rf /var/lib/apt/lists/* /tmp/ms.deb

ARG TSEC_REF=ee9459cc4f42c6b025797bad22ffe8d9f1cf6487
ARG OUTFLANK_REF=e371a38c717edaf1650923575ab33bee0dd3e0ee
ARG SHARP_REF=dad01b93abf5074e72b94218b74bee310f6eb74a

WORKDIR /src
RUN git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF.git tsec && \
    git -C tsec checkout ${TSEC_REF}
RUN git clone https://github.com/outflanknl/C2-Tool-Collection.git outflank && \
    git -C outflank checkout ${OUTFLANK_REF}
RUN git clone https://github.com/Flangvik/SharpCollection.git sharp && \
    git -C sharp checkout ${SHARP_REF}

COPY build_catalog.sh /tmp/build_catalog.sh
RUN chmod +x /tmp/build_catalog.sh && /tmp/build_catalog.sh


# ---- Stage 2: runtime ----
FROM ubuntu:22.04

ARG CA_CERTIFICATE
ARG NPM_REGISTRY
ARG PYPI_INDEX
ARG PYPI_INDEX_URL
ARG DOCKER_REGISTRY_MIRROR
ARG HTTP_PROXY
ARG HTTPS_PROXY

ENV DEBIAN_FRONTEND=noninteractive


# combine update+install into one RUN to keep indices fresh
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      build-essential curl zip nasm \
      libssl-dev zlib1g-dev libbz2-dev \
      xz-utils tk-dev libffi-dev liblzma-dev \
      libsqlite3-dev protobuf-compiler \
      software-properties-common apt-utils \
      mingw-w64 \
      osslsigncode openssl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=catalog-builder /catalog /opt/kassandra_catalog


ENV PATH="/root/.cargo/bin:/usr/local/go/bin:${PATH}"
ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc

# Donut (TheWover): convert built PE EXE to position-independent shellcode.
# Same tooling Apollo uses for output_type=Shellcode. Binary from official v1.1 release.
ARG DONUT_VERSION=v1.1
ARG DONUT_SHA256=033132caee328c6d53cf6074719bfa326d88044484cc8bcbce0eaeeb73dd6494
RUN mkdir -p /opt/donut /tmp/donut_src && \
    curl -fsSL -o /tmp/donut.tar.gz \
      "https://github.com/TheWover/donut/releases/download/${DONUT_VERSION}/donut_${DONUT_VERSION}.tar.gz" && \
    echo "${DONUT_SHA256}  /tmp/donut.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/donut.tar.gz -C /tmp/donut_src && \
    install -m 0755 /tmp/donut_src/donut /opt/donut/donut && \
    ln -sf /opt/donut/donut /usr/local/bin/donut && \
    rm -rf /tmp/donut.tar.gz /tmp/donut_src

# Install Go (needed to build tailscale FFI library)
# Using Go 1.27.0 (latest stable as of 2026-08)
ARG GO_VERSION=1.27.0
ARG GO_SHA256=675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685
RUN curl -fsSL -o /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" && \
    echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

# Install Rust with checksum verification
# rustup-init.sh is fetched over HTTPS from the official domain; no pinned hash
# because rustup.rs updates it silently and a stale sha breaks the build.
RUN curl -fsSL -o /tmp/rustup-init.sh https://sh.rustup.rs && \
    sh /tmp/rustup-init.sh -y --default-toolchain nightly && \
    rm /tmp/rustup-init.sh && \
    rustup target add x86_64-pc-windows-gnu && \
    rustup toolchain install nightly-2025-04-30 && \
    rustup +nightly-2025-04-30 target add x86_64-pc-windows-gnu

# Pre-warm dependency cache (dummy-build pattern, same idea as Sliver's warm GOCACHE).
# Copies Cargo.toml + Cargo.lock with a stub main.rs, compiles all 245 deps once into
# /opt/kassandra_cache. Payload builds reuse this cache and only recompile the kassandra
# crate itself (~15s vs ~10min). The cache is valid as long as Cargo.toml/Cargo.lock are
# unchanged; adding/removing a dep triggers a partial rebuild (only the new crate).
COPY Kassandra/agent_code/kassandra/Cargo.toml Kassandra/agent_code/kassandra/Cargo.lock /tmp/depcache/kassandra/
RUN mkdir -p /tmp/depcache/kassandra/src && \
    echo "fn main(){}" > /tmp/depcache/kassandra/src/main.rs && \
    echo "pub fn lib(){}" > /tmp/depcache/kassandra/src/lib.rs && \
    cd /tmp/depcache/kassandra && \
    CARGO_TARGET_DIR=/opt/kassandra_cache \
      cargo +nightly-2025-04-30 build --release --target x86_64-pc-windows-gnu && \
    CARGO_TARGET_DIR=/opt/kassandra_cache \
      cargo +nightly-2025-04-30 build --release --target x86_64-pc-windows-gnu \
        --features no_console && \
    CARGO_TARGET_DIR=/opt/kassandra_cache \
      cargo +nightly-2025-04-30 build --release --target x86_64-pc-windows-gnu \
        --features debug_log && \
    CARGO_TARGET_DIR=/opt/kassandra_cache \
      cargo +nightly-2025-04-30 build --release --target x86_64-pc-windows-gnu \
        --features no_console,debug_log && \
    CARGO_TARGET_DIR=/opt/kassandra_cache \
      cargo +nightly-2025-04-30 build --release --target x86_64-pc-windows-gnu \
        --features tailscale && \
    CARGO_TARGET_DIR=/opt/kassandra_cache \
      cargo +nightly-2025-04-30 build --release --target x86_64-pc-windows-gnu \
        --features tailscale,no_console,debug_log && \
    rm -rf /tmp/depcache

# Pre-build loader DLLs (BOF + .NET)
# Fix: beacon_api.rs args.as_va_list() removed in nightly 2025+; pass args directly.
COPY Kassandra/agent_code/kassandra/loaders /tmp/loaders
RUN cd /tmp/loaders/bof-loader &&     cargo +nightly build --release --target x86_64-pc-windows-gnu &&     cd /tmp/loaders/dot-loader &&     cargo +nightly build --release --target x86_64-pc-windows-gnu &&     mkdir -p /opt/loaders &&     cp /tmp/loaders/bof-loader/target/x86_64-pc-windows-gnu/release/bof_loader.dll /opt/loaders/bof_loader.dll &&     cp /tmp/loaders/dot-loader/target/x86_64-pc-windows-gnu/release/dot_loader.dll /opt/loaders/dot_loader.dll &&     rm -rf /tmp/loaders

COPY requirements.txt /
RUN pip3 install -r /requirements.txt


# Pre-build the Tailscale FFI static library for Windows (cross-compiled via Go + mingw)
COPY Kassandra/agent_code/kassandra/tailscale_ffi /tmp/tailscale_ffi
RUN cd /tmp/tailscale_ffi && \
    go mod tidy && \
    CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 \
      go build -buildmode=c-archive -ldflags="-s -w" -o /opt/tailscale_ffi/libtailscale_ffi.a . && \
    rm -rf /tmp/tailscale_ffi

WORKDIR /Mythic/
CMD ["python3", "main.py"]
