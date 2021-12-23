FROM alpine:3.12

ENV PATH "/root/.local/share/ponyup/bin:$PATH"

RUN apk add --update --no-cache \
    clang \
    curl \
    build-base \
    binutils-gold \
    libexecinfo-dev \
    libexecinfo-static \
    git \
    pcre2 \
    pcre2-dev \
    openssl \
    openssl-dev \
    openssl-libs-static \
    libcrypto1.1 \
    cmake \
    zlib-static \
    libzip-dev

WORKDIR /src/main

RUN sh -c "wget https://tukaani.org/xz/xz-5.2.5.tar.gz && tar -zxvf xz-5.2.5.tar.gz"
RUN sh -c "cd xz-5.2.5 && ./configure --prefix=/usr && make && make install"

RUN sh -c "wget https://libzip.org/download/libzip-1.8.0.tar.gz && tar -zxvf libzip-1.8.0.tar.gz"
RUN sh -c "cd libzip-1.8.0 && mkdir build && cd build && cmake .. cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=/usr ; make ; make install"

RUN sh -c "$(curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/ponylang/ponyup/latest-release/ponyup-init.sh)" \
 && ponyup update ponyc release --platform=musl \
 && ponyup update stable release \
 && ponyup update corral release \
 && ponyup update changelog-tool release


RUN sh -c "git clone https://github.com/redvers/jndi-file-scanner"
RUN sh -c "cd jndi-file-scanner && echo 'use \"lib:lzma\"' > alpine.pony"
RUN sh -c "cd jndi-file-scanner && corral fetch && corral run -- ponyc --static"

