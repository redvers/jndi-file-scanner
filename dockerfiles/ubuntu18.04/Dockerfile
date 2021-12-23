FROM ubuntu:18.04

ENV PATH "/root/.local/share/ponyup/bin:$PATH"

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates \
     clang \
     curl \
     git \
     libssl-dev \
     make \
     libpcre2-dev \
     libzip-dev

RUN sh -c "$(curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/ponylang/ponyup/latest-release/ponyup-init.sh)" \
 && ponyup update ponyc release --platform=ubuntu18.04 \
 && ponyup update stable release \
 && ponyup update corral release \
 && ponyup update changelog-tool release

WORKDIR /src/main

RUN sh -c "git clone https://github.com/redvers/jndi-file-scanner"
RUN sh -c "cd jndi-file-scanner && make"

