#This docker file is expected to be run from the root of s2n
#e.g. `docker build --rm -f "tests\saw\Dockerfile" -t saw:latest .`
FROM ubuntu:xenial

RUN apt update && \
    apt install -y \
    clang \
    clang-3.8 \
    curl \
    git \
    language-pack-en \
    libssl-dev \
    llvm-3.8 \
    make

COPY /.travis/ ~/.travis/

WORKDIR ~/

ENV TESTS=tls \
    SAW=true \
    GCC_VERSION=NONE

RUN ./.travis/install_saw.sh ./tmp /saws2n/

RUN NO_SUDO=true ./.travis/install_z3_yices.sh ./tmp/ /provers/

ENV PATH="/saws2n/bin:${PATH}"
ENV PATH="/provers/bin:${PATH}"

