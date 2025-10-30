FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN echo "deb http://archive.ubuntu.com/ubuntu/ jammy main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "# deb-src http://archive.ubuntu.com/ubuntu/ jammy main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb http://archive.ubuntu.com/ubuntu/ jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "# deb-src http://archive.ubuntu.com/ubuntu/ jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb http://archive.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "# deb-src http://archive.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb http://archive.ubuntu.com/ubuntu/ jammy-backports main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "# deb-src http://archive.ubuntu.com/ubuntu/ jammy-backports main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb http://archive.canonical.com/ubuntu/ jammy partner" >> /etc/apt/sources.list && \
    echo "# deb-src http://archive.canonical.com/ubuntu/ jammy partner" >> /etc/apt/sources.list


RUN apt update && \
    apt install -y gcc-mingw-w64-x86-64=10.3.0-14ubuntu1+24.3 \
                   nasm \
                   make \
                   python3-pip && \
    pip install pefile --break-system-packages && \
    pip install argparse --break-system-packages && \
    apt clean && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]