FROM ubuntu:22.04

ARG DEBIAN_FRONTEND="noninteractive" 

RUN apt update
RUN apt upgrade -y
RUN apt install ssh curl cmake gcc pkg-config autoconf automake git build-essential ninja-build libnghttp2-dev libcap-dev libtool libtool-bin libuv1-dev unzip iputils-ping iptables iproute2 liburcu-dev libnetfilter-queue-dev libpcap-dev net-tools netcat traceroute iperf libnl-3-dev libnl-genl-3-dev binutils-dev libreadline6-dev -y
WORKDIR /
# Install OpenSSL 3.2.5
RUN curl -L -O https://github.com/openssl/openssl/releases/download/openssl-3.2.5/openssl-3.2.5.tar.gz
RUN tar -xzvf openssl-3.2.5.tar.gz
RUN rm openssl-3.2.5.tar.gz
WORKDIR openssl-3.2.5
RUN ./Configure
RUN make
RUN make install
RUN sed -i 's/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/' /usr/local/ssl/openssl.cnf
RUN echo -e "[oqsprovider_sect]\nactivate = 1" >> /usr/local/ssl/openssl.cnf
RUN echo "/usr/local/lib64" > /etc/ld.so.conf.d/openssl.conf
RUN ln -s /usr/local/lib64/libcrypto.so /usr/lib/x86_64-linux-gnu/libcrypto.so
RUN ldconfig 
# Install liboqs 0.14.0
WORKDIR /
RUN git clone https://github.com/open-quantum-safe/liboqs.git --branch 0.14.0
RUN mkdir liboqs/build
WORKDIR liboqs/build
RUN cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
RUN ninja
RUN ninja install
# Install oqs-provider 0.10.0
WORKDIR /
RUN git clone https://github.com/open-quantum-safe/oqs-provider.git --branch 0.10.0
WORKDIR oqs-provider
RUN cmake -S . -B _build && cmake --build _build && cmake --install _build
# Install OQS-bind
WORKDIR /
RUN git clone https://github.com/mr-torgue/OQS-bind.git
WORKDIR OQS-bind
RUN autoreconf -fi
RUN ./configure 
RUN make
RUN make install
RUN mkdir /usr/local/etc/bind
RUN mkdir /usr/local/etc/bind/zones
RUN mkdir /var/cache/bind
RUN mkdir /setup_files/
# Setting up daemon
COPY ./qbf-daemon/src /qbf/src
COPY ./qbf-daemon/include /qbf/include
COPY ./qbf-daemon/c-hashmap /qbf/c-hashmap
COPY ./qbf-daemon/makefile /qbf/makefile
WORKDIR /qbf
RUN make daemon
RUN ldconfig 