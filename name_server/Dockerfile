FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=nointeractive
ARG LISTENIP

ENV LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib:/usr/lib/x86_64-linux-gnu/:${LD_LIBRARY_PATH}

# Set up OQS and bind
RUN apt update 
RUN apt upgrade -y
RUN apt install ssh curl cmake gcc pkg-config autoconf automake git build-essential ninja-build libnghttp2-dev libcap-dev libtool libtool-bin libuv1-dev unzip iputils-ping iptables iproute2 liburcu-dev libnetfilter-queue-dev libpcap-dev net-tools -y
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
RUN ln -s /usr/local/lib64/libcrypto.so /usr/lib/x86_64-linux-gnu/libcrypto.so
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
COPY named.conf /usr/local/etc
RUN mkdir /setup_files
COPY add_ds.bash /setup_files/
COPY move_ds.bash /setup_files/
RUN ldconfig 
# Setting up daemon
COPY ./qbf/src /qbf/src
COPY ./qbf/include /qbf/include
COPY ./qbf/c-hashmap /qbf/c-hashmap
COPY ./qbf/makefile /qbf/makefile
WORKDIR /qbf
RUN make daemon
ENV LISTENIP=${LISTENIP}
WORKDIR /
