FROM ubuntu:22.04
RUN apt update 
RUN apt upgrade -y
#RUN DEBIAN_FRONTEND="noninteractive" apt install ssh vim iputils-ping iptables iproute2 curl git pkg-config autoconf automake build-essential libnghttp2-dev libtool libtool-bin libuv1-dev libcap-dev astyle cmake gcc ninja-build unzip -y
RUN DEBIAN_FRONTEND="noninteractive" apt install ssh curl cmake gcc pkg-config autoconf automake git build-essential ninja-build libnghttp2-dev libcap-dev libtool libtool-bin libuv1-dev unzip iputils-ping iptables iproute2 liburcu-dev -y
WORKDIR /
# Install OpenSSL 3.2.5
RUN curl -L -O https://github.com/openssl/openssl/releases/download/openssl-3.2.5/openssl-3.2.5.tar.gz
RUN tar -xzvf openssl-3.2.5.tar.gz
RUN rm openssl-3.2.5.tar.gz
WORKDIR openssl-3.2.5
RUN ./Configure
RUN make
RUN make install
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
CMD ["/bin/bash"]
