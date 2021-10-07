FROM ubuntu:14.04

RUN apt update
RUN apt install -y gcc-arm-linux-gnueabihf 1>/dev/null
RUN apt install -y curl 1>/dev/null
RUN apt install -y build-essential 1>/dev/null

RUN curl -k https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz -o /root/openssl-1.0.2u.tar.gz
RUN tar zxf /root/openssl-1.0.2u.tar.gz -C /root

WORKDIR /root/openssl-1.0.2u
RUN TARGETMACH=arm-linux-gnueabihf BUILDMACH=i686-pc-linux-gnu AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib ./Configure linux-generic32 --cross-compile-prefix=arm-linux-gnueabihf- --prefix=/root/opensslArm
RUN TARGETMACH=arm-linux-gnueabihf BUILDMACH=i686-pc-linux-gnu AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib CPPFLAGS="-fPIC" make
RUN TARGETMACH=arm-linux-gnueabihf BUILDMACH=i686-pc-linux-gnu AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib make install

RUN apt install -y vim git autoconf libtool libpam-dev autopoint automake bison bzip2 docbook-xml docbook-xsl flex gettext libaudit-dev libdb-dev libfl-dev libselinux1-dev libssl-dev libtool libxml2-utils make pkg-config sed w3m xsltproc xz-utils 1>/dev/null

WORKDIR /root

RUN git clone https://github.com/linux-pam/linux-pam
WORKDIR /root/linux-pam
RUN ./autogen.sh
RUN TARGETMACH=arm-linux-gnueabihf BUILDMACH=i686-pc-linux-gnu AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib ./configure --host=arm-linux-gnueabihf --prefix=/root/libpamArm
RUN TARGETMACH=arm-linux-gnueabihf BUILDMACH=i686-pc-linux-gnu AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib make
RUN TARGETMACH=arm-linux-gnueabihf BUILDMACH=i686-pc-linux-gnu AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib make install

WORKDIR /root
RUN git clone https://github.com/duosecurity/duo_unix.git
WORKDIR /root/duo_unix
RUN git checkout duo_unix-1.11.4

COPY configure.patch /root/configure.patch

RUN TARGETMACH=arm-linux-gnueabihf BUILDMACH=i686-pc-linux-gnu CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib ./bootstrap
RUN patch -p0 </root/configure.patch
RUN TARGETMACH=arm-linux-gnueabihf BUILDMACH=i686-pc-linux-gnu CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib LIBS="-Wl,--verbose -ldl -Wl,--no-as-needed" LDFLAGS="-L/usr/lib/gcc-cross/arm-linux-gnueabihf -L/root/libpamArm/lib" CPPFLAGS="-fPIC" ./configure --with-pam=/root/libpamArm --prefix=/usr/arm-linux-gnueabihf --host=arm-linux-gnueabihf --with-openssl=/root/opensslArm
RUN TARGETMACH=arm-linux-gnueabihf BUILDMACH=i686-pc-linux-gnu CC=arm-linux-gnueabihf-gcc AR=arm-linux-gnueabihf-ar RANLIB=arm-linux-gnueabihf-ranlib LIBS="-Wl,--verbose -ldl -Wl,--no-as-needed" LDFLAGS="-L/usr/lib/gcc-cross/arm-linux-gnueabihf -L/root/libpamArm/lib" CPPFLAGS="-fPIC" make
