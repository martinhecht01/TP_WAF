FROM nginx:1.25.5

EXPOSE 80

RUN apt-get update && apt-get install -y \
    apt-utils \
    autoconf \
    automake \
    build-essential \
    git \
    libcurl4-openssl-dev \
    libgeoip-dev \
    liblmdb-dev \
    libpcre3-dev \
    libtool \
    libxml2-dev \
    libyajl-dev \
    pkgconf \
    wget \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity

WORKDIR /ModSecurity
RUN git submodule init
RUN git submodule update
RUN ./build.sh 
RUN ./configure
RUN make
RUN make install
WORKDIR /

RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git

RUN mkdir /etc/nginx/modsec
RUN wget -P /etc/nginx/modsec/ https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
