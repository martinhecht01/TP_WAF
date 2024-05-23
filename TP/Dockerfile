FROM nginx:1.25.5

EXPOSE 80

ARG CONFIG_ARGS=--prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-compat --with-file-aio --with-threads --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-mail --with-mail_ssl_module --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-cc-opt='-g -O2 -ffile-prefix-map=/data/builder/debuild/nginx-1.23.4/debian/debuild-base/nginx-1.23.4=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie'

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
    vim \
    wget \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch v3/master --single-branch https://github.com/SpiderLabs/ModSecurity

WORKDIR /ModSecurity
RUN git submodule init
RUN git submodule update
RUN ./build.sh 
RUN ./configure
RUN make
RUN make install
WORKDIR /

RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git
RUN wget http://nginx.org/download/nginx-1.25.5.tar.gz
RUN tar zxvf nginx-1.25.5.tar.gz
WORKDIR ./nginx-1.25.5
RUN ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx
RUN make modules
RUN cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules

RUN mkdir /etc/nginx/modsec

RUN wget -P /etc/nginx/modsec/ https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended

RUN mv /etc/nginx/modsec/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
WORKDIR /
RUN cp ModSecurity/unicode.mapping /etc/nginx/modsec
RUN sed --i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf



RUN git clone https://github.com/coreruleset/coreruleset /opt/coreruleset
RUN mv /opt/coreruleset/crs-setup.conf.example /opt/coreruleset/crs-setup.conf
RUN mv /opt/coreruleset/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /opt/coreruleset/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
