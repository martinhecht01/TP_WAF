# HowTo Grupo 26

# Consigna: Tema 2 – WAF (Web Application Firewall)

- No puede ser implementado en nube.
- Configurar un servidor Proxy que funcione como proxy reverso para recibir las peticiones para al menos 2 servidores con web server.
- Configurar un servidor con ModSecurity que reciba las redirecciones del Proxy y chequee la seguridad de las mismas
- Configurar al menos 3 reglas de solo detección para realizar análisis.
- Configurar al menos 3 reglas de bloqueo.
- Probar al menos 3 ataques para mostrar la respuesta del waf, configurar una página default de respuesta ante detección de anomalía.

# Stack

Comenzamos la guía de uso e instalación mencionando los componentes que utilizamos.

- **Docker**: armamos una imagen de Docker basada en la imagen oficial de Nginx, agregando los distintos componentes que utilizamos para firewall y el funcionamiento correcto del proyecto.
- **Nginx**: utilizamos Nginx como web server y proxy reverso para manejar el tráfico entrante a los distintos servicios que montamos.
- **ModSecurity**: utilizamos ModSecurity como firewall y lo montamos sobre el proxy reverso Nginx. Dentro de su configuración es que explicitamos las reglas de seguridad.
- **Owasp**: una librería open-source con reglas para firewalls ModSecurity.
- **bWapp**: una aplicación web con muchos bugs para montar sobre un servidor web y probar el funcionamiento del firewall.
- **dvwa**: otra aplicación web similar a bWapp con exploits distintos para seguir probando ataques.

# Arquitectura

La estructura general del proyecto consiste de una imagen de Docker que armamos para poder resolver la consigna. Dentro del container, corremos un reverse proxy de Nginx para montar nuestro WAF de ModSecurity con las reglas que establecimos, y utilizamos Nginx también para levantar los dos web servers requeridos, uno llamado bWapp, el otro dvwa. Si bien vamos a repasar cada uno de los componentes en detalle más adelante, adjuntamos una imagen representativa de la arquitectura propuesta.

![Screenshot 2024-06-05 at 7.03.23 PM.png](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Screenshot_2024-06-05_at_7.03.23_PM.png)

Representativamente, podemos ver en el diagrama que el host tiene nuestro container, y en el se ubican tanto el Proxy y el WAF, como los dos WebServers que estos manejan. Además, y sin entrar en más detalle para no ser repetitivos a lo largo del informe, vemos que el Proxy escucha en el puerto 80 los llamados redirigidos del puerto 3000 que dispusimos arbitrariamente.

# Estructura del repositorio

El repositorio tiene la siguiente estructura que se ve listada abajo tras correr el comando `tree`  en la raíz. A la hora de correr el proyecto, es importante mantener la estructura para que los archivos de Docker encuentren a los volumes.

```bash
.
├── Dockerfile
├── docker-compose.yml
└── volumes
    ├── error403.html
    ├── main.conf
    └── nginx.conf
```

# Detalle de los componentes e implementación

## Docker Compose

Para crear el entorno de ejecución de nuestro trabajo realizamos una imagen de Docker basada en la imagen oficial de Nginx. Por otro lado para que la ejecucion de las 3 componentes( proxy, bwapp, dvwa) corran sobre el mismo contexto utilizamos docker compose. Debajo vemos un el contenido del archivo  `docker-compose.yml`.

En este archivo podemos ver que se incluyen los servicios de Nginx para correr en el puerto 3000, con 3 volúmenes: uno para la configuracion de ModSecurity (main.conf), otra para la de nginx (nginx.conf), y una con el código de la página de error 403. Debajo se listan los otros dos servios utilizados para levantar nuestros dos servidores web: bwapp y dvwa.

```yaml
services:
  nginx:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:80"
    volumes:
      - ./volumes/main.conf:/etc/nginx/modsec/main.conf
      - ./volumes/nginx.conf:/etc/nginx/nginx.conf
      - ./volumes/error403.html:/etc/nginx/html/error403.html
  bwapp:
    image: hackersploit/bwapp-docker
    container_name: bwapp
    hostname: bwapp
   web-dvwa:
    image: vulnerables/web-dvwa
    container_name: web-dvwa
    hostname: web-dvwa
```

En conjunto con el Docker File, podemos utilizar los siguientes comandos para construir y levantar la imagen:

```bash
docker compose build
docker compose up
```

## Docker File

Para que el WAF funcione es necesario tomar reglas y archivos de distintos repositorios que vamos a detallar de a poco. Por el momento, desglosamos el Docker File para ver de que está compuesto nuestro sistema.

En primer lugar partimos de la imagen de Nginx en su versión 1.25.5. Tomamos la decisión de hardcodear la versión ya que se usará a lo largo del archivo. Corremos además configuración previa para instalar ModSecurity en los directorios y con las especificaciones requeridas. Se puede observar que en los argumentos de configuración se encuentra nuestro volumen con la configuración que establecimos para Nginx, que también detallaremos.

```bash
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
    libmaxminddb0 \
    libmaxminddb-dev \
    mmdb-bin \
    pkgconf \
    vim \
    wget \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
```

Descargamos e instalamos ModSecurity.  Tener en cuenta que el comando `make` **puede tomar hasta 15 minutos en terminar de ejecutar. Luego de finalizar su ejecución ejecutamos `make install` para terminar la instalación y pasamos a la integración del módulo con Nginx. Para esto nos movemos de directorio y conectamos ModSecurity con Nginx. Como bien dice la documentación de Nginx, para integrarse con ModSecurity es necesario descargar un integrador llamado *SpiderLabs* para realizar la conexión. Finalmente luego de descargarlo y ejecutar el los comandos correspondientes, se integra el WAF al proxy reverso de Nginx.

```bash
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
WORKDIR /nginx-1.25.5
RUN ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx 
RUN make modules
RUN cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules
```

Luego de terminar la integración utilizamos nuestro volumen de ModSecurity para configurar el funcionamiento del Firewall y sus reglas. Adicionalmente, clonamos el repositorio de Owasp con reglas definidas para el WAF y lo incluimos en el directorio de reglas para que el archivo `modsecurity.conf` pueda leerlas.

```bash
RUN mkdir /etc/nginx/modsec

RUN wget -P /etc/nginx/modsec/ https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended

RUN mv /etc/nginx/modsec/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
WORKDIR /
RUN cp ModSecurity/unicode.mapping /etc/nginx/modsec
RUN sed --i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf

RUN git clone https://github.com/coreruleset/coreruleset /opt/coreruleset
RUN mv /opt/coreruleset/crs-setup.conf.example /opt/coreruleset/crs-setup.conf
RUN mv /opt/coreruleset/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /opt/coreruleset/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
```

## Nginx

El volumen utilizado de Nginx detalla principalmente la configuración de los servidores en Nginx y de la página de error. Listados bajo *server* podemos ver como ambos servicios escuchan en el puerto 80 (redirigidos desde el puerto 3000 que configuramos en el Docker File) bajo los URN `*/bwapp/`* y `/web-dvwa/` **. Además se ubica en `*/error403.html`* la página de error designada. Finalmente, es importante notar que en este archivo se indica que la configuración de ModSecurity está encendida con su configuración correspondiente en `*/etc/nginx/modsec.conf`* la cual fue incluida como volumen y explicaremos a continuación.

Dentro de este archivo hay que prestarle especial atencion a la linea que dice `modsecurity on;` ya que es donde estamos habilitando el uso de modsecurity.

```bash
load_module modules/ngx_http_modsecurity_module.so;

user nginx;
worker_processes auto;
http{
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        
        sendfile on;

     log_format custom '$remote_addr - $remote_user [$time_local] '
                      '"$request" $status $body_bytes_sent '
                      '"$http_referer" "$http_user_agent" '
                      '"$request_time" "$upstream_response_time" '
                      ;
    access_log /var/log/nginx/access.log custom;

server {
    listen       80;
    listen  [::]:80;
    server_name  localhost;

    #access_log  /var/log/nginx/host.access.log  main;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    location /bwapp/ {
        proxy_set_header Accept-Encoding "";
        proxy_pass http://bwapp/;
        proxy_set_header Host bwapp;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect off;
        sub_filter 'href=\"/' 'href=\"/bwapp/';
        sub_filter 'src="/'  'src="/bwapp/';
        sub_filter 'action="/'  'action="/bwapp/';
        sub_filter_once off;
        error_log /var/log/nginx/waf.log;
    }

      location /web-dvwa/ {
        proxy_set_header Accept-Encoding "";
        proxy_pass http://web-dvwa/;
        proxy_set_header Host web-dvwa;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        sub_filter 'href=\"/' 'href=\"/web-dvwa/';
        sub_filter 'src="/'  'src="/web-dvwa/';
        sub_filter 'action="/'  'action="/web-dvwa/';
        proxy_redirect /setup.php http://localhost:3000/web-dvwa/setup.php;  
        sub_filter_once off;
        error_log /var/log/nginx/waf.log;
    }

    error_page  403 /error403.html;

    location = /error403.html {
        root /etc/nginx/html;
    }
}

}
events {
        worker_connections 1024; 
}
```

## ModSecurity

Para configurar las reglas propias realizadas para el TP se necesita modificar el archivo main.conf alojado en el directorio /volumes. Inicialmente, el TP solo está configurado para utilizar el core rule-set de OWASP.

En el siguiente archivo se detalla la configuración básica de ModSecurity. Podemos ver como se incluyen los archivos importados de OWASP con las reglas generales, y por debajo algunas de las reglas custom que agregamos para la demostración.

```
# From https://github.com/SpiderLabs/ModSecurity/blob/master/
# modsecurity.conf-recommended
#
# Edit to set SecRuleEngine On
Include "/etc/nginx/modsec/modsecurity.conf"
Include "/opt/coreruleset/crs-setup.conf"
Include "/opt/coreruleset/rules/*.conf"

# Reglas de ModSecurity:
# bloquo de IP
SecRule REMOTE_ADDR "@ipMatch 172.18.0.1" "id:1001,phase:1,log,deny,status:403, msg='Denying connection from origin @REMOTE_ADDR.'”

# XSS
SecRule ARGS "@rx <script>" "id:1002,phase:2,t:lowercase,log,deny,status:403, msg='Denying request as possible XSS might occur: <script> tag located.'"
SecRule ARGS "@rx <\s*img\b.*?on\w+\s*=" "id:1003,phase:2,t:lowercase,log,deny,status:403, msg='Denying request as possible XSS might occur: <img> tag with action (onLoad/onError) located.'"
SecRule ARGS "@rx (<\s*script\b|<\s*img\b.*?on\w+\s*=|<\s*body\b.*?onload\s*=|<\s*.*?\bon\w+\s*=|%3Cscript%3E|&#x|<script>|%3C%73%63%72%69%70%74%3E)" "id:1004,phase:2,t:lowercase,log,deny,status:403, msg='Denying request as possible XSS might occur: multiple dangerous tags found.'"

# SQL
SecRule ARGS "@rx (?i)union.*select" "id:1005,phase:2,t:lowercase,log,deny,status:403,msg:'Denying request as possible SQL Injection might occur: UNION SELECT detected.'"
SecRule ARGS "@rx (?i)(or 1=1|select.*from|drop.*table|update.*set|insert.*into)" "id:1006,phase:2,t:lowercase,log,deny,status:403,msg:'Denying request as possible SQL Injection might occur: malicious SQL keyword detected.'"
SecRule ARGS "@rx (?i)(and 1=1|and 1=2|or 1=1|or 1=2)" "id:1007,phase:2,t:lowercase,log,deny,status:403,msg:'Denying request as possible SQL Injection might occur: boolean-based SQL syntax detected.'"

# Command Injection
SecRule ARGS "@rx (?i)(;|\||&|`|\$|>|<|!)" "id:1008,phase:2,t:lowercase,log,deny,status:403,msg:'Denying request as possible command injection might occur: detected dangerous characters used for executing commands on the host operating system.'"

# Denial of Service por Aplicacion
# Init de entrada en coleccion IP
SecAction "id:1008, phase:1, nolog, pass, initcol:ip=%{REMOTE_ADDR}"

# Inicio del contador y timeout para la IP
SecAction "id:1011, phase:1, nolog, pass, setvar:ip.count=+0, expirevar:ip.count=10"

# Incremento del contador y reset del timeout para la IP
SecRule REQUEST_URI "@beginsWith /bwapp/" "id:1013, phase:2, pass, nolog, setvar:ip.count=+1, expirevar:ip.count=10"

# Acceso denegado si el contador de requests supera el umbral antes del timeout, chain encadena las dos reglas siguientes
SecRule REQUEST_URI "@beginsWith /bwapp/" "chain,id:1015, phase:2, log, deny, status:403, msg:'Rate limit exceeded for /bwapp'" 

SecRule ip:count "@gt 25" "t:none"
```

Para no utilizar el core rule-set debemos comentar/eliminar las líneas 6 y 7.

```jsx
SecRule VARIABLES "OPERATOR" "TRANSFORMATIONS,ACTIONS"
```

Las reglas de ModSecurity se definen con el tag `SecRule` al principio y luego por una serie de 3 objetos que la completan, estos siendo:

1) Variable: es en donde ModSecurity realizará la búsqueda en donde imponer la regla. Utilizando el código anterior como ejemplo, `REMOTE_ADDR` y `ARGS` son dos opciones de muchas.

2) Operador: especifica al ModSecurity que buscar en el lugar especificado por la Variable. Utilizando el código anterior como ejemplo, `@ipMatch` y `@rx` son dos operadores. `@rx` e `@ipMatch` se utilizan para buscar coincidencias con expresiones regulares y direcciones IP respectivamente durante la inspección del trafico.

3) Acciones y Transformaciones: determina aspectos de ejecución de la regla con distintos parámetros

a) Identificador único de la regla

a.a) `id: [nro]`

b) Fase del pedido/respuesta en la cual se deberia ejecutar la regla en el caso de ser activada

uso:

`phase: [opcion]`

opciones:

b.a) `1` = encabezado del pedido

b.b) `2` = cuerpo del pedido

b.c) `3` = encabezado de la respuesta

b.d) `4` = cuerpo de la respuesta

b.e) `5` = registrado

c) Acción: determina que ocurre cuando la regla se acciona

uso:

`[opción]`

Algunas opciones:

c.a) `drop` = rechaza el pedido y aborta la conexión con el cliente

c.b) `deny` = rechaza el pedido, hace que no se siga procesando el pedido con las siguientes reglas, devuelve un código al cliente y registra la acción.

c.c) `block` = lo mismo que deny pero con valores default (ej: estado 403)

c.d) `pass` = si el pedido pasa la regla, continua con el resto de las reglas

c.e) `allow` = si el pedido pasa la regla, no se continua analizandolo con las siguientes reglas y se le permite acceder a la aplicación web

c.f) `log` = registra en el archivo especificado un mensaje

d) Estado: especifica el estado que se debe devolver

uso: 

`status: [nro]`

e) Mensaje: registra el mensaje en el lugar especificado

uso:

`msg: '[texto]'`

f) Transformación: transformaciones a aplicar sobre sobre los datos

uso:

`t: [opcion]`

algunas opciones:

`lowercase` = convierte toda la data en minúscula

g) Severidad: categorización de la regla

uso:

`severity: [nro]`

h) Etiqueta: categorización de la regla

uso:

`tag: '[etiqueta]'`

Al ejecutarse una regla, esta se registra en un archivo para su control. Este archivo se puede encontrar bajo el directorio `/var/log/` del container de NGNIX bajo el nombre `modsec_audit.log`.

Para accederlo, primero se debe ingresar al filesystem del container via línea de comando mediante:

```bash
docker exec -t -i [hashDelContainer] /bin/bash
```

Luego, viajar al directorio y leer el archivo:

```bash
cd /var/log
cat modsec_audit.log
```

## Owasp

Como vimos anteriormente, utilizamos reglas de Owasp para generar un WAF más robusto y no reinventar reglas que se han demostrado que pueden frenar distintos vectores de ataques. Esto lo hicimos clonando el repositorio de Github de Owasp y utilizando algunos de sus archivos durante el Docker File. 

```bash
#codigo del Docker File
RUN git clone https://github.com/coreruleset/coreruleset /opt/coreruleset
RUN mv /opt/coreruleset/crs-setup.conf.example /opt/coreruleset/crs-setup.conf
RUN mv /opt/coreruleset/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /opt/coreruleset/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
```

Destacamos esto nuevamente, ya que queremos remarcar los archivos que contienen las reglas de Owasp. Por un lado tenemos el archivo `/opt/coreruleset/crs-setup.conf` contiene la configuración general de las reglas de Owasp, y el archivo `/opt/coreruleset/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` está diseñado para modificarlo y alterar el comportamiento de algunas reglas. Por ejemplo, podríamos hacer que una regla que está dispuesta en modo **block**, pase a estar en modo **log**.

## bWapp

Luego de construir y correr el container, dirigirnos a la siguiente dirección para configurar bWapp:

```
[http://localhost:3000/bwapp/install.php](http://localhost:3000/bwapp/install.php)
```

Al realizar esto, veremos la siguiente página de inicio, donde deberemos clickear en **”here”** para instalar las herramientas necesarias para que el sitio web funcione como corresponde.

![Screenshot 2024-06-05 at 10.14.05 AM.png](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Screenshot_2024-06-05_at_10.14.05_AM.png)

Tras descargar las herramientas, bWapp nos muestra un mensaje diciendo que instalaron correctamente, y debemos clickear en **“New User”** para crear un nuevo usuario con las credenciales deseadas.

![Screenshot 2024-06-05 at 10.15.39 AM.png](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Screenshot_2024-06-05_at_10.15.39_AM.png)

Una vez en la página de **“New User”**, crear un nuevo usuario con credenciales deseadas en el siguiente menú que se ve en la próxima imagen.

![Screenshot 2024-06-05 at 10.16.57 AM.png](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Screenshot_2024-06-05_at_10.16.57_AM.png)

Una vez creado el usuario, dirigirse al inicio de sesión **“Login”** e introducir las credenciales del usuario creado. Luego de iniciar sesión, veremos el siguiente menú de ataques donde se podrá elegir que ataque que se desea realizar.

![Screenshot 2024-06-05 at 10.18.48 AM.png](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Screenshot_2024-06-05_at_10.18.48_AM.png)

Del menú, seleccionamos que vulnerabilidad queremos explotar y seleccionamos "hack". Se puede utilizar también el drop-down menu indicado con una flecha.

Por ejemplo, seleccionemos Cross-Site Scripting - Reflected (GET) y probemos utilizar código para modificar el DOM de la página: `<iframe src="javascript:alert('esto es un ataque')">`

![Untitled](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Untitled.png)

Luego de clicker sobre el boton “Go”, se verá reflejado el ataque.

En el caso de no tener ninguna regla activa que bloquee el ataque:

![Untitled](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Untitled%201.png)

Si hay reglas de ModSecurity activas, el ataque será bloqueado y el usuario será redirigido a la página que indique que su acción está prohibida:

![Untitled](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Untitled%202.png)

## DVWA

Luego de correr el container, para acceder a la segunda página del proyecto, dirigirse en un browser a:

```
http://localhost:3000/web-dvwa/
```

![Untitled](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Untitled%203.png)

Por default las credenciales iniciales son Username: admin, Password: password, clickear login.

![Untitled](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Untitled%204.png)

Una vez iniciados sesión, dirigirse al fondo de la pantalla y clickear “Create / Reset Database” para inicializar la base de datos.

![Screenshot 2024-06-05 145513.png](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Screenshot_2024-06-05_145513.png)

Luego de clickear, se debera hacer login nuevamente, clickeando sobre el boton login justo debajo del botón o yendo a la url: 

```
http//localhost:3000/web-dvwa/login.php
```

Una vez hecho login nuevamente, por la izquierda se tendrá un menu similar al de bwapp para realizar los ataques:

![Untitled](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Untitled%205.png)

Por ejemplo, para hacer un ataque del tipo inyección de SQL:

![Untitled](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Untitled%206.png)

Intentando hacer un ataque sin reglas de ModSecurity activas…

![Untitled](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Untitled%207.png)

Podemos recuperar los nombres de usuarios junto a sus contraseñas hasheadas

Si tenemos reglas de ModSecurity se redigirá al usuario a la página de error:

![Untitled](HowTo%20Grupo%2026%2060971eacc6864a94ae2b70e247e43c07/Untitled%202.png)