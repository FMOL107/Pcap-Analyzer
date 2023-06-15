#root
apt update && apt install sudo wget curl git -y 
usermod -aG sudo usuario
apt-get install python3-setuptools python3-pip -y 
apt-get install tcpdump graphviz imagemagick -y
apt-get install python3-gnuplot python3-pyx python3-pycryptodome -y

sudo pip3 install Flask
sudo pip3 install Flask-WTF
sudo pip3 install geoip2
sudo pip3 install pyx
sudo pip3 install requests

git clone <URL>
# Proyecto original - https://github.com/HatBoy/Pcap-Analyzer
# Fork en ingles - https://github.com/ccgcyber/Pcap-Analyzer
cd Pcap-Analyzer/
nano config.py
## coding:UTF-8
#__author__ = 'dj'
#
#DEBUG = True
#
#WTF_CSRF_ENABLED = False
#
#SECRET_KEY = '!@#$%8F6F98EC3684AECA1DC44E1CB816E4A5^&*()'
#
#UPLOAD_FOLDER = '/home/usuario/files/pcaps/'
#FILE_FOLDER = '/home/usuario/files/extracts/'
#PDF_FOLDER = '/home/usuario/files/pdfs/'

sudo pip3 install gunicorn
sudo pip3 install scapy


sudo apt-get install nginx -y

nano /etc/nginx/nginx.conf
#.............
#events{.............}
#http{.............}
#server {
#        listen 81;
#        server_name localhost;
#        access_log /var/log/nginx/access.log;
#        error_log /var/log/nginx/error.log;
#
#        location / {
#                #root   html;
#                #index  index.html index.htm;
#                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#                proxy_set_header Host $http_host;
#                proxy_pass http://127.0.0.1:8000;
#        }
#
#        error_page   500 502 503 504  /50x.html;
#        location = /50x.html {
#        root   html;
#}

gunicorn -c deploy_config.py run:app

#############################################################
#Proceso de instalación y despliegue.
#Entorno de ejecución: Python 3.5.X
#Sistema operativo: Linux (Ubuntu 15.10 como ejemplo)
#1. Configuración del entorno relacionado con Python (Ubuntu instala Python 2.7 por defecto sin necesidad de instalación adicional de Python)
#1. Instalación del gestor de paquetes Python: sudo apt-get install python-setuptools python-pip
#
#2. Instalación de dependencias de terceros relacionadas: sudo apt-get install
#sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx
#sudo pip3 install Flask
#sudo pip3 install Flask-WTF
#sudo pip3 install geoip2
#sudo pip3 install pyx
#sudo pip3 install peticiones
#Por favor, consulte la documentación oficial para la instalación de scapy. La versión 2.4.0 de scapy ha cambiado significativamente desde la 2.4.0, lo que puede causar incompatibilidad.
#3. Modifique el archivo de configuración
#Tenga en cuenta la ubicación del directorio en el archivo de configuración config.py
#
#UPLOAD_FOLDER = '/home/dj/PCAP/' la ubicación donde se almacenan los archivos PCAP cargados
#FILE_FOLDER = '/home/dj/Files/' la ubicación donde se guardan los archivos cuando se extraen, los siguientes subdirectorios deben ser All, FTP, Mail, Web, utilizados para almacenar los archivos extraídos de diferentes protocolos
#PDF_FOLDER = '/home/dj/Files/PDF/' La ubicación donde se guarda el PCAP como PDF
#4. Instalación del servidor
#Servidor Gunicorn: pip3 install gunicorn
#Servidor Nginx: sudo apt-get install nginx
#Configuración de Nginx: modifica el archivo /etc/nginx/nginx.conf y añade el siguiente código a http{}
#servidor { 
#listen 81. 
#server_name localhost. 
#access_log /var/log/nginx/access.log. 
#error_log /var/log/nginx/error.log.
#
#     location / {
#        #root html.
#        #index index.html index.htm.
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for.
#         proxy_set_header Host $http_host.
#         proxy_pass http://127.0.0.1:8000.
#    }
#
#    error_page 500 502 503 504 /50x.html.
#    location = /50x.html {
#        html raíz.
#    }
#5. Para iniciar el sistema:
#Vaya al directorio del sistema: ... /pcap-analyzer
#6. Para arrancar el sistema desde el servidor Gunicorn, ejecute el comando: gunicorn -c deploy_config.py run:app
#En este punto sólo puede acceder al sistema localmente en http://127.0.0.1:8000
#Inicie el servidor Nginx: sudo service nginx start
#En este punto, otros hosts también pueden acceder al sistema en http://服务器IP:81
#Optimización del análisis
#La precisión de los resultados del análisis de paquetes puede mejorarse modificando el archivo de configuración para fijar
#Sustituir . /app/utils/GeoIP/GeoLite2-City.mmdb por el archivo de base de datos de latitud y longitud de direcciones IP para mejorar la precisión de los mapas de latitud y longitud IP
#Modificar. . /app/utils/protocol/ con cada pila de protocolos TCP/IP y el nombre de protocolo correspondiente para corregir los resultados del análisis de protocolos
#Modificar. /app/utils/waring/HTTP_ATTACK para mejorar la precisión de los ataques del protocolo HTTP en los paquetes
#############################################################
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#https://github.com/HatBoy/Pcap-Analyzer
#############################################################
#安装部署过程:
#运行环境：Python 3.5.X
#操作系统：Linux (以Ubuntu 15.10为例)
#1.Python相关环境配置（Ubuntu默认安装Python2.7不需要额外安装Python）
#Python包管理器安装：sudo apt-get install python-setuptools python-pip
#
#2.相关第三方依赖库安装：
#sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx
#sudo pip3 install Flask
#sudo pip3 install Flask-WTF
#sudo pip3 install geoip2
#sudo pip3 install pyx
#sudo pip3 install requests
#scapy的安装请参见官方文档，scapy的版本为2.4.0，2.4.0之后版本有较大的变化，可能导致不兼容
#3.修改配置文件
#注意修改config.py配置文件中的目录位置
#
#UPLOAD_FOLDER = '/home/dj/PCAP/' 上传的PCAP文件保存的位置
#FILE_FOLDER = '/home/dj/Files/' 提取文件时保存的位置，下面必须要有All、FTP、Mail、Web子目录，用于存放提取不同协议的文件
#PDF_FOLDER = '/home/dj/Files/PDF/' PCAP保存为PDF时保存的位置
#4.服务器安装
#Gunicorn服务器：pip3 install gunicorn
#Nginx服务器：sudo apt-get install nginx
#Nginx配置：修改/etc/nginx/nginx.conf文件，在http{}中添加下面代码：
#server { 
#listen 81; 
#server_name localhost; 
#access_log /var/log/nginx/access.log; 
#error_log /var/log/nginx/error.log;
#
#     location / {
#        #root   html;
#        #index  index.html index.htm;
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#         proxy_set_header Host $http_host;
#         proxy_pass http://127.0.0.1:8000;
#    }
#
#    error_page   500 502 503 504  /50x.html;
#    location = /50x.html {
#        root   html;
#    }
#5.启动系统：
#进入系统所在目录：../pcap-analyzer
#通过Gunicorn服务器服务器启动系统，运行命令：gunicorn -c deploy_config.py run:app
#此时只能本地访问系统，地址：http://127.0.0.1:8000
#启动Nginx服务器：sudo service nginx start
#此时其他主机也可访问该系统，地址：http://服务器IP:81
#分析优化
#对数据包的分析结果的准确率可通过修改配置文件来提高，修正
#替换./app/utils/GeoIP/GeoLite2-City.mmdb的IP地址经纬度数据库文件能提高IP经纬度地图的准确率
#修改./app/utils/protocol/目录中的各个TCP/IP协议栈的表示号和对应的协议名称可修正协议分析结果
#修改./app/utils/waring/HTTP_ATTACK文件可提高数据包中HTTP协议攻击的准确率
##############################################################