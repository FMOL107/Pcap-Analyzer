# Pcap-Analyzer

## Update Notes
+ ported project from Python 2.X to Python 3.X
+ Fixed several bugs

## Main features
+ 1. Display basic packet information
+ 2. Analyze packet protocols
+ 3. Analyze packet traffic
+ 4. Map out access IP latitude and longitude
+ 5. Extract protocol-specific session connections (WEB, FTP, Telnet) from packets
+ 6. extract sensitive data (passwords) from sessions
+ 7. Simple analysis of security risks in packets (WEB attacks, brute force cracking)
+ 8. Extraction of protocol-specific transport files or all binaries from datagrams

## Results show
### Home.
![Alt Text](https://github.com/FMOL107/Pcap-Analyzer/blob/master/images/index.png)

### Basic data display.
![Alt Text](https://github.com/FMOL107/Pcap-Analyzer/blob/master/images/basedata.png)

### Protocol analysis.
![Alt Text](https://github.com/FMOL107/Pcap-Analyzer/blob/master/images/protoanalyxer.png)

### Traffic analysis.
![Alt Text](https://github.com/FMOL107/Pcap-Analyzer/blob/master/images/flowanalyzer.png)

### Access to IP latitude and longitude maps.
![Alt Text](https://github.com/FMOL107/Pcap-Analyzer/blob/master/images/ipmap.png)

### Session extraction.
![Alt Text](https://github.com/FMOL107/Pcap-Analyzer/blob/master/images/getdata.png)

### Attack message warning.
![Alt Text](https://github.com/FMOL107/Pcap-Analyzer/blob/master/images/attackinfo.png)

### File extraction.
![Alt Text](https://github.com/FMOL107/Pcap-Analyzer/blob/master/images/getfiles.png)

## Installation and deployment process.

+ Runtime environment: Python 3.5.X
+ Operating system: Linux (Ubuntu 15.10 as an example)

### 1. Python-related environment configuration (Ubuntu installs Python 2.7 by default without additional Python installation)
Python package manager installation: sudo apt-get install python-setuptools python-pip

### 2. Related third-party dependency library installations:
+ sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx
+ sudo pip3 install Flask
+ sudo pip3 install Flask-WTF
+ sudo pip3 install geoip2
+ sudo pip3 install pyx
+ sudo pip3 install requests
+ see the official documentation for scapy installation, scapy version 2.4.0, there are major changes after 2.4.0 that may cause incompatibility

### 3. Modify the configuration file
Note the directory location in the config.py configuration file
+ UPLOAD_FOLDER = '/home/dj/PCAP/' where the uploaded PCAP files are stored
+ FILE_FOLDER = '/home/dj/Files/' the location where the files are saved when extracted, the following subdirectories must be All, FTP, Mail, Web, to store the files extracted from different protocols
+ PDF_FOLDER = '/home/dj/Files/PDF/' The location where PCAP is saved as PDF

### 4. Server installation
+ Gunicorn server: pip3 install gunicorn
+ Nginx server: sudo apt-get install nginx
+ Nginx configuration: modify the /etc/nginx/nginx.conf file and add the following code to http{}
```
server { 
listen 81. 
server_name localhost. 
access_log /var/log/nginx/access.log. 
error_log /var/log/nginx/error.log.

     location / {
        #root html.
        #index index.html index.htm.
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for.
         proxy_set_header Host $http_host.
         proxy_pass http://127.0.0.1:8000.
    }

    error_page 500 502 503 504 /50x.html.
    location = /50x.html {
        root html.
    }
```

### 5. To start the system:
+ Go to the system directory: . /pcap-analyzer
+ Start the system via the Gunicorn server server and run the command: gunicorn -c deploy_config.py run:app
+ At this point, you can only access the system locally at http://127.0.0.1:8000
+ Start the Nginx server: sudo service nginx start
+ At this point, other hosts can also access the system at http://服务器IP:81


## Analysis and optimisation
### The accuracy of the packet analysis results can be improved by modifying the configuration file, fixing
+ replace . /app/utils/GeoIP/GeoLite2-City.mmdb with the IP address latitude and longitude database file to improve the accuracy of the IP latitude and longitude maps
+ Modify. /app/utils/protocol/ directory for each TCP/IP protocol stack and the corresponding protocol name to correct the protocol analysis results
+ Modify. /app/utils/waring/HTTP_ATTACK file to improve the accuracy of HTTP protocol attacks in packets
