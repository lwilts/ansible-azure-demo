# Install ELK stack on CentOS

# Based on DigitalOcean tutorial:
# https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-centos-7

#!/bin/bash

# Install Elasticsearch
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u73-b02/jdk-8u73-linux-x64.rpm"
yum -y localinstall jdk-8u73-linux-x64.rpm
rm jdk-8u*-linux-x64.rpm
rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch
echo '[elasticsearch-2.x]
name=Elasticsearch repository for 2.x packages
baseurl=http://packages.elastic.co/elasticsearch/2.x/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | tee /etc/yum.repos.d/elasticsearch.repo
yum -y install elasticsearch
sed -i 's/# network.host: 192.168.0.1/network.host: localhost/g' /etc/elasticsearch/elasticsearch.yml
systemctl start elasticsearch
systemctl enable elasticsearch

# Install Kibana
cat <<EOF >/etc/yum.repos.d/kibana.repo
[kibana-4.4]
name=Kibana repository for 4.4.x packages
baseurl=http://packages.elastic.co/kibana/4.4/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
EOF
yum -y install kibana
sed -i 's/# server.host: "0.0.0.0"/server.host: localhost/g' /opt/kibana/config/kibana.yml
systemctl start kibana
chkconfig kibana on

# Install nginx
yum -y install epel-release
yum -y install nginx httpd-tools
< /dev/urandom tr -dc A-Z-a-z-0-9 | head -c${1:-8} | tee kibana.pass | htpasswd -ic /etc/nginx/htpasswd.users kibanaadmin
sed -ie '38,57d' /etc/nginx/nginx.conf
cat <<EOF >/etc/nginx/conf.d/kibana.conf
server {
    listen 80;

    server_name $(curl -s http://checkip.amazonaws.com);

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;        
    }
}
EOF
systemctl start nginx
systemctl enable nginx
setsebool -P httpd_can_network_connect 1

# Install Logstash
cat <<EOF >/etc/yum.repos.d/logstash.repo
[logstash-2.2]
name=logstash repository for 2.2 packages
baseurl=http://packages.elasticsearch.org/logstash/2.2/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
EOF
yum -y install logstash

# Generate SSL certificates
sed -i "/\[ v3_ca \]/a subjectAltName = IP: $(hostname -I)" /etc/pki/tls/openssl.cnf
openssl req -config /etc/pki/tls/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt

# Configure Logstash
cat <<EOF >/etc/logstash/conf.d/02-beats-input.conf
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}
EOF
cat <<EOF >/etc/logstash/conf.d/10-syslog-filter.conf
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
EOF
cat <<EOF >/etc/logstash/conf.d/30-elasticsearch-output.conf
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
EOF
systemctl restart logstash
chkconfig logstash on

# Load sample dashboards
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
yum -y install unzip
unzip beats-dashboards-*.zip
rm beats-dashboards-*.zip
cd beats-dashboards-*
./load.sh

# Load Filebeat index template in Elasticsearch
cd ~
curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json
curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json

# DONE
echo "Finished configuring ELK server - now set up client server(s) to send logs via Filebeat"
echo "Certificate downloaded to certs/logstash-forwarder.crt"
