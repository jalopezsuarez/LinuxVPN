### ROUTER VPN LINUX DEBIAN

Bannanian 16.04 (Debian 8/Jessie) (released 2016-04-23 / 158 MB) 
Linux bananapi 3.4.111-bananian

#### Imagen Sistema Operativo
```
diskutil list
diskutil umountDisk /dev/disk3
sudo dd bs=1m if=bananian-1604.img of=/dev/disk3
```

#### Acceso
Acceso configurado por defecto en el sistema (Bannanian Debian 8 Jessy).
```
root / pi
```

Recomendable cambiar el password del usuario `root`:
```
passwd
```

#### Actualizar Repositorios
Actualizar todos los repositorios y paquetes de instalación a la version mas reciente:
```
apt-get update
```

#### Preparar Sistema VPN
```
apt-get install -y build-essential make automake cmake git subversion checkinstall unzip nmap
apt-get install -y libwrap0 libwrap0-dev bcrelay libpcap0.8-dev
apt-get -y install libgmp10 libgmp3-dev libssl-dev pkg-config libpcsclite-dev libpam0g-dev rng-tools
```
```
apt-get -y autoremove --purge
apt-get autoclean
apt-get autoremove
apt-get clean
ldconfig
```

#### Editor de Usuario
Usar el Vim como editor por defecto del sistema:
```
echo "set nocompatible" > ~/.vimrc
echo "set backspace=indent,eol,start" >> ~/.vimrc
```

`/etc/environment`
```
LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8
```

#### Sistema de Servicios
Eliminar el sistema `SystemV` e instalar el nuevo sistema `systemd`:
```
rm /etc/apt/preferences.d/systemd
apt-get update && apt-get install -y systemd dbus systemd-sysv
reboot
```
```
apt-get remove -y sysvinit
```

#### Configurar Hostname / Nombre del Servidor
Establecer el nombre del servidor en los siguientes archivos:
`/etc/hostname`
```
vpn-server
```

## Network
Then disable the DHCP client daemon and switch to standard Debian networking. Desactivar DHCP para activar el sistema de IP standard.
```
systemctl disable dhcpcd
systemctl enable networking
```

Network Interfaces method and configure a static network address:

`/etc/network/interfaces`
```
# interfaces(5) file used by ifup(8) and ifdown(8)
# Include files from /etc/network/interfaces.d:
source-directory /etc/network/interfaces.d

auto lo
iface lo inet loopback

auto eth0

# dhcp configuration
#iface eth0 inet dhcp

# static ip configuration
#iface eth0 inet static
#       address 192.168.6.241
#       netmask 255.255.255.0
#       gateway 192.168.6.1

auto eth0
iface eth0 inet static
        address 10.0.60.150
        netmask 255.255.255.0
        gateway 10.0.60.100
        dns-nameservers 8.8.8.8 8.8.4.4
```

#### Herramientas Networking
```
iptables -L -n -v
iptables -t nat -L
```
```
apt-get install tcpdump
tcpdump -nn -vv -i any 'udp port 67 and udp port 68'
```
```
apt-get install nmap
nmap -sU -p 47
```
```
netstat -tulpn
```
```
tail -f /var/log/syslog
```

## VPN
Configuracion especifica de firewall y enrutado para controlar el trafico del servidor VPN.

`/etc/vpn.sh`
```
#!/bin/bash

echo 1 > /proc/sys/net/ipv4/ip_forward

for each in /proc/sys/net/ipv4/conf/*
do
    echo 0 > $each/accept_redirects
    echo 0 > $each/send_redirects
done

iptables -A INPUT -p udp -m udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 1723 -j ACCEPT

iptables -A INPUT -p gre -j ACCEPT
iptables -A OUTPUT -p gre -j ACCEPT
iptables -A INPUT -p esp -j ACCEPT
iptables -A OUTPUT -p esp -j ACCEPT

iptables -t nat -A POSTROUTING -s 20.20.20.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 22.22.22.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.0.222.0/24 -o eth0 -j MASQUERADE

iptables -A FORWARD -s 20.20.20.0/24 -d 10.0.0.0/8 -j ACCEPT
iptables -A FORWARD -s 20.20.20.0/24 -d 192.168.0.0/16 -j ACCEPT

iptables -A FORWARD -s 22.22.22.0/24 -d 10.0.0.0/8 -j ACCEPT
iptables -A FORWARD -s 22.22.22.0/24 -d 192.168.0.0/16 -j ACCEPT

iptables -A FORWARD -s 10.0.222.0/24 -d 10.0.0.0/8 -j ACCEPT
iptables -A FORWARD -s 10.0.222.0/24 -d 192.168.0.0/16 -j ACCEPT

iptables -A FORWARD -s 20.20.20.0/24 -j REJECT
iptables -A FORWARD -s 22.22.22.0/24 -j REJECT
iptables -A FORWARD -s 10.0.222.0/24 -j REJECT

route add -net 10.0.0.0 netmask 255.0.0.0 gw 10.0.60.220
route add -net 192.168.0.0 netmask 255.255.0.0 gw 10.0.60.220
```

## Dnsmasq DHCP Server
Dnsmasq is a Domain Name System (DNS) forwarder and Dynamic Host Configuration Protocol (DHCP) server for small computer networks.
```
cd /root
mkdir dnsmasq
cd dnsmasq
wget http://www.thekelleys.org.uk/dnsmasq/dnsmasq-2.76.tar.gz
tar zxvf dnsmasq-2.76.tar.gz
```
```
make -j4
make install
cp dnsmasq.conf.example /etc/dnsmasq.conf
```

`/etc/dnsmasq.conf`
```
# Configuration file for dnsmasq.
#

# keep bogus-priv OFF, upstream does know about 10.x.x.x addrs
except-interface=eth0

log-facility=/var/log/dnsmasq.log
log-queries=extra
log-dhcp

dhcp-range=set:red,20.20.20.1,20.20.20.254,255.255.255.0,24h
# 3: router, 6: DNS, 121/249: static routes
dhcp-option=tag:red,121,10.0.0.0/8,20.20.20.1,192.168.0.0/16,20.20.20.1  # for rfc-client
dhcp-option=tag:red,249,10.0.0.0/8,20.20.20.1,192.168.0.0/16,20.20.20.1  # for win-client
dhcp-option=tag:red,vendor:MSFT,2,1i

dhcp-range=set:green,22.22.22.1,22.22.22.254,255.255.255.0,24h
# 3: router, 6: DNS, 121/249: static routes
dhcp-option=tag:green,121,10.0.0.0/8,22.22.22.1,192.168.0.0/16,22.22.22.1  # for rfc-client
dhcp-option=tag:green,249,10.0.0.0/8,22.22.22.1,192.168.0.0/16,22.22.22.1  # for win-client
dhcp-option=tag:green,vendor:MSFT,2,1i

dhcp-range=set:blue,10.0.222.1,10.0.222.254
# 3: router, 6: DNS, 121/249: static routes
dhcp-option=tag:blue,3,10.0.60.150
dhcp-option=tag:blue,6,10.0.60.150
dhcp-option=tag:blue,121,10.0.0.0/8,10.0.60.150,192.168.0.0/16,10.0.60.150  # for rfc-client
dhcp-option=tag:blue,249,10.0.0.0/8,10.0.60.150,192.168.0.0/16,10.0.60.150  # for win-client
dhcp-option=tag:blue,vendor:MSFT,2,1i
```
## PPP Service
Implements the Point-to-Point Protocol (PPP) on Linux. Debian 8 Repositories has PPP 2.4.6.
```
apt-get install -y ppp ppp-dev
```

`/etc/ppp/chap-secrets`
```
# Secrets for authentication using CHAP
# client        server  secret          IP addresses
USERNAME        *       PASSWORD        *
```

## PPTP Server
Poptop - The PPTP Server for Linux
```
https://ppp.samba.org/pppd.html
```

```
cd /root
mkdir pptpd
cd pptpd
wget https://sourceforge.net/projects/poptop/files/pptpd/pptpd-1.4.0/pptpd-1.4.0.tar.gz
```

```
./configure
make -j4
make install
```

```
mkdir /usr/lib/pptpd
cd /usr/lib/pptpd
ln -s /usr/local/lib/pptpd/pptpd-logwtmp.so pptpd-logwtmp.so
```

`/etc/pptpd.conf`
```
###############################################################################
# $Id: pptpd.conf,v 1.11 2011/05/19 00:02:50 quozl Exp $
#
# Sample Poptop configuration file /etc/pptpd.conf
#
# Changes are effective when pptpd is restarted.
###############################################################################

option /etc/ppp/options.pptpd
logwtmp

# Using private address 20.20.20.0/24 for ppp+ device
localip 20.20.20.1
remoteip 20.20.20.2-254
```

`/etc/ppp/options.pptpd`
```
###############################################################################
# $Id: options.pptpd,v 1.11 2005/12/29 01:21:09 quozl Exp $
#
# Sample Poptop PPP options file /etc/ppp/options.pptpd
# Options used by PPP when a connection arrives from a client.
# This file is pointed to by /etc/pptpd.conf option keyword.
# Changes are effective on the next connection.  See "man pppd".
#
# You are expected to change this file to suit your system.  As
# packaged, it requires PPP 2.4.2 and the kernel MPPE module.
###############################################################################

name pptpd

require-mschap-v2
require-mppe-128

nodefaultroute
lock
mtu 1460
mru 1460
passive

proxyarp
```

## L2TP Server

```
cd /root
mkdir xl2tp
cd xl2tp
wget https://github.com/xelerance/xl2tpd/archive/v1.3.8.tar.gz
tar zxvf v1.3.8.tar.gz
```

```
make -j4
make install
```

`/etc/xl2tpd/xl2tpd.conf`
```
[global]
port = 1701
auth file = /etc/ppp/chap-secrets

[lns default]
ip range = 22.22.22.2-22.22.22.254
local ip = 22.22.22.1
refuse chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
```

`/etc/ppp/options.xl2tpd`
```
name l2tpd
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
idle 1800
mtu 1460
mru 1460
lcp-echo-failure 10
lcp-echo-interval 60
connect-delay 5000
```

## StrongSwan

```
cd /root
mkdir ipsec 
cd ipsec
wget https://download.strongswan.org/strongswan-5.5.1.tar.gz
tar zxvf strongswan-5.5.1.tar.gz
```

```
./configure --prefix=/usr --sysconfdir=/etc --enable-eap-radius --enable-eap-mschapv2 --enable-md4 --enable-eap-identity --enable-eap-md5 --enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap --enable-eap-tnc --enable-eap-dynamic --enable-xauth-eap --enable-openssl --enable-unity --enable-dhcp
```

```
make -j4
make install
```

`/etc/ipsec.conf`
```
# ipsec.conf - strongSwan IPsec configuration file

config setup
        uniqueids=never
        charondebug="cfg 2, dmn 2, ike 2, net 0"

conn %default
        dpdaction=restart
        dpddelay=60s
        rekey=no
        left=%defaultroute
        leftfirewall=yes
        right=%any
        ikelifetime=24h
        keylife=24h
        rekeymargin=3m
        keyingtries=%forever
        auto=start
        closeaction=restart

#######################################
# L2TP Connections
#######################################

conn L2TP-IKEv1-PSK
        type=transport
        keyexchange=ikev1
        authby=secret
        leftprotoport=udp/l2tp
        left=%any
        right=%any
        rekey=no
        forceencaps=yes
        esp=aes128-sha1
        ike=aes256-sha1-modp1024

#######################################
# Default non L2TP Connections
#######################################

conn Non-L2TP
        leftsubnet=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
        rightsourceip=%dhcp

#######################################
# EAP Connections
#######################################

# This detects a supported EAP method
conn IKEv2-EAP
        also=Non-L2TP
        keyexchange=ikev2
        eap_identity=%any
        rightauth=eap-dynamic
        leftauth=pubkey
        leftcert=server.cert.pem
        leftid=@vpn.server.com
        leftsendcert=always

#######################################
# PSK Connections
#######################################

conn IKEv2-PSK
        also=Non-L2TP
        keyexchange=ikev2
        authby=secret
        leftid=vpn.server.com

# Cisco IPSec
conn IKEv1-PSK-XAuth
        also=Non-L2TP
        keyexchange=ikev1
        leftauth=psk
        rightauth=psk
        rightauth2=xauth
```

`/etc/ipsec.secrets`
```
# ipsec.secrets - strongSwan IPsec secrets file
: RSA server.key.pem
: PSK "PASSWORD"
USERNAME : EAP "PASSWORD"
USERNAME : XAUTH "PASSWORD"
```

`/etc/strongswan.conf`
```
# /etc/strongswan.conf - strongSwan configuration file
# strongswan.conf - strongSwan configuration file
#
# Refer to the strongswan.conf(5) manpage for details

charon {
        load_modular = yes
        send_vendor_id = yes
        cisco_unity = yes
        plugins {
                include strongswan.d/charon/*.conf
                attr {
                        dns = 8.8.8.8, 8.8.4.4
                }
                dhcp {
                        force_server_address = yes
                        identity_lease = yes
                        server = 10.0.60.150

                }
        }
}

include strongswan.d/*.conf
```

## IPSec Certificates
Para utilizar VPN IKEv2 EAP. IKEv2 con usuario / password. Es necesario tener el certificado raiz instalado en el CLIENTE.
Para ello hay dos formas: autogenerarlo o utilizar una autoridad certificadora. Si se autogenera hay que copiar el certificado raiz (ca.cer.pem) en cada cliente, sino NUNCA conectara IKEv2 con EAP.

While the connecting user is authenticated with Username/Password using MSCHAPv2, the gateway is authenticated in advance using Certificates. To install the trusted CA certificate locally, call up the Microsoft Management Console (mmc) and add the Certificates Snap-In: Go into the Certificates (Local Computer) / Trusted Root Certification Authorities / Certificates folder. Si se genera hay que instalarlo manualmente en todo el cliente windows que se quiera conectar, mejor usar un certificado preinstalado (Verisign por ejemplo).

#### AUTOGENERADO (hay que instalar el certificado raiz 'ca.cert.pem' en CADA CLIENTE sino NUNCA conectara):
```
ipsec pki --gen --outform pem > ca.key.pem
ipsec pki --self --in ca.key.pem --dn "C=CN, O=VPN Server, CN=vpn.server.com" --ca --lifetime 3650 --outform pem >ca.cert.pem
ipsec pki --gen --outform pem > server.key.pem
ipsec pki --pub --in server.key.pem | ipsec pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --dn "C=CN, O=VPN Server, CN=vpn.server.com" --san="vpn.server.com" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem
```

```
\cp -r ca.cert.pem /etc/ipsec.d/cacerts/
\cp -r server.cert.pem /etc/ipsec.d/certs/
\cp -r server.key.pem /etc/ipsec.d/private/
```

#### COMODO SSL Security Services
Tenemos la clave privada con la que se genera la peticion del certificado `server.key`. Una vez comprado el certificado para el DOMINIO vpn.server.com hay que descargar:
```
Root CA Certificate - AddTrustExternalCARoot.crt
Intermediate CA Certificate - COMODORSAAddTrustCA.crt
Intermediate CA Certificate - COMODORSADomainValidationSecureServerCA.crt
Your PositiveSSL Certificate - vpn_server_com.crt
```

```
openssl rsa -in server.key -out server.key.pem
cat vpn_server_com.crt COMODORSADomainValidationSecureServerCA.crt  COMODORSAAddTrustCA.crt AddTrustExternalCARoot.crt > server.cert.pem

\cp -r server.key.pem /etc/ipsec.d/private/
\cp -r server.cert.pem /etc/ipsec.d/certs/
```

```
\cp -r AddTrustExternalCARoot.crt /etc/ipsec.d/cacerts/
\cp -r COMODORSAAddTrustCA.crt /etc/ipsec.d/cacerts/
\cp -r COMODORSADomainValidationSecureServerCA.crt /etc/ipsec.d/cacerts/
```

## System Services

`/etc/systemd/system/vpn.service`
```
[Unit]
Description=VPN Settings at boot
After=syslog.target network.target

[Service]
ExecStart=/etc/vpn.sh
StandardOutput=syslog

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/dnsmasq.service`
```
[Unit]
Description=A lightweight DHCP and caching DNS server
After=syslog.target network.target

[Service]
ExecStart=/usr/local/sbin/dnsmasq -k --conf-file=/etc/dnsmasq.conf
StandardOutput=syslog
Restart=always

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/pptpd.service`
```
[Unit]
Description=Point-to-Point Tunneling Protocol (PPTP)
After=syslog.target network.target

[Service]
ExecStart=/usr/local/sbin/pptpd --fg
StandardOutput=syslog
Restart=always

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/xl2tpd.service`
```
[Unit]
Description=Level 2 Tunnel Protocol Daemon (L2TP)
After=syslog.target network.target

[Service]
PIDFile=/var/run/xl2tpd/xl2tpd.pid
ExecStartPre=/bin/sh -x -c 'mkdir -p /var/run/xl2tpd'
ExecStart=/usr/local/sbin/xl2tpd -D
StandardOutput=syslog
Restart=always

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/ipsec.service`
```
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using ipsec.conf
After=syslog.target network.target

[Service]
ExecStart=/usr/sbin/ipsec start --nofork
StandardOutput=syslog
Restart=always

[Install]
WantedBy=multi-user.target
```

```
systemctl start vpn.service
systemctl start dnsmasq.service 
systemctl start pptpd.service  
systemctl start xl2tpd.service  
systemctl start ipsec.service 
```
```
systemctl enable vpn.service
systemctl enable dnsmasq.service 
systemctl enable pptpd.service 
systemctl enable xl2tpd.service 
systemctl enable ipsec.service 
```

## VPN Service Running (PPTP / L2TP / IPSec / IKEv1 / IKEv2)
There are two services running: Strongswan and addtionally XL2TPD for IPSec/L2TP support. The default IPSec configuration supports:
```
IKEv2 with EAP Authentication (Though a certificate has to be added for that to work)
IKEv2 with PSK
IKEv1 with PSK and XAuth (Cisco IPSec)
IPSec/L2TP with PSK
```

The ports that are exposed for this container to work are:
```
4500/udp and 500/udp for IPSec
1701/udp for L2TP
1723/tcp for PPTP
```

```
VPN PPTP
VPN L2TP PSK
VPN IKEv1 PSK (Cisco IPSec)
VPN IKEv2 EAP
VPN IKEv2 PSK
```

## Windows L2TP Behind NAT
En servidores que se encuentran tras una NAT puede haber problemas de conectividad con sistemas Windows. 
Para solventar la conexión L2TP puede ser conveniente anotar en el registro de windows las claves siguientes.

#### WINDOWS 7 SUPERIOR
```
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent /v AssumeUDPEncapsulationContextOnSendRule /t REG_DWORD /d 0x2 /f
```
####WINDOWS XP
```
REG ADD HKLM\SYSTEM\CurrentControlSet\Services\IPSec /v AssumeUDPEncapsulationContextOnSendRule /t REG_DWORD /d 0x2 /f
```
