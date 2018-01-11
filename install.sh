#!/bin/bash

set -e
set -x

sudo apt update
sudo apt install -y apache2
sudo apt install -y curl
sudo apt install -y freeradius
sudo apt install -y freeradius-utils
sudo apt install -y git
sudo apt install -y ipsec-tools
sudo apt install -y libapache2-mod-auth-radius
sudo apt install -y openssh-client
sudo apt install -y openssh-server
sudo apt install -y strongswan
sudo apt install -y strongswan-plugin-eap-md5
sudo apt install -y strongswan-plugin-eap-radius

#### Inatall Wireshark
sudo apt install -y wireshark
# sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER

#### Install Sublime Text 3
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
sudo apt-get install apt-transport-https
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
sudo apt-get update
sudo apt-get install sublime-text

#### Apache2
# Generate default digital certificates for Apache2
sudo make-ssl-cert generate-default-snakeoil --force-overwrite
# Enable Apache2 SSL Site
sudo a2ensite default-ssl.conf
# Enable Apache2 TLS/SSL module
sudo a2enmod ssl

#### IPv6 settings
echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

#### Clone iptables
cd ~/Desktop
# git clone https://github.com/lem-course/isp-iptables.git
git clone https://github.com/rlamp/isp-iptables.git
cd ./isp-iptables
chmod +x iptables1.sh 
chmod +x iptables2.sh

#### Prepare for a VPN IPsec tunnel using digital certificates
# Create CA key and certificate
cd ~/Desktop
ipsec pki --gen > caKey.der
ipsec pki --self --in caKey.der --dn "C=SL, O=FRI-UL, CN=FRICA" --ca > caCert.der