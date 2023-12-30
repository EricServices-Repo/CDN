#!/usr/bin/env bash
#EricServic.es CDN Server Install

##### Variables ###############################
# CERTBOT - Toggle for Installing Certbot
# DOMAIN - Email Domain
###############################################

#################
# Define Colors #
#################
RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[34m"
ENDCOLOR="\e[0m"

echo -e "${GREEN}EricServic.es CDN Server${ENDCOLOR}"

echo -e "${BLUE} ______      _       _____                 _                    ${ENDCOLOR}"  
echo -e "${BLUE}|  ____|    (_)     / ____|               (_)                   ${ENDCOLOR}"
echo -e "${BLUE}| |__   _ __ _  ___| (___   ___ _ ____   ___  ___   ___  ___    ${ENDCOLOR}"
echo -e "${BLUE}|  __| | '__| |/ __|\___ \ / _ \ '__\ \ / / |/ __| / _ \/ __|   ${ENDCOLOR}"
echo -e "${BLUE}| |____| |  | | (__ ____) |  __/ |   \ V /| | (__ |  __/\__ \   ${ENDCOLOR}"
echo -e "${BLUE}|______|_|  |_|\___|_____/ \___|_|    \_/ |_|\___(_)___||___/ \n${ENDCOLOR}"

#####################
# Set all Variables #
#####################
echo -e "${GREEN}Set Variables for custom install.${ENDCOLOR}"

read -p "Set DOMAIN [ericservic.es]:" DOMAIN
DOMAIN="${DOMAIN:=ericservic.es}"
echo "$DOMAIN"

read -p "Install Certbot? (s:Staging) [y/N/s]:" CERTBOT
CERTBOT="${CERTBOT:=n}"
echo "$CERTBOT"


################################
# Updates + Install + Firewall #
################################
echo -e "${GREEN}Process updates and install${ENDCOLOR}"
sleep 1

echo -e "Yum Update"
yum update -y

echo -e "Install epel-release"
yum install epel-release -y

echo -e "${GREEN}Check to see if required programs are installed.${ENDCOLOR}"
yum install open-vm-tools firewalld wget certbot python3-certbot-nginx rsyslog nginx -y 

echo -e "${GREEN}Turning on the Firewall${ENDCOLOR}"
systemctl enable firewalld
systemctl restart firewalld

echo -e "${GREEN}Allow Ports for Email Server on Firewall\n${ENDCOLOR}"
firewall-cmd --permanent --add-port={80/tcp,443/tcp}

echo -e "${GREEN}Reload the firewall.\n${ENDCOLOR}"
firewall-cmd --reload

echo -e "${GREEN}Ports allowed on firewall.\n${ENDCOLOR}"
firewall-cmd --list-all

# Permissive Mode #
###################
echo -e "${GREEN}Setting to Permissive Mode for install\n${ENDCOLOR}"
setenforce 0

echo -e "${GREEN}Setting Permissive SELINUX value.\n${ENDCOLOR}"
sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config


#####################
# Configure CertBot #
#####################

if [[ "$CERTBOT" =~ ^([yY][eE][sS]|[yY]|[sS])$ ]]
then
echo -e "${GREEN}Configure Let's Encrypt SSL Certs\n${ENDCOLOR}"
sleep 1

if [[ "$CERTBOT" =~ ^([sS])$ ]]
then
echo -e "${GREEN}Installing Staging Certificates\n${ENDCOLOR}"
certbot run -n --nginx --agree-tos --test-cert -d cdn.$DOMAIN, -m  admin@$DOMAIN --redirect
fi

if [[ "$CERTBOT" =~ ^([yY][eE][sS]|[yY])$ ]]
then
echo -e "${GREEN}Installing Production Certificates\n${ENDCOLOR}"
certbot run -n --nginx --agree-tos -d cdn.$DOMAIN, -m  admin@$DOMAIN --redirect
fi
