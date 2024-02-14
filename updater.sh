##################################
# Nginx CDN Config File Download #
##################################
echo -e "${GREEN}Download required nginx CDN config files.\n${ENDCOLOR}"
sleep 1

echo -e "Check to see if nginx.conf.old file exists already.\n"
NGINXOLD_FILE=/etc/nginx/nginx.conf.old
if test -f "$NGINXOLD_FILE"; then
    echo -e "$NGINXOLD_FILE already exists, need to delete.\n"
    rm /etc/nginx/nginx.conf.old
fi

echo -e "Check to see if nginx.conf file exists already.\n"
NGINX_FILE=/etc/nginx/nginx.conf
if test -f "$NGINX_FILE"; then
    echo -e "$NGINX_FILE already exists, needs to be moved.\n"
    mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.old
fi

echo -e "Make sure no nginx.conf file exists now, and download it.\n"
if [ ! -f "$NGINX_FILE" ]
then
curl -o /etc/nginx/nginx.conf https://raw.githubusercontent.com/eembling/EricServices-Lancache-nginx/main/nginx.conf
fi
