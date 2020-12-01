#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#   Dscription: V2ray ws+tls With Bt-Panel
#   Version: 1.3.20.00908

#fonts color
Red="\033[1;31m"
Green="\033[1;32m"
Yellow="\033[1;33m"
Blue="\033[1;36m"
Font="\033[0m"

OK="${Green}[OK]${Font}"
web_dir="/www/wwwroot"


install_v2ray_ws_tls() {
    install_prepare
    v2ray_install
    V2Ray_information
    start_service
}


install_prepare() {
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi
    if [[ -e "/etc/init.d/bt" ]]; then
        sleep 1
    else
        echo -e "${Yellow} 未检测到 宝塔面板，请先安装……${Font}"
        exit 1
    fi
    if [[ -e "/www/server/nginx" ]]; then
        sleep 1
    else
        echo -e "${Yellow} 未检测到 Nginx，请先安装……${Font}"
        exit 1
    fi

    echo -e "${Yellow} 请确保已完成伪装网址的域名解析 ${Font}"
    read -rp "请输入域名信息(eg:www.hanx.vip):" domain

    webstate=26
    Website_config
    acme_SSL

    yum install -y wget
    yum reinstall glibc-headers gcc-c++ -y
}


Website_config() {
    if [[ -e "/www/server/panel/vhost/nginx/${domain}.conf" ]]; then
        sleep 1
    else
      echo -e "${Yellow} 未检测到 ${domain} 内容！${Font}"
      read -rp " 是否尝试自动配置？ [Y/N]?" autowebcfg
        case $autowebcfg in
        [yY])
            WriteWebConf
            Website_arrange
            echo -e "${OK} 自动配置完成！ ${Font}"
            ;;
        *)
            echo -e "${Yellow}请手动配置后重试！ ${Font}"
            exit 
            ;;
        esac
    fi
}


acme_SSL() {
    if [[ -e "/www/server/panel/vhost/cert/${domain}/" ]]; then
        sleep 1
    else
        curl https://get.acme.sh | sh
        mkdir -p /www/wwwroot/${domain}/.well-known/acme-challenge
        chmod 777 /www/wwwroot/${domain}/.well-known/acme-challenge        
        ~/.acme.sh/acme.sh  --issue  -d "${domain}"  --webroot /www/wwwroot/${domain}/
        mkdir -p /www/server/panel/vhost/cert/${domain}/
        ~/.acme.sh/acme.sh  --installcert  -d  "${domain}" \
            --key-file   /www/server/panel/vhost/cert/${domain}/privkey.key \
            --fullchain-file /www/server/panel/vhost/cert/${domain}/fullchain.cer \
            --reloadcmd  "/www/server/nginx/sbin/nginx -s reload"
    fi
}


v2ray_install() {
    curl -O https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh
    bash install-release.sh
    
    [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
    PORT=$((RANDOM + 10000))

    cd /usr/local/etc/v2ray/
    WriteV2rayConf

    sed -i '$d' /www/server/panel/vhost/nginx/${domain}.conf
    cat >>/www/server/panel/vhost/nginx/${domain}.conf <<EOF
        location /vcache/
        {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        }
} 
EOF
    if [[ $(V2ray_info_query '\"aid\"') == 16  ]]; then
        sleep 1
    else    
        sed -i "/    ssl_certificate    /www/server/panel/vhost/cert/${domain}/fullchain.cer/c  \    ssl_certificate    /www/server/panel/vhost/cert/${domain}/fullchain.pem;" /www/server/panel/vhost/nginx/${domain}.conf
        sed -i "/    ssl_certificate_key    \/www\/server\/panel\/vhost\/cert\/${domain}\/privkey.key;/c  \    ssl_certificate_key    \/www\/server\/panel\/vhost\/cert\/${domain}\/privkey.pem;" /www/server/panel/vhost/nginx/${domain}.conf
    fi

    cat >/usr/local/vmess_info.json <<-EOF
{
  "v": "2",
  "ps": "v2ray_${domain}",
  "add": "${domain}",
  "port": "443",
  "id": "${UUID}",
  "aid": "${webstate}",
  "net": "ws",
  "type": "none",
  "host": "${domain}",
  "path": "/vcache/",
  "tls": "tls"
}
EOF
}


V2ray_info_query() {
    grep "$1" "/usr/local/vmess_info.json" | awk -F '"' '{print $4}'
}


V2Ray_information() {
    clear
    vmess_link="vmess://$(base64 -w 0 /usr/local/vmess_info.json)"
    {
        echo -e "${Green} V2ray vmess+ws+tls 安装成功${Font}"
        echo -e "${Blue}=====================================================${Font}"
        echo -e "${Green} V2ray 配置信息 ${Font}"
        echo -e "${Green} 地址（address）:${Font} $(V2ray_info_query '\"add\"') "
        echo -e "${Green} 端口（port）：${Font} $(V2ray_info_query '\"port\"') "
        echo -e "${Green} 用户ID（id）：${Font} $(V2ray_info_query '\"id\"')"
        echo -e "${Green} 额外ID（alterId）：${Font} 16"
        echo -e "${Green} 加密方式（security）：${Font} auto"
        echo -e "${Green} 传输协议（network）：${Font} ws"
        echo -e "${Green} 伪装类型（type）：${Font} none"
        echo -e "${Green} 路径（不要落下/）：${Font} /vcache/"
        echo -e "${Green} 底层传输安全：${Font} tls"
        echo -e "${Blue}=====================================================${Font}" 
        echo -e "${Yellow} URL导入链接:${vmess_link} ${Font}"
    }
}


WriteWebConf() {
      cat >/www/server/panel/vhost/rewrite/${domain}.conf <<EOF
EOF

      cat >/www/server/panel/vhost/nginx/${domain}.conf <<EOF
server
{
    listen 80;
  listen 443 ssl http2;
    server_name ${domain};
    index index.php index.html index.htm default.php default.htm default.html;
    root /www/wwwroot/${domain};
    
    #SSL-START SSL相关配置，请勿删除或修改下一行带注释的404规则
    #error_page 404/404.html;
    #HTTP_TO_HTTPS_START
    if (\$server_port !~ 443){
        rewrite ^(/.*)$ https://\$host\$1 permanent;
    }
    #HTTP_TO_HTTPS_END
    ssl_certificate    /www/server/panel/vhost/cert/${domain}/fullchain.cer;
    ssl_certificate_key    /www/server/panel/vhost/cert/${domain}/privkey.key;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    error_page 497  https://\$host\$request_uri;
    #SSL-END
    #ERROR-PAGE-START  错误页配置，可以注释、删除或修改
    #error_page 404 /404.html;
    #error_page 502 /502.html;
    #ERROR-PAGE-END
    #PHP-INFO-START  PHP引用配置，可以注释或修改
    include enable-php-00.conf;
    #PHP-INFO-END
    #REWRITE-START URL重写规则引用,修改后将导致面板设置的伪静态规则失效
    include /www/server/panel/vhost/rewrite/${domain}.conf;
    #REWRITE-END
    #禁止访问的文件或目录
    location ~ ^/(\.user.ini|\.htaccess|\.git|\.svn|\.project|LICENSE|README.md)
    {
        return 404;
    }
    #一键申请SSL证书验证目录相关设置
    location ~ \.well-known{
        allow all;
    }
    
    location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
    {
        expires      30d;
        error_log off;
        access_log /dev/null;
    }
    location ~ .*\.(js|css)?$
    {
        expires      12h;
        error_log off;
        access_log /dev/null; 
    }
    access_log  /www/wwwlogs/${domain}.log;
    error_log  /www/wwwlogs/${domain}.error.log;
}
EOF
  webstate=16
}


Website_arrange() {
    if [[ -e "/www/wwwroot/${domain}" ]]; then
        sleep 1   
    else     
        mkdir -p /www/wwwroot/${domain}
    fi    
    cd /www/wwwroot/${domain}
    wget -nc https://github.com/vikinglzh/v2ray_bt/master/index.zip
    unzip index.zip
}


WriteV2rayConf() {
      cat >/usr/local/etc/v2ray/config.json <<EOF
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
        "loglevel": "warning"
  },
  "inbound": {
    "tag":"vmess-in",
    "listen": "127.0.0.1",
    "port": ${PORT},
    "protocol": "vmess",
    "settings": {
    "clients": [
      {
        "id": "${UUID}",
        "level": 0, 
        "alterId": 16
        }
      ]
     }, 
    "streamSettings": {
      "network": "ws",
      "security": "auto",
      "wsSettings": {
        "path": "/vcache/",
        "headers": {
          "Host": "${domain}"
        }
      }
    }
  }, 
  "outbound": {
    "tag":"direct",
    "protocol": "freedom",
    "settings": {}
  }, 
  "outboundDetour": [
    {
      "protocol": "blackhole",
      "settings": { },
      "tag": "blocked"
    }
  ], 
  "routing": {
    "strategy": "rules",
    "settings": {
      "rules": [
        {
          "type": "field",
          "ip": [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "::1/128",
            "fc00::/7",
            "fe80::/10"
          ], 
          "outboundTag": "blocked"
        }
      ]
    }
  },
  "policy": {
    "levels": {
      "0": {
      "uplinkOnly": 0,
      "downlinkOnly": 0,
      "connIdle": 150,
      "handshake": 4
      }
    }
  } 
}
EOF
}


start_service() {
    systemctl enable v2ray
    systemctl start v2ray    
    systemctl daemon-reload
    /www/server/nginx/sbin/nginx -s reload
    systemctl restart v2ray.service
}


stop_service() {
    systemctl stop v2ray
    systemctl stop v2ray.service
    systemctl disable v2ray.service
}


uninstall_V2Ray() {
    systemctl stop v2ray
    systemctl stop v2ray.service
    systemctl disable v2ray.service
    bash install-release.sh --remove

    if [[ $(V2ray_info_query '\"aid\"') == 16  ]]; then
        rm -rf /www/server/panel/vhost/rewrite/$(V2ray_info_query '\"add\"').conf
        rm -rf /www/server/panel/vhost/nginx/$(V2ray_info_query '\"add\"').conf
        rm -rf /www/server/panel/vhost/cert/$(V2ray_info_query '\"add\"')
        rm -rf /www/wwwroot/$(V2ray_info_query '\"add\"')/
    else    
        sed -i "/\location \/vcache\//,/}/d"  /www/server/panel/vhost/nginx/$(V2ray_info_query '\"add\"').conf
    fi
    rm -rf /etc/systemd/system/v2ray.service
    rm -rf /usr/bin/v2ray
    rm -rf /etc/v2ray
    rm -rf /usr/local/etc/v2ray/
    systemctl daemon-reload
    echo -e "${OK} ${GreenBG} 卸载完成，谢谢使用~ ${Font}"
}


Main_menu() {
  clear    
    echo -e ""
    echo -e "  ${Blue}V2ray (ws+tls) With 宝塔 部署脚本${Font}"
    echo -e "    ${Blue}---- authored by hxlive ----${Font}"
    echo -e ""
    echo -e " ${Yellow}———————————— 安装选项 ————————————${Font}"
    echo -e ""    
    echo -e "    ${Green}1. 安装 V2Ray (ws+tls)${Font}"
    echo -e "    ${Green}2. 查看 V2Ray 配置信息${Font}"
    echo -e "    ${Green}3. 升级 V2Ray Core${Font}"
    echo -e "    ${Red}4. 卸载 V2Ray 及配置${Font}"
    echo -e "    ${Green}5. 退出 V2Ray 部署脚本${Font}" 
    echo -e ""    
    read -rp " 请输入数字：" menu_num
    case $menu_num in
    1)
        install_v2ray_ws_tls
        ;;
    2)
        V2Ray_information
        ;;
    3)
        curl -O https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh
        bash install-release.sh
        ;;
    4)
        uninstall_V2Ray
        ;;
    5)
        exit 0
        ;;
    *)
        echo -e "${RedBG}请输入正确的数字${Font}"
        sleep 2s
        Main_menu
        ;;
    esac
}

Main_menu