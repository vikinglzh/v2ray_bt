# v2ray_bt
**与宝塔面板共存v2ray一键安装脚本**

使用说明：

1、目前仅测试过CentOS7，其他系统未经测试；

2、前提：VPS上要安装有 宝塔Linux面板，且通过宝塔安装有Nginx；

3、确保需要使用的域名已经解析至VPS；

4、如果通过宝塔部署了要使用的域名的网站，请先开启SSL；如果没有部署要使用域名的网站，脚本会自行配置；

5、使用本脚本即可完成部署；

一键脚本：
```
wget -N --no-check-certificate https://raw.githubusercontent.com/vikinglzh/V2ray_bt/master/v2bt.sh && chmod +x v2bt.sh && bash v2bt.sh
```
> v2配置目录：/usr/local/etc/v2ray/**.config
