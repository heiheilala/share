# 使用VPS科学上网及搭建博客
### 一、概述
论坛前面也有讨论科学上网相应的工具(分享个开源的翻墙工具：XX-net)，现在介绍下自己使用国外VPS搭建shadowsocks科学上网，以及创建博客的过程。
### 二、VPS选择
网上搜索VPS有较多选择，如Vultr(欧神推荐)、SugarHosts、Linode、VPS.NET、BandwagonHost、DigitalOcean等。每个不同的VPS在各地区有不同的机房，如美国、新加坡、香港、日本等。线路速度不一致，价钱也各不相同，具体介绍参考“老左常用国内/国外VPS推荐”。
我选择BandwagonHost，俗称搬瓦工（好贴切），原因就是价格便宜($19.99/年)、可用支付宝，对新手来说是不错的选择。当然不足之处就是线路不稳定，延时较大，自我感觉平时查查资料还是够用的，我选择的VPS配置如下:
```
CPU：1核
内存：512MB
硬盘：10GB SSD
流量：500GB
端口：1Gbps
架构：KVM+KiwiVM面板
IP数：1独立IP
系统：Linux
$19.99/年（6机房KVM）
注："6机房KVM"就是有6个机房可以切换，如果因为科学上网IP被禁止了就可以通过切换机房来更换IP地址。
```
通过控制面板可以选择VPS运行的系统以及机房所在地。我当前选择的是洛杉矶机房以及ubuntu14 64位系统。
如图所示仪表盘用于查看资源信息以及重启系统。
### 二、搭建shadowsocks服务
翻墙查找资料是很多程序员必备的技能，常用的方法是VPN(K3C支持)。由于有VPS我使用shadowsocks的方式，优点是方便快捷、各个系统兼容性较强。且配置简单。
1.服务器端搭建
1)安装
```
sudo apt-get install python-pip
sudo pip install shadowsocks
```
2)配置
通过json格式字符串保存配置信息。

配置完成后通过以下命令即可启动服务器端程序，可以添加到"/etc/rc.local"开机启动服务。
```
ssserver -c /etc/shadowsocks.json
```
2.客户端连接
shadowsocks客户端支持多平台，目前我在windows、ubuntu以及安卓系统上测试成功。
1)windows平台
windows通过在浏览器配置代理的方式可以实现科学上网。
首先需要安装shadowsocks windows客户端软件，下载地址：
https://github.com/shadowsocks/shadowsocks-windows/releases
配置信息同服务器段配置，其中代理端口为在windows上在浏览器上需要配置的代理端口。谷歌和火狐浏览器均有相应的插件实现代理上网。
由于我使用谷歌浏览器正常上网，使用火狐浏览器翻墙。本文介绍使用火狐浏览器配置代理翻墙。
在火狐浏览器的附加组件中搜索autoproxy并安装插件，插件会在右上角显示一个“福”字按钮，在“福”字上点击鼠标右键，选择首选项->代理服务器->编辑代理服务器，填写代理主机IP以及端口号，启动服务器即可实现科学上网。
2)ubuntu
ubuntu同样可以通过在浏览器配置代理的方式科学上网。
安装和服务器端安装方式一致。
```
sudo apt-get install python-pip
sudo pip install shadowsocks
```
通过json格式字符串保存配置信息。配置完成后通过以下命令即可启动服务器端程序，可以添加到"/etc/rc.local"开机启动服务。

```
sslocal -c /etc/shadowclient.json
```
ubuntu火狐浏览器的配置方法和windows端火狐配置类似。
3)安卓手机
安卓手机的影梭下载地址为：
https://github.com/shadowsocks/shadowsocks-android/releases
安卓手机的配置方法更为简单。
配置使用服务器端的配置即可，需要主机的是影梭实现的是全局翻墙，及开启影梭功能后手机软件都通过shadowsocks翻墙后上网。
配置及上网截图如下：
### 四、博客搭建
1.网络环境搭建
由于设备内存较小，所以我选择LNMPi(Linux+Nginx+MySQL+Php)搭建web服务器。
网络上有较多关于LNMP搭建的方法，还有一键安装的脚本，本处略过(见参考文献)。
2.博客安装
博客使用开元项目WordPress，可用于搭建功能强大的网络信息发布平台以及个性化的博客。wordpress内置许多主题，可以根据自己的喜好选择，网上也有很多收费的主题可供选择。
(1)创建数据库
WordPress需要在MySQL创建用户：
```
mysql -u root -p 
CREATE DATABASE wordpress; 
CREATE USER wordpresuser@localhost IDENTIFIED BY 'password'; 
GRANT ALL PRIVILEGES ON wordpress.* TO wordpressuser@localhost; 
FLUSH PRIVELEGES; 
exit
```
(2)下载WordPress
下载地址：https://wordpress.org/latest.tar.gz
```
wget https://wordpress.org/latest.tar.gz
tar zxvf latest.tar.gz
cd wordpress
```
(3)配置WordPress
首先备份配置，然后编辑wp-config.php，具体内容为配置数据库的名字，更改创建的用户名和密码。
```
cd wordpress 
cp wp-config-sample.php wp-config.php
vi wp-config.php
define('DB_NAME', 'wordpress'); /** wordpress数据库名*/ 
define('DB_USER', 'wordpressuser'); /** MySQL中wordpress的用户名*/ 
define('DB_PASSWORD', 'password'); /** MySQL中wordpress的密码*/ 
```
配置完成后将"wordpress"目录里面的内容复制到"/var/www/html"。
(4)配置nginx
修改"/etc/nginx/sites-available/default"文件，配置前先做备份。修改内容为指定网站index页面和工作目录，文件对比如下。
```
--- default     2017-07-12 06:59:06.015478017 -0400
+++ default_bak 2017-07-12 06:23:19.995478017 -0400
@@ -21,10 +21,8 @@
        listen 80 default_server;
        listen [::]:80 default_server ipv6only=on;
-       #root /usr/share/nginx/html;
-       #root /var/www;
-       root /var/www/html;
-       index index.php index.html index.htm;
+       root /usr/share/nginx/html;
+       index index.html index.htm;
```
重启nginx和PHP服务即可进入wordpress图形化配置界面，按照向导简单配置即可。
```
service nginx restart 
service php5-fpm restart
```
3.域名
服务器放在国外有个好处就是不用进行备案。为博客添加域名可以更方便的进行访问，我使用阿里云域名服务，1元可以使用".top"的域名一年。
购买成功后只需要将域名指向固定的网址即可，当然自己搭建的博客也基本上不会被搜索引擎收录，以尝试的心态搭建还是不错的。
我的域名是“lmyforfun.top”，效果如下：
### 五、小结
本文只是大体的介绍了租赁一个国外的VPS，实现科学上网以及搭建博客的方法，细节描述较少，详情见考参考文献。当然VPS可以做更多的事情，感兴趣可以多研究。
### 六、参考文献 ```
老左常用国内/国外VPS推荐
http://www.laozuo.org/myvps
Ubuntu下ss的安装与使用
http://www.cnblogs.com/Dumblidor/p/5450248.html
Ubuntu 16.04LTS LNMP环境配置
http://www.cnblogs.com/ddling/p/5906109.html
Ubuntu 14.04基于Nginx安装WordPress
http://www.linuxidc.com/Linux/2016-01/127840.htm
```
