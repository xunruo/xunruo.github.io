# Nmap-使用基础


nmap使用基础

<!--more-->


## 常见用法与参数

Nmap默认发送ARP的ping数据包，检测常用端口开放

```bash
nmap 192.168.244.160
```

<img src="https://npm.elemecdn.com/xrhugo@1.0.5/public/img/image-20230327214404178.png" alt="image-20230327214404178" style="zoom:80%;" description="nihao" />

快速扫描多个IP地址目标

```bash
nmap 192.168.244.160 192.168.244.1
```

<img src="https://npm.elemecdn.com/xrhugo@1.0.5/public/img/image-20230327214600527.png" alt="image-20230327214600527" style="zoom:80%;" />

简单扫描，并对返回的结果详细描述输出

```bash
nmap -vv 192.168.244.160
```

<img src="https://npm.elemecdn.com/xrhugo@1.0.5/public/img/image-20230327215224914.png" alt="image-20230327215224914" style="zoom:80%;" />

指定端口和范围扫描

Nmap默认扫描常用端口号，使用-p参数设定扫描的端口范围

```bash
nmap -p 端口范围 目标主机IP
nmap -p 80-443 192.168.244.160
```

<img src="https://npm.elemecdn.com/xrhugo@1.0.5/public/img/image-20230327215626646.png" alt="image-20230327215626646" style="zoom:80%;" />

### 网段扫描格式

```bash
nmap -sP <network address > </CIDR >  
```

```bash
10.1.1.0/8   =  10.1.1.1-10.255.255.255   # a段扫描
10.1.1.0/16  =  10.1.1.1-10.1.255.255     # b段扫描
10.1.1.0/24  =  10.1.1.1-10.1.1.255       # c段扫描
```

### 从文件中读取需要扫描的 IP 列表

```bash
nmap -iL ip-address.txt
```



### 扫描除过某一个 ip 外的所有子网主机

```bash
nmap 192.168.244.1/24 -exclude 192.168.244.1
```

### 扫描除过某一个文件中的 ip 外的子网主机

```bash
nmap 192.168.244.1/24 -exclude robots.txt
```

### 显示扫描的所有主机的列表

```bash
nmap -sL 192.168.244.1/24
```

### -sP 

ping扫描：类似与windows/linux中ping扫描方式，常使用该命令去扫描一个内网范围来进行主机发现

```bash
nmap -sP 192.168.244.1-255/nmap -sP 192.168.244.1/24
```

<img src="https://npm.elemecdn.com/xrhugo@1.0.5/public/img/image-20230327220442785.png" alt="image-20230327220442785" style="zoom:80%;" />

### -sS 

SYN 半开放扫描

```
nmap -sS 192.168.244.160
SYN扫描,又称为半开放扫描，它不打开一个完全的TCP连接，执行得很快，效率高
优点：Nmap发送SYN包到远程主机，但是它不会产生任何会话，目标主机几乎不会把连接记入系统日志。
（防止对方判断为扫描攻击），扫描速度快，效率高，在工作中使用频率最高
缺点：需要root权限
```

<img src="https://npm.elemecdn.com/xrhugo@1.0.5/public/img/image-20230327220915658.png" alt="image-20230327220915658" style="zoom:80%;" />

### -sT 

TCP 扫描

```
nmap -sT 192.168.244.160 等同于 192.168.244.160
```

```
Tcp connect() scan (sT)和上面的Tcp SYN 对应，TCP connect()扫描就是默认的扫描模式.
不同于Tcp SYN扫描,Tcp connect()扫描需要完成三次握手,并且要求调用系统的connect().
扫描技术只适用于找出 TCP 和 UDP 端口。
优点：不需要root权限
缺点：这种扫描很容易被检测到，在目标主机的日志中会记录大批的连接请求以及错误信息，
由于它要完成3次握手，效率低，速度慢
```

### -sU

UDP 扫描

```bash
nmap -sU 192.168.244.160
```

```
这种扫描技术用来寻找目标主机打开的 UDP 端口，它不需要发送任何的 SYN 包，因为这种技术是针对 UDP 端口的。
UDP 扫描发送 UDP 数据包到目标主机，并等待响应。如果返回 ICMP 不可达的错误消息，说明端口是关闭的，如果
得到正确的适当的回应，说明端口是开放的。
缺点：扫描速度较慢
```

### -sF

 FIN 标志的数据包扫描

```bash
namp -sF 192.168.224.160
```

```
有时候TcpSYN扫描不是最佳的扫描模式,因为有防火墙的存在.目标主机有时候可能有IDS和IPS系统的存在,防火墙会阻止
掉SYN数据包。发送一个设置了FIN标志的数据包并不需要完成TCP的握手.和sS扫描效果差不多，比sT速度快
```

### -sV 

Version 版本检测扫描

```bash
nmap -sV 192.168.244.160
```

```
版本检测是用来扫描目标主机和端口上运行的软件的版本,使用版本检测扫描之前需要先用 TCP SYN 扫描开放了哪些端口
扫描速度较慢
```

### -O 

OS 操作系统类型的探测

```bash
nmap -O 192.168.244.160
```

```
远程检测操作系统和软件，Nmap 的 OS 检测技术在渗透测试中用来了解远程主机的操作系统和软件是非常有用的，
通过获取的信息你可以知道已知的漏洞。Nmap 有一个名为的 nmap-OS-DB 数据库，该数据库包含超过 2600 种
操作系统的信息。Nmap 把 TCP 和 UDP 数据包发送到目标机器上，然后检查结果和数据库对照。
```

### --osscan-guess 

猜测匹配操作系统

```bash
nmap -O --osscan-guess 192.168.244.160
```

```
通过 Nmap 准确的检测到远程操作系统是比较困难的，需要使用到 Nmap 的猜测功能选项，–osscan-guess 猜测认为最接近目标的匹配操作系统类型。
```

### -PN 

No ping 扫描

```bash
nmap -O -PN 192.168.244.160
```

```
如果远程主机有防火墙，IDS 和 IPS 系统，你可以使用 -PN 命令来确保不 ping 远程主机，因为有时候防火墙会组织掉 ping 请求。-PN 命令告诉 Nmap 不用 ping 远程主机。有时候使用 -PN 参数可以绕过 PING 命令，但是不影响主机的系统的发现。
```

### -T 

设置时间模板

```bash
nmap -sS -T<0-5> 192.168.168.160
```

优化时间控制选项的功能很强大也很有效，但有些用户会被迷惑。此外， 往往选择合适参数的时间超过了所需优化的扫描时间。因此，Nmap 提供了一些简单的 方法，使用 6 个时间模板，使用时采用 - T 选项及数字 (0 - 5) 或名称。模板名称有 `paranoid (0)、sneaky (1)、polite (2)、normal(3)、 aggressive (4)和insane (5)`

- paranoid、sneaky 模式用于 IDS 躲避
- Polite 模式降低了扫描 速度以使用更少的带宽和目标主机资源。
- Normal 为默认模式，因此 - T3 实际上是未做任何优化。
- Aggressive 模式假设用户具有合适及可靠的网络从而加速扫描.
- nsane 模式假设用户具有特别快的网络或者愿意为获得速度而牺牲准确性。

### -traceroute

路由跟踪扫描：通过路由器追踪查处从我们电脑所在地到目标地之间所经常的网络节点，并可以看到通过各个节点所花费的时间。

```bash
nmap -traceroute www.baidu.com
```

### -A

综合扫描：包括系统探测，版本探测，脚本扫描，路由跟踪，速度很慢

```bash
nmap -A 192.168.244.160
```

多参数混合

```bash
nmap -vv -p 1-100,3306,3389 -O -traceroute 192.168.244.160
```

<img src="https://npm.elemecdn.com/xrhugo@1.0.5/public/img/image-20230328135045026.png" alt="image-20230328135045026" style="zoom: 50%;" />

Nmap输出格式

```bash
nmap -O -PN 192.168.244.160 -oN 1.txt #标准输出
nmap -O -PN 192.168.244.160 -oX 1.xml #xml格式输出
nmap -O -PN 192.168.244.160 -oG 2.txt #grep格式输出
```

Nmap脚本使用

```bash
nmap --script 类别
```

Nmap脚本分类

```code
- auth: 负责处理鉴权证书（绕开鉴权）的脚本  
- broadcast: 在局域网内探查更多服务开启状况，如dhcp/dns/sqlserver等服务  
- brute: 提供暴力破解方式，针对常见的应用如http/snmp等  
- default: 使用-sC或-A选项扫描时候默认的脚本，提供基本脚本扫描能力  
- discovery: 对网络进行更多的信息，如SMB枚举、SNMP查询等  
- dos: 用于进行拒绝服务攻击  
- exploit: 利用已知的漏洞入侵系统  
- external: 利用第三方的数据库或资源，例如进行whois解析  
- fuzzer: 模糊测试的脚本，发送异常的包到目标机，探测出潜在漏洞
- intrusive: 入侵性的脚本，此类脚本可能引发对方的IDS/IPS的记录或屏蔽
- malware: 探测目标机是否感染了病毒、开启了后门等信息  
- safe: 此类与intrusive相反，属于安全性脚本  
- version: 负责增强服务与版本扫描（Version Detection）功能的脚本  
- vuln: 负责检查目标机是否有常见的漏洞（Vulnerability），如是否有MS08_067
```

使用具体脚本进行扫描

```none
nmap --script 具体的脚本 www.baidu.com
```

常用脚本案例：

1、扫描服务器常见漏洞

```bash
nmap --script vuln <target>
```

2、检查FTP是否开启匿名登录

```bash
nmap --script ftp-anon <target>
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 1170     924            31 Mar 28  2001 .banner
| d--x--x--x   2 root     root         1024 Jan 14  2002 bin
| d--x--x--x   2 root     root         1024 Aug 10  1999 etc
| drwxr-srwt   2 1170     924          2048 Jul 19 18:48 incoming [NSE: writeable]
| d--x--x--x   2 root     root         1024 Jan 14  2002 lib
| drwxr-sr-x   2 1170     924          1024 Aug  5  2004 pub
|_Only 6 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
```

3、对mysql进行暴力破解

<img src="https://npm.elemecdn.com/xrhugo@1.0.6/public/img/image-20230328142953127-1679988225064-1.png" alt="image-20230328142953127" style="zoom: 67%;" />

## 参数速查

Nmap 支持主机名，网段的表示方式
例如:`blah.highon.coffee, namp.org/24, 192.168.0.1;10.0.0-25.1-254`

```
VERILOG-iL filename				从文件中读取待检测的目标,文件中的表示方法支持机名,ip,网段
-iR hostnum                     随机选取,进行扫描.如果-iR指定为0,则是无休止的扫描
--exclude host1[, host2]        从扫描任务中需要排除的主机           
--exculdefile exclude_file      排除文件中的IP,格式和-iL指定扫描文件的格式相同
```

### 主机发现

```
VERILOG-sL				仅仅是显示,扫描的IP数目,不会进行任何扫描
-sn                     ping扫描,即主机发现
-Pn                     不检测主机存活
-PS/PA/PU/PY[portlist]  TCP SYN Ping/TCP ACK Ping/UDP Ping发现
-PE/PP/PM               使用ICMP echo, timestamp and netmask 请求包发现主机
-PO[prococol list]      使用IP协议包探测对方主机是否开启   
-n/-R                   不对IP进行域名反向解析/为所有的IP都进行域名的反响解析
```

### 扫描技巧

```
VERILOG-sS/sT/sA/sW/sM			TCP SYN/TCP connect()/ACK/TCP窗口扫描/TCP Maimon扫描
-sU                             UDP扫描
-sN/sF/sX                       TCP Null，FIN，and Xmas扫描
--scanflags                     自定义TCP包中的flags
-sI zombie host[:probeport]     Idlescan
-sY/sZ                          SCTP INIT/COOKIE-ECHO 扫描
-sO                             使用IP protocol 扫描确定目标机支持的协议类型
-b “FTP relay host”             使用FTP bounce scan
```

### 指定端口和扫描顺序

```
VERILOG-p				特定的端口 -p80,443 或者 -p1-65535
-p U:PORT               扫描udp的某个端口, -p U:53
-F                      快速扫描模式,比默认的扫描端口还少
-r                      不随机扫描端口,默认是随机扫描的
--top-ports "number"    扫描开放概率最高的number个端口,出现的概率需要参考nmap-services文件,ubuntu中该文件位于/usr/share/nmap.nmap默认扫前1000个
--port-ratio "ratio"    扫描指定频率以上的端口
```

### 服务版本识别

```
VERILOG-sV						开放版本探测,可以直接使用-A同时打开操作系统探测和版本探测
--version-intensity "level"     设置版本扫描强度,强度水平说明了应该使用哪些探测报文。数值越高，服务越有可能被正确识别。默认是7
--version-light                 打开轻量级模式,为--version-intensity 2的别名
--version-all                   尝试所有探测,为--version-intensity 9的别名
--version-trace                 显示出详细的版本侦测过程信息
```

### 脚本扫描

```
VERILOG-sC						根据端口识别的服务,调用默认脚本
--script=”Lua scripts”          调用的脚本名
--script-args=n1=v1,[n2=v2]     调用的脚本传递的参数
--script-args-file=filename     使用文本传递参数
--script-trace                  显示所有发送和接收到的数据
--script-updatedb               更新脚本的数据库
--script-help=”Lua script”      显示指定脚本的帮助
```

### OS 识别

```
VERILOG-O			启用操作系统检测,-A来同时启用操作系统检测和版本检测
--osscan-limit		针对指定的目标进行操作系统检测(至少需确知该主机分别有一个open和closed的端口)
--osscan-guess		推测操作系统检测结果,当Nmap无法确定所检测的操作系统时，会尽可能地提供最相近的匹配，Nmap默认进行这种匹配
```

### 防火墙 / IDS 躲避和哄骗

```
VERILOG-f; --mtu value			指定使用分片、指定数据包的MTU.
-D decoy1,decoy2,ME             使用诱饵隐蔽扫描
-S IP-ADDRESS                   源地址欺骗
-e interface                    使用指定的接口
-g/ --source-port PROTNUM       使用指定源端口  
--proxies url1,[url2],...       使用HTTP或者SOCKS4的代理

--data-length NUM               填充随机数据让数据包长度达到NUM
--ip-options OPTIONS            使用指定的IP选项来发送数据包
--ttl VALUE                     设置IP time-to-live域
--spoof-mac ADDR/PREFIX/VEBDOR  MAC地址伪装
--badsum                        使用错误的checksum来发送数据包
```

### Nmap 输出

```
VERILOG-oN				将标准输出直接写入指定的文件
-oX                     输出xml文件
-oS                     将所有的输出都改为大写
-oG                     输出便于通过bash或者perl处理的格式,非xml
-oA BASENAME            可将扫描结果以标准格式、XML格式和Grep格式一次性输出
-v                      提高输出信息的详细度
-d level                设置debug级别,最高是9
--reason                显示端口处于带确认状态的原因
--open                  只输出端口状态为open的端口
--packet-trace          显示所有发送或者接收到的数据包
--iflist                显示路由信息和接口,便于调试
--log-errors            把日志等级为errors/warings的日志输出
--append-output         追加到指定的文件
--resume FILENAME       恢复已停止的扫描
--stylesheet PATH/URL   设置XSL样式表，转换XML输出
--webxml                从namp.org得到XML的样式
--no-sytlesheet         忽略XML声明的XSL样式表
```

### 其他 Nmap 选项

```
VERILOG-6				开启IPv6
-A                      OS识别,版本探测,脚本扫描和traceroute
--datedir DIRNAME       说明用户Nmap数据文件位置
--send-eth / --send-ip  使用原以太网帧发送/在原IP层发送
--privileged            假定用户具有全部权限
--unprovoleged          假定用户不具有全部权限,创建原始套接字需要root权限
-V                      打印版本信息
-h                      输出帮助
```

## 常见端口对应服务

|              服务              | 端口 |                             说明                             |
| :----------------------------: | :--: | :----------------------------------------------------------: |
|              FTP               |  20  |         FTP服务器真正传输所用的端口，用于上传、下载          |
|              FTP               |  21  |                      用于FTP的登陆认证                       |
|           SSH、SFTP            |  22  |                   加密的远程登录，文件传输                   |
|             Telnet             |  23  | 远程登录（在本地主机上使用此端口与远程服务器的22/3389端口连接） |
|              SMTP              |  25  |                         用于发送邮件                         |
|              HTTP              |  80  |                         用于网页浏览                         |
|              POP3              | 110  |                   SUN公司的RPC服务所有端口                   |
| Network News Transfer Protocol | 119  |              NEWS新闻组传输协议，承载USENET通信              |
|              SMTP              | 161  |     Simple Network Management Protocol，简单网络管理协议     |
|           SNMP Trap            | 162  |                           SNMP陷阱                           |
|             HTTPS              | 443  |                      加密的网页浏览端口                      |
|              CIFS              | 445  |                     公共Internet文件系统                     |
|           sql server           | 1433 |             Microsoft的SQL服务开放的端口 数据库              |
|             Oracle             | 1521 |                            数据库                            |
|              NFS               | 2049 |      通过网络，让不同的机器、不同的操作系统实现文件共享      |
|             MySQL              | 3306 |                            数据库                            |
|        WIN2003远程登录         | 3389 | Windows 2000(2003) Server远程桌面的服务端口，本地服务器开放此端口，去连接到远程的服务器 |
|               QQ               | 4000 |                    腾讯QQ客户端开放此端口                    |
|            WebLogic            | 7001 | 一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器 |
|            Wingate             | 8010 |                    Wingate代理开放此端口                     |
|             TOMCAT             | 8080 |                      WWW代理开放此端口                       |


参考文章：
{{< link "https://www.sqlsec.com/2017/07/nmap.html" "Nmap 不老的神器" "" false >}}

---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/543fca94/  

