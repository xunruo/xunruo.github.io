# 内网权限解读




## 0x1 工作组权限

### 本地工作组

本地工作组的电脑，所有的账号密码，群组都存放再本地的电脑文件中，不管电脑有没有网络，只要能开机，我们输入的本地的账号密码都能登录到电脑上

在电脑中一般有两种角色，一个是用户一个是组，一个组中可以有多个用户，一个用户可以属于多个组，通过给组划分不同的权限，用户就有了不同的权限

<img src="https://s1.vika.cn/space/2023/07/27/18a69aa66a864e12a812bd15d11549f0" alt="image-20230727230958332" />

### 本地最高管理员权限

Administrator在计算机中的的意思就是系统超级管理员或超级用户

1、Administrator用户在家庭版的电脑中是属于禁用状态(添加的用户为本地普通管理员)，在专业版中默认属于开启状态，在server机器中属于开启

2、Administrator用户的SID最后一位是500结尾

3、Administrator用户默认在administrators组中

<img src="https://s1.vika.cn/space/2023/07/27/c8d5093b63064626b376caf7e8149502" alt="image-20230727231522414" />

### 本地普通管理员权限

本地一般管理员就是加入了administrators组的管理员但不是administrator用户(job)

<img src="https://s1.vika.cn/space/2023/07/27/141a7c13d9ed4ea988f29c05030bc029" alt="image-20230727232251428" />

下面演示一下，最高管理员与普通管理员的区别(添加新用户)

<img src="https://s1.vika.cn/space/2023/07/27/c7d2640bc64c46ec9ecc0e54cc976043" alt="image-20230727232556195" />

切换用户到普通管理员job

<img src="https://s1.vika.cn/space/2023/07/27/4d37ed431e2346ba9b96620f60ae90b4" alt="image-20230727232829755" />

发生系统错误拒绝访问，有些操作执行不了，因为有UAC的存在，执行高权限的操作必须右键使用管理员打开

<img src="https://s1.vika.cn/space/2023/07/27/cd559762f8c64e9ebaeb25078044b170" alt="123" />

### 本地普通用户

本地普通用户，就是在windows电脑中本地新建的普通用户。没有管理员的权限，一般很多操作搜执行不了，需要管理员认证才可以指向，以下是windows用户组，新建的用户一般是默认是user组

<img src="https://s1.vika.cn/space/2023/07/27/bbe13500c8024c459acbbf24298dea37" alt="image-20230727233717623" />

当进行高权限的操作时候会出现以下认证(需要输入管理员的账号和密码才可以)

<img src="https://s1.vika.cn/space/2023/07/27/902ab0528d7249ad8b189183eaf537c3" alt="image-20230727233839810" />

### UAC认证

UAC (User Account Control)，中文翻译为用户帐户控制，是微软在Windows Vista和Windows7中引用 的
新技术，主要功能是进行一些会影响系统安全的操作时，会自动触发UAC，用户确认后才能执行。因为大部分的恶意软件、木马病毒、广告插件在进入计算机时都会有如:将文件复制到Windows或Program Files等目录、安装驱动、安装ActiveX等操作，而这些操作都会触发UAC,用户都可以在UAC提示时来禁止这些程序的运行
许可提示(普通管理员操作)当用户尝试执行需要用户管理访问令牌的任务时，会显示同意提示。下面是UAC同意提示的示例

<img src="https://s1.vika.cn/space/2023/07/27/9575d66f06e3448d8cb745609a83d6eb" alt="image-20230727235059498" />

凭据提示当标准用户(普通用户)尝试执行需要用户管理访问令牌的任务时，会显示凭据提示，还可以要求管理员提供其凭据

<img src="https://s1.vika.cn/space/2023/07/27/902ab0528d7249ad8b189183eaf537c3" alt="image-20230727233839810" />

#### UAC的触发条件:

1.修改Windows Update配置;
2.增加或删除用户帐户;
3.改变用户的帐户类型;
4.改变UAC设置;
5.安装ActiveX;
6.安装或卸载程序;
7.安装设备驱动程序;
8.修改和设置家长控制;
9.增加或修改注册表;
10.将文件移动或复制到Program Files或是Windows目录; 
11.访问其他用户目录

#### UAC四种设置要求

UAC设置分为四种，分为始终通知、仅在成俗尝试对我计算机进行更改时通知我、仅当承租尝试更改计算机时通知我(不降低桌面亮度)和从不通知。输入Win+R-->msconfig设置UAC(`必须用管理员账号来设置`)

<img src="https://s1.vika.cn/space/2023/07/27/7d91217d7b69430b83618499ddb48dca" alt="image-20230728000139921" />

<img src="https://s1.vika.cn/space/2023/07/27/f3a5c4671050406ababd52c0424f2fcd" alt="image-20230728000200714" />

`默认都为第二档位`

<img src="https://s1.vika.cn/space/2023/07/27/c1862677e9244cc7b52ef8011d51e764" alt="image-20230728000230250" />

我们将它设置为从不通知，我们切换账号到普通管理员(job),再次使用管理员身份打开，许可提示消失

<img src="https://s1.vika.cn/space/2023/07/27/58817713dff34ca09cf95780ead49df6" alt="关闭提示" />

再次切换用户到普通用户xun，发现依然需要提供凭证

<img src="https://s1.vika.cn/space/2023/07/27/f67de178b798498494b0ed110306439b" alt="66" />

这里证明只是提示不出现了，但是UAC认证仍然存在

### 本地系统最高权限(system)

system的中文意思是系统，在windows中主要作为系统服务或进程的运行账户

<img src="https://s1.vika.cn/space/2023/07/27/342174fd5669428ebaaf999ea837d47a" alt="image-20230728002737459" />

#### Administrator和system权限区别

并不是说System比Administrator权限大，这两个用户的区别是Administrator是系统内置的管理员用户,一般平时安装、运行程序、修改系统设置等都是以这个权限身份运行的
System权限是系统本身的权限，比如任务管理器里面的winlogon.exe、svchost.exe、alg.exe这些进程等等，另外，注册表里面某些地方只有系统自己可以访问，Administrator用户 也不能访问

充当不同的角色，不能完全去区别谁的权限大

## 0x2 域内机器权限

### 域内用户权限解读

机器加入到域中，使用域内用户进行登录，域内账户的信息存放在域控(DC)上，添加用户或者修改密码等操作都在域控上进行

<img src="https://s1.vika.cn/space/2023/07/28/4608fca21c684717b14028cc711648b4" alt="image-20230728094222190" />

### 管理员组(Administrators)

成员可以不受限制地存取计算机/域的资源。它不仅是最具有权力的一个组，也是在活动目录和域控制器中默认具有管理员权限的组。该组成员可以更改Enterprise Admins、Domian admins 组成员关系，是域森林中强大的服务管理组，`从工作组升级成域控后Administrators增加了两个用户组，Enterprise Admins、Domian admins`

<img src="https://s1.vika.cn/space/2023/07/28/0a29433866bb46cab634fdc689634221" alt="image-20230728095908967" />

### 域管理员组(Domain Admins)

指定的域管理员(域控的本地管理员)，拥有完整的管理员权限。因为该组会被添加到所在域的Administrators组中，因此可以继承Administrator组的所有权限。同时该组默认会被添加到每台域成员计算机的本地Administrators组中，因此Domain admins组获得了域中所有计算机的所有权。`下图是域内主机win-08，这样相当于Domain Admins组中成员默认为域内主机的普通管理员`

<img src="https://s1.vika.cn/space/2023/07/28/c2d5296c1ec74f519f7e9958ea0b1bd0" alt="image-20230728100518821" />

domain Admins中默认会有一个Administrator用户

<img src="https://s1.vika.cn/space/2023/07/28/5a49439700994cadb3937647d1ee0332" alt="image-20230728100801855" />

综上所述，当我们要加一个域管理员用户时，要在域控Domain Admins中添加用户，这样每台域内中上都能用该管理员用户登录使用

### 企业系统管理员组(Enterprise Admins)

域森林或者根域中的一个组。该组在域森林的每个域中都是Administrators组的成员，因此对所有域控制器都有完全访问权限

<img src="https://s1.vika.cn/space/2023/07/28/7c8343a8bd7241ec9d2411b12a5c4745" alt="image-20230728101955190" />

如果只是添加域控管理员，可以将用户添加到Enterprise Admins即可

### 域用户组(Domain users)

所有的域成员。在默认情况下，任何由我们建立的用户账号都属于Domain Users组，该组在域内机器中存在Users组

<img src="https://s1.vika.cn/space/2023/07/28/34ef51d0c7684af9aea92bd71b3ce672" alt="image-20230728103608344" />

这里可以看到我们添加的liu用户也默认在该组中，在域控默认添加用户都在Domain users组，Domain Users组，该组在域内机器中存在Users组，这样用户可以当作普通用户登录域内主机

<img src="https://s1.vika.cn/space/2023/07/28/1cb93550b28842b4814a211d903cfa4b" alt="image-20230728103814226" />

Domain Computers组，任何由我们建立的计算机账号都属于该组(加入域中的主机都在这里)

<img src="https://s1.vika.cn/space/2023/07/28/f5d6483b1fd94282bdcbfe479cf6dcc7" alt="image-20230728104024949" />

机器加入到域之后可以选择使用域内用户登录，也可以使用本地用户登录，但是有以下区别

1、本地用户登录，是存放在本地文件中然后本机进行校验。域内用户登录，是要通过DC认证之后才能登录，用户信息放在域控上

2、本地用户登录主要对比的是NTLM HASH值，域认证是通过kerberos认证

3、机器可以选择本地登录或者域用户登录，本地用户 机器名\用户名,域内用户 域名\用户名

### 域内最高管理员权限

域内最高管理员权限是：域名\administrator,他没有UAC认证，他也是每个域内机器的本地管理员。和机器名\administrator具有相同权限，SID也是500结尾

<img src="https://s1.vika.cn/space/2023/07/28/4d2be6c6cb774bcca6db51e98475c325" alt="image-20230728182216624" />

### 域内普通管理员

域内普通管理员就是加入域的Domain Admins组，但是不是administrator用户

与本地的普通管理员权限类似，也有UAC的存在

### 域内普通用户权限

域用户组(Domain users)中所有的域用户。在默认情况下，任何由我们建立的用户账号都属于Domain Users组，该组在域内机器上存在于Users组

其权限于本地的普通用户权限相同，执行高操作的时候需要UAC认证

### 机器用户和system的关系

Domain Computers组，任何由我们建立的计算机账号都属于该组,机器账户是指在网络中用于代表计算机或设备的账户。在Windows域环境中，每台计算机都有一个机器账户，用于在网络中进行身份验证和授权。机器账户的名称通常以计算机名称或计算机GUID作为前缀，如"ZS-PC$"。 机器账户与具体计算机相关联，用于代表计算机进行域认证和访问域资源。

<img src="https://s1.vika.cn/space/2023/07/28/eba11c28a3e24be5941a371ee5dbe48b" alt="image-20230728183157327" />

当电脑加入到域中后机器账号的密码或同步到域控上，所以说本地system用户对应域内的机器用户，如果说我们渗透的电脑加了域，但是使用本地用户进行登录，我们就可以提权到system用户，然后对域内进行查询
虽然"System"账户是本地计算机上的特殊账户，而机器账户是域环境中的账户，但在某些情况下，例如当本地计算机需要访问域资源时，"System"账户 可能会充当机器账户的角色。这是因为在域环境中，本地计算机可以使用"System"账户作为其身份进行域认证和访问授权。但需要明确的是，它们仍然是两个不同的概念,"System"账户不是专门为域中的机器账户而创建的。

## 0x3 system查询域内用户实验

实验前提：本地administrator用户密码与域中administrator的密码不能相同，否则是可以查询域内用户的

首先我们使用域内主机的本地administrator用户去查询域内用户 net user /domain

<img src="https://s1.vika.cn/space/2023/07/28/9f85565b9ad24f6398857c671baec137" alt="image-20230728185712554" />

我们可以将提权到system用户来代表机器用户去查询域内用户，因为机器用户，再加入域时被同步到域控上

使用incognito工具实现该实验

列出当前的token令牌列表 incognito.exe list_tokens -u

<img src="https://s1.vika.cn/space/2023/07/28/1d685537b6c046c695c1bc58331a3c6d" alt="666" />

使用system的令牌 incognito.exe execute -c "NT AUTHORITY\SYSTEM" cmd

<img src="https://s1.vika.cn/space/2023/07/28/17f906c14eaa466bb7b385734cecd305" alt="image-20230728190832484" />

whoami可以看到现在是system权限，现在我们再去查询域内用户

<img src="https://s1.vika.cn/space/2023/07/28/b418a86fef5445f2a5ebf9c1174e60b3" alt="image-20230728191022938" />

成功查询到域内用户，实验完成


---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/c8bae9e9/  

