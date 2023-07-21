# sqlmap --os-shell原理


## 网站注入漏洞

### 利用条件

- 知道网站的物理路径
- 高权限数据库用户
- secure_file_priv无限制
- 网站路径有写入权限

### 注入步骤

<img src="https://s1.vika.cn/space/2023/07/06/54f39494174d41dca2d40a9bec7f8dd5" alt="image-20230706093405947" style="zoom: 67%;" />

选择web网站的语言，默认为ASP

<img src="https://s1.vika.cn/space/2023/07/06/6e8f965d49e446f0a26dfaf7ced7f797" alt="image-20230706093528331" style="zoom:67%;" />

选择写入的路径，我们选2，输入写入的路径

> `选项一为用这几个路径`
>
> `选项二为用户自己输入`
>
> `选项三为用用户的字典`
>
> `选项四为爆破。`

<img src="https://s1.vika.cn/space/2023/07/06/9a5a8128d5e64af7968ac13f398a52a5" alt="image-20230706100143026" style="zoom:80%;" />

到这就完成了--os-shell的执行，来看看在sqlmap的执行效果

<img src="https://s1.vika.cn/space/2023/07/06/c1e4952117c448968c89cd6e7feb135e" alt="image-20230706100538467" style="zoom: 67%;" />

综上所述：大致可以分为三个步骤

1、进行目标的一个基础信息的探测。
2、上传shell到目标web网站上。
3、退出时删除shell。

------

下面来具体看一下底层流量的执行过程

wireshark捕获数据包，只查看http数据包，流量包如下图，我们分四部分分析

<img src="https://s1.vika.cn/space/2023/07/21/86436be6961e49abbd62bf12e0339c20" alt="流量特征"  />

**1、sqlmap上传一个上传功能的马**

<img src="https://s1.vika.cn/space/2023/07/21/fae8a60cb08245988ebd1cc0a2957592" alt="image-20230721114110748"  />

可以看出是利用into outfile进行的文件的写入，下面16进制解码看一下文件内容

<img src="https://s1.vika.cn/space/2023/07/21/e8274d84a7844e60902056661ce27500" alt="image-20230721121743062"  />

解码后可以看出是一个文件上传功能的马

**2、通过上传的马进行shell的上传。**

<img src="https://s1.vika.cn/space/2023/07/21/a8eccd6c8b2e41dab2baa8b9e944f0c6" alt="image-20230721122052773" style="zoom:80%;" />

可以看出上传了一个文件名为tmpbbkxxv.php的webshell

**3、shell传参进行命令执行**

![image-20230721122306611](https://s1.vika.cn/space/2023/07/21/1e6e7862445546db9d18b5bbca1b9f42)

使用变量cmd传入whoami命令，返回内容

**4、删除shell**

![image-20230721122546132](https://s1.vika.cn/space/2023/07/21/af684bc0cc244281911bcf60a200827a)

删除tmpuyvln.php文件，接着删除它自身，这里可以注意到马的命名规则，tmpuxxxx.php,tmpbxxxx.php


---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/48daf525/  

