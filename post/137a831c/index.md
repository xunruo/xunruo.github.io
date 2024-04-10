# 预编译就安全了吗？


### Mysql运行过程

在了解什么是预编译之前先了解一下mysql的运行过程，下面这张图是mysql完整的运行过程(在*MySQL8.0*取消了查询缓存)

![](https://s1.vika.cn/space/2024/04/04/1b5f6c371d8d43ceb24aca2da270c9a4)

1. 客户端通过连接器与MySQL服务器建立连接、获取权限、维持和管理连接；
2. 查询缓存，如果开启查询缓存，则先去缓存哈希表查找数据，如果命中缓存，则直接返回数据给客户端；如果没有命中缓存，则继续执行下面逻辑；
3. 解析器通过 词法分析 和 语法分析验证SQL是否合法，并生成相应”语法树“；并通过预处理器进一步检查”语法树“是否合法；
4. 接着，优化器将语法树转化成执行计划。执行计划决定了执行器会选择存储引擎的哪个方法去获取数据。MySQL使用基于成本的优化器，它会尝试预测一个查询使用某种执行计划时的成本，并选择其中成本最小的一个。
5. 执行器负责根据这个执行计划调用存储引擎的API接口来完成整个查询工作。
6. MySQL将结果集增量、逐步返回给客户端，如果开启了查询缓存，MySQL在这个阶段会将结果放到查询缓存中。

#### 总结：

简单总结一下就是：

**一、连接建立；二、查询解析；三、查询优化；四、查询执行；五、连接关闭**

### 什么是预编译

那什么是预编译呢？

绝大多数情况下，某需求某一条 SQL 语句可能会被反复调用执行，或者每次执行的时候只有个别的值不同（比如 select 的 where 子句值不同，update 的 set 子句值不同，insert 的 values 值不同）。如果每次都需要经过上面的词法语义解析、语句优化、制定执行计划等，则效率就明显不行了。

所谓预编译语句就是将此类 SQL 语句中的值用占位符替代，可以视为将SQL语句模板化或者说参数化，一般称这类语句叫Prepared Statements。

预编译语句的优势在于归纳为：一次编译、多次运行，省去了解析优化等过程；此外预编译语句能防止 SQL 注入(能防止SQL注入的本质就是参数化，输入的参数被当作字符串，不会改变SQL的原有语义，从而防止SQL注入)

### 预编译的实际使用

下面看一个常见的案例java+mybatis，首先区分一下#{}与${}的区别，#{}是使用预编译，${}就是单纯的字符串拼接，先使用#{}。

这个是mybatis的xml文件,包含了一个select查询语句

```xml
<select id = "queryUserByID" resultMap="UserInfoMap">
    select * from user where id=#{id}
</select>
```

下面是Controller层，我们取url/queryUserByID/后面的id绑定作为参数

```java
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/queryUserByID/{id}")
    public List<User> queryUserByID(@PathVariable String id){
        return userService.queryUserByID(id);
    }
}
```

访问的URL：`http://127.0.0.1:8080/web/queryUserByID/-1%20union%20select%20*%20from%20user`,id就是-1 union select * from user

如果存在sql注入那么现在应该返回所有用户，实际的请求结果如下：

![image-20240410170220125](https://s1.vika.cn/space/2024/04/10/f15bf1ee0e6b4b459e2ab285041adacc)

![image-20240410170410944](https://s1.vika.cn/space/2024/04/10/4b35c355111b4b07a8eacd19702bd388)

上图是mysql的查询日志，我们看到它使用了？来占位，将-1 union select * from user作为参数传入形成select * from user where id='-1 union select * from user'这段语句，参数被作为字符串所以不影响原有SQL语句的语义，等同于select * from user where id='-1'

下面将#{id}改成${id}再次测试，结果返回了所有数据，这次形成的sql语句：select * from user where id=-1 union select * from user，就是单纯的字符串拼接，存在SQL注入风险

![image-20240410170531079](https://s1.vika.cn/space/2024/04/10/fe3f5e3c2d46471ab19c241385cd5fe8)

那么是不是我们把所有的${}都替换成#{}就行了，那当然不是因为有很多地方不能被参数化，比如说 order by 后的字段名，下面我们实际测试一下：

给字段id加上单引号也就是参数化后，显然这条SQL语句并没有达到我们想要的结果，如果在这里用#{}那么这条sql就不能达到目的。

![image-20240410171752953](https://s1.vika.cn/space/2024/04/10/7039fd6d319047debee473e66317a6fc)

就是因为这样的原因很多开发者在数据排序处就会疏漏出现SQL注入漏洞，下面详细举一个例子就出现了虽然使用了预编译但是还是产生了SQL注入 

```xml
<select id = "queryUserByID" resultMap="UserInfoMap">
	select * from user where id >= #{id} order by ${columnName} desc limit 2
</select>
```

在这里可以利用报错或者布尔完成注入，下面以报错注入为例子

```txt
http://127.0.0.1:8080/web/queryUserByID/42&
updatexml(1,concat(0x7e,database(),0x7e,user(),0x7e,@@datadir),1)
```

![image-20240410190209595](https://s1.vika.cn/space/2024/04/10/54f7e395c28e480681d25dd599f12cbe)

那么怎么能解决这个问题呢，很简单就是设置order by 后面字段白名单

```xml
    <select id = "queryUserByID" resultMap="UserInfoMap">
        select * from user where id >= #{id}
        <choose>
            <when test="columnName == 'username' or columnName == 'password' or columnName == 'uuid'">
                order by ${columnName} desc limit 2
            </when>
            <otherwise>
                order by id desc limit 2
            </otherwise>
        </choose>

    </select>
```



---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/137a831c/  

