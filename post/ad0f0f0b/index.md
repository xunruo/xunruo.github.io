# Go入门日记-字符串

Go4：字符与字符串
<!--more-->
### 一、字符

```go
//在golang中没有专门的字符类型变量
var c1 byte = 'a'
fmt.Println("c1=", c1)
//字符对应码大于255的字符可以使用int来保存
var c2 int = '成'
fmt.Printf("c2=%c\n", c2)
```

### 二、字符串

**Tips**：Go与传统的字符串不同，Go字符串是一串固定长度的字符连接起来的字符序列，字符串在内容初始化后不能被**修改**，都是采用UTF-8字符集编码。

```go
var str1 string
str1 = "hello"
str2 := "beijing"
//字符串不可直接改变
//str1[0]='c'会报错
fmt.Printf("%c\n", str1[1])
//输出 e
fmt.Println(len(str2))
//输出 7
fmt.Println(str1 + str2)
//输出 hellobeijing
```

修改字符串的间接方式：

1、通过两次转换来修改字符串

```go
str := "successful"
//转换成byte数组类型
strTemp := []byte(str)
fmt.Println("strTemp=", strTemp)
//输出
//strTemp= [115 117 99 99 101 115 115 102 117 108]
//修改数组的的值
strTemp[0] = 'c'
//将数组转换成字符串
strResult := string(strTemp)
fmt.Println("strResult=", strResult)
```

2、使用切片来完成

```go
str3 := "liu"
str3 = "c" + str3[1:]
fmt.Println(str3)
//输出：ciu
```

### 三、字符串操作

#### 3.1 len()、string()函数

```go
str4 := "hello"
str5 := "北京"
//在go语言中中文以utf-8格式保存，每个中文占据三个字节
fmt.Println(len(str4))
//输出 5
fmt.Println(len(str5))
//输出 6
//使用特定函数可以输出真正的字符串长度
fmt.Println(utf8.RuneCountInString(str5))
//输出 2
```

使用len()遍历字符串

```go
str := "你好"
for i,ch := range str {
	fmt.Println(i,ch)
}
//输出
0 20320
3 22909
```

string()函数

```go
num := 108
fmt.Printf("%T \n", string(num))
//输出 string
fmt.Printf("%s \n", string(num))
//输出 l
```

#### 3.2 字符串连接

```go
str1 = "hello"
str2 := "beijing"
fmt.Println(str1 + str2)
//用+号来连接字符串不高效
//我们使用StringBuilder来高效字符串连接
//创建字节缓冲
var stringBuilder strings.Builder

//把字符串写入缓冲
stringBuilder.WriteString(str1)
stringBuilder.WriteString(str2)

//将缓冲以字符串形式输出
fmt.Println(stringBuilder.String())
```

### 四、strings包相关函数

```go
//查找s在字符串str中的索引
//Index(str, s string) int 
str := "hello beijing"
s := "e"
fmt.Println(strings.Index(str, s))
//输出 1

//判断str是否包含s
//Contains(str, s string) bool
fmt.Println(strings.Contains(str, s))
//输出 true

//使用字符串str连接s的各个字符串
//Join(s []string, str string) string
str := "<-->"
s := []string{"O", "O", "O"}
fmt.Println(strings.Join(s, str))
//输出 O<-->O<-->O

//替换字符串str中old字符串为new字符串，n表示替换的次数，小于0全部替换
//Replace(str,old,new string,n int) string
str := "hello"
old := "e"
new := "o"
fmt.Println(strings.Replace(str, old, new, 1))
//输出 hollo

//字符串str按照s分割，返回切片
//Split(str,s string)[]string
str := "php"
s := "h"
fmt.Println(strings.Split(str, s))
//输出 [p p]

// 去除头部、尾部指定的字符串
//Trim(s string, cutset string) string
str := "linux"
s := "l"
fmt.Println(strings.Trim(str, s))
//输出 inux

// 去除空格，返回切片
//Fields(s string) []string
s := "ha ha"
fmt.Println(strings.Fields(s))
//输出 [ha ha]
```

### 五、strconv包的字符串转换

```go
//整型转字符串
num := 100
str := strconv.Itoa(num)
fmt.Printf("type: %T value: %#v\n", str, str)
//输出 type: string value: "100"

//字符串转整型(字符串中如果夹杂这非数字的字符则可能转换失败)
str1 := "110"
str2 := "s100"
num1, err := strconv.Atoi(str1)
if err != nil {
    fmt.Printf("%v 转换失败！", str1)
} else {
    fmt.Printf("type:%T value:%#v\n", num1, num1)
}
num2, err := strconv.Atoi(str2)
if err != nil {
    fmt.Printf("%v 转换失败！", str2)
} else {
    fmt.Printf("type:%T value:%#v\n", num2, num2)
}
//输出 
type:int value:110
s100 转换失败！
```

```go
//Parse 系列函数
//ParseBool字符串转为布尔型
//只能接受 1、0、t、f、T、F、true、false、True、False、TRUE、FALSE其他都返回错误
str1 := "t"
boo1, err := strconv.ParseBool(str1)
if err != nil {
    fmt.Printf("str1: %v\n", err)
} else {
    fmt.Println(boo1)
}
//输出 true

//ParseInt返回字符串表示的整数值(包括正负号)
参数1: s string 数字的字符串形式
参数2: base int 取值(2-36) 
Tips: 如果base为0，根据字符串前置判断，“0x”是16进制，“0”是8进制，否则是10进制
参数3: bitSize int 指定结果必须能无溢出赋值的整数类型，0、8、16、32、64 分别代表
int、int8、int16、int32、int64,限制转化生成int类型的位数,但是返回结果都是int64
可参考链接: https://studygolang.com/topics/12335
str := "-11"
num, err := strconv.ParseInt(str, 10, 0)
if err != nil {
   fmt.Println(err)
} else {
   fmt.Println(num)
}
//输出 -11

//ParseUint函数的功能类似于ParseInt函数,只适用于无符号整数
//不再举例

//ParseFloat 函数用于将一个表示浮点数的字符串转换为 float 类型
//参数说明：
//如果 s 合乎语法规则，函数会返回最为接近 s 表示值的一个浮点数（使用 IEEE754 规范舍入）。
//bitSize 指定了返回值的类型，32 表示 float32，64 表示 float64；
//返回值 err 是 *NumErr 类型的，如果语法有误 err.Error=ErrSyntax，
//如果返回值超出表示范围，返回值 f 为 ±Inf，err.Error= ErrRange。
```

```go
//Format 系列函数
//FormatBool函数可以一个bool类型的值转换为对应的字符串类型
num := true
str := strconv.FormatBool(num)
fmt.Printf("type:%T,value:%v\n ", str, str)
//输出 type:string,value:true

//FormatInt函数将整型数据转成指定类型字符串
//Tips:参数 i 必须是 int64 类型
var num int64 = 16
str := strconv.FormatInt(num, 16)
fmt.Printf("type:%T,value:%v\n ", str, str)
//输出 type:string,value:10

//FormatUint函数与FormatInt函数的功能类似，但是参数 i 必须是无符号的 uint64 类型
//不再举例

//FormatFloat函数用于将浮点数转换为字符串类型
参数1: bitSize 参数f的来源类型（32表示float32、64表示float64）会据此进行舍入
参数2: fmt 表示格式，可以设置为“f”表示 -ddd.dddd、“b”表示 -ddddp±ddd，指数为二进制、
“e”表示 -d.dddde±dd 十进制指数、“E”表示 -d.ddddE±dd 十进制指数、“g”表示指数很大时用“e”格式，
否则“f”格式、“G”表示指数很大时用“E”格式，否则“f”格式。
参数3: prec 控制精度（排除指数部分）：当参数 fmt 为“f”、“e”、“E”时，它表示小数点后的数字个数
当参数 fmt 为“g”、“G”时，它控制总的数字个数。
如果 prec 为 -1，则代表使用最少数量的、但又必需的数字来表示 f。
var num float64 = 3.1415926
str := strconv.FormatFloat(num, 'E', -1, 64)
fmt.Printf("type:%T,value:%v\n ", str, str)
//输出 type:string,value:3.1415926E+00
```

```go
//Append 系列函数
// 声明一个slice
b10 := []byte("int (base 10):")
  
// 将转换为10进制的string，追加到slice中
b10 = strconv.AppendInt(b10, -42, 10)
fmt.Println(string(b10))
b16 := []byte("int (base 16):")
b16 = strconv.AppendInt(b16, -42, 16)
fmt.Println(string(b16))
//输出 
int (base 10):-42
int (base 16):-2a
```



---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/ad0f0f0b/  

