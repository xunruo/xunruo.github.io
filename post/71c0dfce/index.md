# Go入门日记-数据类型

Go2：数据类型初识
<!--more-->
### 一、数据类型分类

Go 语言按类别有以下几种数据类型：布尔型、数字型、字符串型、派生型 

|  整型  |    int8、uint等    |  数字型  |
| :----: | :----------------: | :------: |
| 浮点型 | float32、float64等 |  数字型  |
|  复数  |                    |  数字型  |
| 布尔型 |        bool        |  布尔型  |
| 字符串 |       string       | 字符串型 |
|  数组  |                    |  派生型  |
| 结构体 |       struct       |  派生型  |

引用类型：即保存的是对程序中一个变量的或状态的间接引用，对其修改将影响所有该引用的拷贝

```
指针    *
切片    slice
字典    map
函数    func
管道    chan
接口    interface
```

tip：Go语言没有字符型，可以使用byte来保存单个字母

### 二 、零值机制

Go变量初始化会自带默认值，不像其他语言为空，下面列出各种数据类型对应的0值：

```go
int     0
int8    0
int32   0
int64   0
uint    0x0
rune    0           //rune的实际类型是 int32
byte    0x0         // byte的实际类型是 uint8
float32 0           //长度为 4 byte
float64 0           //长度为 8 byte
bool    false
string  ""
```


---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/71c0dfce/  

