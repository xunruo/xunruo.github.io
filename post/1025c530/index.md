# Go入门日记-标识符与变量

Go1：语言标识符与变量
<!--more-->
### 1.1关键字

目前Go语言有25个关键字

```go
    break        default      func         interface    select
    case         defer        go           map          struct
    chan         else         goto         package      switch
    const        fallthrough  if           range        type
    continue     for          import       return       var
```

### 1.2保留字

```go
 //内建常量：  
        true        false       iota        nil
 //内建类型：  
        int         int8        int16       int32       int64
        uint        uint8       uint16      uint32      uint64      uintptr
        float32     float64 
        complex128  complex64
 //bool：      
        byte        rune        string 	    error
 //内建函数：   
        make        delete      complex     panic       append      copy    
        close       len         cap	   real        imag        new 
        recover
```

## 二、变量

#### 2.1变量声明

```go
var a int              //初始化变量默认为0
var b = 1              //声明并赋值，自动推导变量类型
c := 2                 //初始化，自动推导类型(只能在函数内部使用，var定义全局变量)
//Go语言中有定义未使用的变量编译会报错
//大小写变量为不同变量
```

#### 2.2多变量声明

```go
var c,d int
var c1,d1 int = 1,2
var c1,d1 = 1,2
c,d := 1,2
var(
    e int
    f byte
)
```

#### 2.3变量值互换

在Go语言中两个变量互换的操作十分简单

```go
var (                //定义初始化变量
	m    int = 1
	n    int = 2
	temp int = 6
)
m,n = n,m           //将m与n的变量值互换
fmt.Println(m, n)   //2 1
```

#### 2.4_丢弃变量

```go
//_丢弃变量任何赋予它的值都会被丢弃，该变量不占用命名空间
_,d := 1,2    //此时d的值为2，1被丢弃掉
```


---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/1025c530/  

