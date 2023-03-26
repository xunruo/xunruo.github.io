# Go入门日记-流程控制

Go3：流程控制
<!--more-->
### 一、条件语句

#### 1.1 **if**判断语句：

```go
if i == 3{
    //如果i等于3输出true
    fmt.Println("true")
}

//将初始化条件与判断语句放在一起
if i := 3;i == 3{
     //如果i等于3输出true
    fmt.Println("true")
}
```

#### 1.2 分支语句 

```go
//Go语言中分支语句中默认书写了break语句
num := 2
switch num {
case 1:
	fmt.Println("111")
case 2:
	fmt.Println("222")
	fallthrough            //fallthrough 不跳出switch
case 3:
	fmt.Println("333")
default:
	fmt.Println("默认")
}
//输出：
222
333
```

### 二、循环语句

#### 2.1 for循环

```go
//传统for循环
for i := 0; i < 10; i++ {
	fmt.Println(i)
}
//for循环简化
var i int
for ; ; i++ {
	if i > 10 {
		break
	}
}
//类似while循环
for i < 10 {
	i++
}
//死循环
for{

}
//for range 遍历数组等
for k, v := range []int{1, 2, 3, 4} {
	fmt.Printf("key:%d  value:%d\n", k, v)
}
//输出：
key:0  value:1
key:1  value:2
key:2  value:3
key:3  value:4
```

#### 2.2 跳出循环

常用的跳出循环关键字：

- `break`用于函数内跳出当前`for`、`switch`、`select`语句的执行

- `continue`用于跳出`for`循环的本次迭代。  

- `goto`可以退出多层循环

- ```go
  goto 标签 
  
  标签：
  ```

  



---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/fd173a46/  

