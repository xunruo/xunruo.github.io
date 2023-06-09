# Go入门日记-数组

Go5：数组与多维数组
<!--more-->
### 一 、数组

#### 1.1 数组的声明

数组是具有相同唯一类型的一组已编号且长度固定的数据项序列，这种类型可以是任意的原始类型

```go
var arr1 [6]int                    //定义长度为6的整型数组，未初始化默认为0
//输出 [0 0 0 0 0 0]
var arr2 = [...]int{1,2,3,4,5}     //自动推导长度并初始化
//输出 [1 2 3 4 5]
arr3 := [6]int{1,2,3,4,5,6}        //定义并初始化
//输出 [1 2 3 4 5 6]
arr3 := [...]int{2,3,4}            //自动推导长度并初始化
//输出 [2 3 4]
arr4 := [6]int{1,2}                //指定固定长度，前几位被初始化，其他使用零值
// [1 2 0 0 0 0]
arr5 := [6]int{1:9, 5:18}          //将索引为 1 和 5 的元素初始化
//输出 [0 9 0 0 0 18]
```

#### 1.2 数组常见操作

```go
arr := [6]int{1,2,3,4,5,6}
//输出所有元素
fmt.Println(arr)
fmt.Println(arr[:])
//输出 [1 2 3 4 5 6]
//输出前五个元素
fmt.Println(arr[:5])
//输出 [1 2 3 4 5]   
//输出从第5个开始（不包含第5个）
fmt.Println(arr[5:])
//输出 [6] 
//数组的长度
fmt.Println(len(arr))
//输出 6
```

#### 1.3 数组的遍历

```go
arr := [3]int{1,2,3}

for i := 0; i < len(arr); i++ {
	fmt.Println(arr[i])
}
//输出 
1
2
3
arr := [3]int{1,2,3}

for key, value := range arr {
	fmt.Println(key, value)
}
//输出
0 1
1 2
2 3
```

#### 1.4 多维数组

```go
//创建多维数组
var arr[2][2]int
arr1 := [][]int{}
//多维数组仅第一维度允许使用"..."
arr2 := [...][2]int{
	{1,2},
	{3,4},
}
```



#### 1.5 数组使用注意事项

**数组创建完长度就固定，不可以再追加元素；**  

**长度是数组类型的一部分，因此`[3]int`与`[4]int`是不同的类型；**  

**数组之间的赋值是值的赋值，即当把一个数组作为参数传入函数的时候，传入的其实是该函数的副本，而不是他的指针。**


---

> 作者: [xunruo](https://xunruo.top)  
> URL: https://xunruo.top/post/5ded7b78/  

