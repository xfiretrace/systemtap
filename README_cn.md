# systemtap-container

基于 systemtap 的增强版本，支持了 container 环境。只要表现为只需要通过在宿主机上获取的容器 pid，就可以直接使用 systemtap 命令对这个 pid 进行 trace 分析。兼容所有的 systemtap 以后特性，无缝迁移


## 支持特性

* 扩展支持 container 环境，可以在宿主机上 trace 容器的 pid
* 适配了 stapxx 和 openresty-systemtap-toolkit

## 安装

### 源码安装

* 获取源码
  
```shell
git clone https://github.com/xfiretrace/systemtap.git
cd systemtap
```

* 安装命令依赖
  
```shell
apt-get build-dep systemtap 
```

* 安装 debuginfo 依赖
  
针对不同版本的 ubuntu 版本，通过地址 <https://wiki.ubuntu.com/Debug%20Symbol%20Packages> 获取对应内核版本

```shell
apt-get install linux-image-$(uname -r)-dbgsym
```

* 编译

```shell
./configure --prefix=/usr
make all
```

## 使用

兼容当前所有的 systemtap 的操作，可以参见 <https://github.com/xfiretrace/stapxx>

### 示例

* 使用自定义脚本
  
```shell
    stap++ -e 'probe begin { println("hello world") exit() }'
```

## Q & A

TODO

## Change log

见 release <https://github.com/xfiretrace/systemtap/release>
