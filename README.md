# systemtap


##

* 核心特性，扩展支持 container 环境，可以在宿主机上 trace 容器的 pid
* 同时适配了 stapxx 和 openresty-systemtap-toolkit

### 安装

获取代码

```
git clone https://github.com/xfiretrace/systemtap.git
cd systemtap
git checkout feature/container
```

编译安装
```
apt-get build-dep systemtap 
./configure --prefix=/usr
make all
 
```

### 获取内核 debuginfo

```
https://wiki.ubuntu.com/Debug%20Symbol%20Packages
apt-get install linux-image-$(uname -r)-dbgsym
```

### 使用适配好的 stapxx

https://github.com/xfiretrace/stapxx
