# systemtap-container

Enhanced version of systemtap to support container environments. This means that you can use the systemtap command to trace and analyze a container's pid if it is obtained on the host. Compatible with all future systemtap features, seamless migration.

## Feature

* Extended support for container environments allows you to trace a container's pid on the host machine.
* Adapted stapxx and openresty-systemtap-toolkit.

## Install

### From source code

* Get source code

```shell
git clone https://github.com/xfiretrace/systemtap.git
cd systemtap
```

* Installation command dependencies

```shell
apt-get build-dep systemtap 
```

* Install the debuginfo dependency

For different versions of ubuntu, get the corresponding kernel version at <https://wiki.ubuntu.com/Debug%20Symbol%20Packages>.

```shell
apt-get install linux-image-$(uname -r)-dbgsym
```

* Compiling

```shell
./configure --prefix=/usr
make all
```

## Get start with systemtap-container

Compatible with all current systemtap operations, see <https://github.com/xfiretrace/stapxx>.

### Example

* Run with script
  
``` shell
    stap++ -e 'probe begin { println("hello world") exit() }'
```

## Q & A

TODO

## Change log

See release <https://github.com/xfiretrace/systemtap/release>
