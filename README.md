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
sudo sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list && apt update
apt-get build-dep systemtap 
```
* Compiling

```shell
./configure --prefix=/usr
make && make install
```

* Install the kernel debuginfo dependency

For different versions of ubuntu, get the corresponding kernel version at <https://wiki.ubuntu.com/Debug%20Symbol%20Packages>.

```shell
apt-get install linux-image-$(uname -r)-dbgsym
```


## Get start with systemtap-container

Compatible with all current systemtap operations, see <https://github.com/xfiretrace/stapxx>.

### Example

* You can trace processes like this

```
probe process("/proc/{PID}/root/Eexec_path}").function("*")
```

* Or Run with the script which stap++
  
``` shell
    stap++ -e 'probe begin { println("hello world") exit() }'
```

## Q & A

### How does it work

* We extended  `systemtap` so that it can trace processes using `/proc/{PID}/root/Eexec_path}` by improving the `Uprobe` inode and matching exec_path

You can only use `stap` like this

```
probe process("/proc/{PID}/root/Eexec_path}").function("*")
```

Also, use `stapxx` which we adapt stap++ with container

```shell

root       11807   11438  0 Jun14 ?        00:00:01 nginx: master process /usr/local/openresty/nginx/sbin/nginx -p /usr/local/kong -c nginx.conf
nobody     12956   11807  0 Jun14 ?        03:38:57 nginx: worker process

./stap++ -I ./tapset -x 12956  ./samples/ngx-rps.sxx --dump-src
#!/usr/bin/env stap

# Print out the current number of requests per second in the Nginx worker
# process specified at real time.

global count

probe process("/proc/12956/root/usr/local/openresty/nginx/sbin/nginx").function("ngx_http_log_request")
{
    if (pid() == target() && $r == $r->main) {
        count++
    }
}

probe timer.s(1) {
    printf("[%d] %d req/sec\n", gettimeofday_s(), count)
    count = 0
}

probe begin {
    warn(sprintf("Tracing process %d (/proc/12956/root/usr/local/openresty/nginx/sbin/nginx).\nHit Ctrl-C to end.\n", target()))
}

````


## Change log

See release <https://github.com/xfiretrace/systemtap/release>
