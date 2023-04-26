# rdb

Reverse debugger, similar to [rr](https://github.com/rr-debugger/rr) or [udb](https://undo.io/).

General usage:

```shell
$ sudo apt install -y build-essential
$ make clean all
# Build test appliance
$ cc test-app.c -O0 -o test-app -ggdb3 -Wall
# Allow child process to attach to the parent
$ echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope 
$ LD_PRELOAD=$PWD/libwrapper.so ./test-app
# ...
[gdb: 94313, src/wrapper.c:219] Waiting for connection from gdb on 0.0.0.0:4445...
```

Connect with GDB:
```gdb
(gdb) target remote 0.0.0.0:4445
(gdb) layout src
```
