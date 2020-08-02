# hosts-hijacking

Hijack UDP-based([libc recvfrom](https://man7.org/linux/man-pages/man2/recvfrom.2.html)) DNS A/AAAA response with LD_PRELOAD.

```
# make build

# cat /path/to/hosts
10.8.8.8 google.com

# HOSTS_HIJACKING=/path/to/hosts LD_PRELOAD=$(pwd)/src/hosts-hijacking.so xx-cmd-using-libc-recvfrom
```

## Why

- We want to keep the dirty hack at the client-side.
- We have no permission to change the hosts file(or we do not want to change it, see below).
- No side effect to other processes.

## NOTES

- NOT FULLY TESTED!!!
- If you want to use it with golang, the most reliable way is compiling the golang program with `-tags netcgo`(DO NOT use cross-platform compile).
