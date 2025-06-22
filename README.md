
Iputils project is located at https://github.com/iputils/iputils/
-----------------------------------------------------------------


iputils + C99 (iputils99)
-------------------------
Updating and testing iputils in C99 way
(plus getaddrinfo wrapper and netdev altnames)


Build
-----
```
meson setup _build
meson compile -C _build
```

Run tests with raw socket
-------------------------
```
sudo setcap cap_net_raw+p ./_build/ping/ping
meson test -C _build
```

Run tests with icmp socket
--------------------------
it needs smth like '0 2147483647' in `sysctl net.ipv4.ping_group_range`
```
meson test -C _build
```
