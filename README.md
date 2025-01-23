
Iputils project is located at https://github.com/iputils/iputils/
-----------------------------------------------------------------


iputils + C99 style (iputils99)
-------------------------------
Updating and testing iputils in C99 way
(iputils and getaddrinfo wrapper)


Build
-----
```
meson setup _build --buildtype=release
meson compile -C _build
```

Tests
-----
- raw socket
```
sudo setcap cap_net_raw+p ./_build/ping/ping
meson test -C _build
```

- icmp socket
```
sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'
meson test -C _build
```

