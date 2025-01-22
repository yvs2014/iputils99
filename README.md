iputils99
---------

Ping and other small IP utilities

Included
--------
- ping
- arping
- clockdiff
- tracepath
- gai

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

Install
-------
```
meson install -C _build
```

Mainstream, History
-------------------
See mainstream iputils (https://github.com/iputils/iputils/)

