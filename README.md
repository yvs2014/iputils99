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

Build and Install
-----------------
- raw
```
meson setup _build --buildtype=release
meson compile -C _build
meson install -C _build
```
- .deb package
```
dpkg-buildpackage -us -uc
dpkg -i ../iputils99-TOOLNAME_*.deb
```

Tests
-----
- raw socket
```
sudo setcap cap_net_raw+ep ./_build/ping/ping
meson test -C _build
```

- icmp socket
```
sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'
meson test -C _build
```

Mainstream, History
-------------------
See mainstream iputils (https://github.com/iputils/iputils/)

