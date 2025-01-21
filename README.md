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

Build/Install
-------------
- raw (usually with /usr/local prefix)
```
meson setup _build --buildtype=release
meson compile -C _build
meson install -C _build
```
- .deb (Debian/Ubuntu)
```
dpkg-buildpackage -us -uc
ls -l ../iputils99-*_*.deb
```
- .rpm (Fedora/OpenSUSE)
```
rpmbuild -ba packaging/rpm/iputils99.spec
ls -l ~/rpmbuild/RPMS/*/iputils99-*.rpm
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

