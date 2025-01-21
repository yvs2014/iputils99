for _TESTING_ only
------------------

There are a few packaging samples

Following commands can be used to build a correspondent package
(should be run from base directory of the project)

- deb (Debian/Ubuntu)
```
dpkg-buildpackage -us -uc
ls -l ../iputils99-*_*.deb
```

- rpm (Fedora/OpenSUSE)
```
rpmbuild -ba packaging/rpm/iputils99.spec
ls -l ~/rpmbuild/RPMS/*/iputils99-*.rpm
```

- PKGBUILD (Arch like)
```
cd packaging/aur
makepkg -cf
ls -l iputils99-*
```

- APKBUILD (Alpine like)
```
cd packaging/alp
abuild -rc
ls -l ~/packages/packaging/*/iputils99-*.apk
```

