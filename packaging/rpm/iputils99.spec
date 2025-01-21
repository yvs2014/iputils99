
# rpmbuild -ba iputils99.spec

Name:       iputils99
Version:    20250121
Release:    1
# some parts are under the original BSD
# some are under GPLv2+
License:    BSD-4-Clause-UC AND GPL-2.0-or-later
Summary:    iputils fork refactored in C99 way
Group:      Productivity/Networking/Other
URL:        https://github.com/yvs2014/%{name}

%define gtag 45d421b
%define namever %{name}-%{version}

#Source0:    {url}/tarball/{gtag}
Source0:    ${RPM_SOURCE_DIR}/%{namever}

BuildRequires: meson, pkgconf, git, sed, gettext, libcap-devel, libidn2-devel
BuildRequires: gcc
%if 0%{?fedora}
Requires: libcap
%else
Requires: libcap2
BuildRequires: libcap-progs
%endif
Conflicts: iputils
Provides: /bin/ping
Provides: /bin/arping
Provides: /bin/tracepath
Provides: /bin/clockdiff
Provides: /bin/gai

%description
iputils fork refactored in C99 way

%define prefix /usr

%prep
rm -rf %{namever}
git clone %{url} %{namever}
rm -rf ${RPM_SOURCE_DIR}/%{namever}
mkdir -p ${RPM_SOURCE_DIR}
cp -rv %{namever} ${RPM_SOURCE_DIR}
cd %{namever}

%build
cd %{namever}
%meson
%meson_build

%install
cd %{namever}
%meson_install
cd -
%find_lang %{name}

%post
setcap cap_net_raw+p %{_bindir}/arping
setcap cap_net_raw,cap_sys_nice+p %{_bindir}/clockdiff

%files -f %{name}.lang
%defattr(-,root,root,-)
%{_bindir}/ping
%{_bindir}/arping
%{_bindir}/clockdiff
%{_bindir}/tracepath
%{_bindir}/gai
%{_mandir}/man8/ping.8*
%{_mandir}/man8/arping.8*
%{_mandir}/man8/clockdiff.8*
%{_mandir}/man8/tracepath.8*
%{_mandir}/man8/gai.8*

%global source_date_epoch_from_changelog 0
%changelog
# autofill

