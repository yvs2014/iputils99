# Copyright (c) Iputils Project, 2017-2021

ping_src = common_sources
ping_src += 'ping.c'
ping_src += 'ping_aux.c'
ping_src += 'ping4.c'
ping_src += 'ping4_aux.c'
ping_src += 'ping6.c'
ping_src += 'ping6_aux.c'
ping_src += 'common.c'
ping_src += 'extra.c'
ping_src += 'node_info.c'
ping_src += ping_extra

ping = executable('ping', ping_src,
	include_directories: include_directories('..'),
	dependencies: [cap_dep, intl_dep, m_dep, resolv_dep],
	install: true)

if setcap_ping
	meson.add_install_script('../build-aux/setcap-setuid.sh',
		bindir, 'ping', perm_type, setcap_path)
endif
