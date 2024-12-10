# Copyright (c) Iputils Project, 2017-2021

inc = include_directories('..')

ping = executable('ping', common_sources + [
		'ping.c',
		'common.c',
		'ping4.c',
		'ping4_func.c',
		'ping4_aux.c',
		'ping6_common.c',
		'node_info.c',
		'md5.c',
		'extra.c',
	],
	include_directories: inc,
	dependencies: [cap_dep, intl_dep, m_dep, resolv_dep],
	install: true)

if (setcap_ping)
	meson.add_install_script('../build-aux/setcap-setuid.sh',
		bindir, 'ping', perm_type, setcap_path)
endif
