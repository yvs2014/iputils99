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
if ni6
ping_src += 'node_info.c'
endif
ping_src += ping_extra

ping_extra_deps = []
ping_extra_deps += cc.find_library('m')
ping_extra_deps += cc.find_library('resolv', required: false)

ping = executable('ping', ping_src,
	include_directories: include_directories('..'),
	dependencies: deps + ping_extra_deps,
	install: true)

if setcap_ping
	meson.add_install_script('../build-aux/setcap-setuid.sh',
		bindir, 'ping', perm_type, setcap_path)
endif

