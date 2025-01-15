# Copyright (c) Iputils Project, 2017-2025

# local edition: yvs, 2024-2025

ping_src  = src
ping_src += 'ping.c'
ping_src += 'ping_aux.c'
ping_src += 'ping4.c'
ping_src += 'ping4_aux.c'
ping_src += 'ping6.c'
ping_src += 'ping6_aux.c'
ping_src += 'common.c'
ping_src += 'stats.c'
ping_src += 'extra.c'

ping_inc = [join_paths('..', aux_inc)]

if rfc4620
	ping_extra = []
	subdir('rfc4620')
	ping_src  += ping_extra
	ping_inc  += 'rfc4620'
endif

ping_extra_deps = []
ping_extra_deps += cc.find_library('m')
ping_extra_deps += cc.find_library('resolv', required: false)

ping = executable('ping', ping_src,
	include_directories: include_directories(ping_inc),
	dependencies: deps + ping_extra_deps,
	install: true)

