# Copyright (c) Iputils Project, 2017-2026

# local edition: yvs, 2024-2025

arping_src  = aux_src + perm_src + sub_src
arping_src += 'arping.c'
arping_src += 'processing.c'

arping_inc = ['..' / aux]

tool = 'arping'
app += { tool: executable(tool, arping_src, dependencies: deps,
	include_directories: include_directories(arping_inc),
	install: true, install_mode: install_mode) }

