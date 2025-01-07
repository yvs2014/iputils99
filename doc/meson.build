# Copyright (c) Iputils Project, 2017-2019

manpages = []
custom_man_xsl = files('custom-man.xsl')
custom_html_xsl = files('custom-html.xsl')

if build_arping == true
	manpages += ['arping']
endif

if build_clockdiff == true
	manpages += ['clockdiff']
endif

if build_ping == true
	manpages += ['ping']
endif

if build_tracepath == true
	manpages += ['tracepath']
endif

xsltproc = find_program('xsltproc', required: build_man or build_html)
xsltproc_args = [
	'--nonet',
	'--stringparam', 'man.output.quietly', '1',
	'--stringparam', 'funcsynopsis.style', 'ansi',
	'--stringparam', 'man.th.extra1.suppress', '1',
	'--stringparam', base + '.version', version,
]

valid = xsltproc.found()
if valid
	docs = []
	if build_man
		docs += ['manpages']
	endif
	if build_html
		docs += ['html']
	endif
	foreach doc: docs
		xsl = 'http://docbook.sourceforge.net/release/xsl-ns/current/' + doc + '/docbook.xsl'
		cmd = [xsltproc, '--nonet', xsl]
		valid = (run_command(cmd, check: false).returncode() == 0)
		if not valid
			warning('xsltproc: cannot process ' + xsl)
			break
		endif
	endforeach
endif

if not valid
	warning('Docs will not be built')
	build_man  = false
	build_html = false
endif

if build_man
	foreach man: manpages
		custom_target(man + '.8',
			output: man + '.8',
			input:  man + '.xml',
			command: [
				xsltproc,
				'-o', '@OUTPUT@',
				xsltproc_args,
				custom_man_xsl,
				'@INPUT@',
			],
			install:     true,
			install_dir: join_paths(get_option('mandir'), 'man8'),
		)
	endforeach
endif

if build_html
	foreach man: manpages
		custom_target(man + '.html',
			output: man + '.html',
			input:  man + '.xml',
			command: [
				xsltproc,
				'-o', '@OUTPUT@',
				xsltproc_args,
				custom_html_xsl,
				'@INPUT@',
			],
			install:     true,
			install_dir: join_paths(get_option('datadir'), base),
		)
	endforeach
endif

