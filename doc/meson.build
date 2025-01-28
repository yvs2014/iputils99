# Copyright (c) Iputils Project, 2017-2019

# local edition: yvs, 2025

gen_proc = 'xsltproc'
gen_html = files('custom-html.xsl')
gen_man  = files('custom-man.xsl')

cmd_proc = find_program(gen_proc)
cmd_args = [
	'--nonet',
	'--stringparam', 'man.output.quietly',     '1',
	'--stringparam', 'funcsynopsis.style',     'ansi',
	'--stringparam', 'man.th.extra1.suppress', '1',
	'--stringparam', base + '.version',        version,
]

valid = cmd_proc.found()
if valid
	foreach book: ['manpages', 'html']
		fmt = 'http://docbook.sourceforge.net/release/xsl-ns/current/' + book + '/docbook.xsl'
		cmd = [cmd_proc, '--nonet', fmt]
		valid = (run_command(cmd, check: false).returncode() == 0)
		if not valid
			docgen_okay = false
			warning(gen_proc + ': cannot process ' + fmt)
			break
		endif
	endforeach
endif

if valid
	cmd = [cmd_proc, '-o', '@OUTPUT@', cmd_args]
	foreach man: manpage
		if docgen_excl.contains(man)
			continue         # not yet
		endif
		template = man + '.xml'
		pageout  = man + '.8'    # manual pages
		custom_target(pageout,
			input:       template,
			output:      pageout,
			command:     cmd + [gen_man, '@INPUT@'],
			install:     true,
			install_dir: get_option('mandir') / 'man8',
		)
		pageout  = man + '.html' # html pages
		custom_target(pageout,
			input:       template,
			output:      pageout,
			command:     cmd + [gen_html, '@INPUT@'],
			install:     true,
			install_dir: get_option('datadir') / base,
		)
	endforeach
	warning('Not all iputils99 changes are reflected in the generated docs')
else
	warning('Documentation is not generated')
endif

