
# pregenerated manuals
# local edition: yvs, 2025

section = '8'
foreach page: manpage
	man = page + '.' + section
	configure_file(input: man + '.in', output: man, copy: true)
	file = meson.current_build_dir() / man
	if page in manexcl
		excl = manexcl[page]
		if excl.length() > 0
			sed = find_program('sed', required: false)
			if sed.found()
				foreach opt: excl
					cmd = run_command(sed, '-i.bak',
's/^\(\.ds o' + opt + ' "\).*/\\1/', file, check: false)
					if cmd.returncode() != 0
						warning(cmd.stderr())
					endif
				endforeach
			endif
		endif
	endif
	install_man(file)
endforeach

