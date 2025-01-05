# Copyright (c) 2021 Petr Vorel <pvorel@suse.cz>

# local edition: yvs, 2024

cmds = []
if build_clockdiff
  cmds += clockdiff
endif
if build_tracepath
  cmds += tracepath
endif
if build_arping
  cmds += arping
endif
if build_ping
  cmds += ping
endif

args = ['-V']
suite = 'version'
foreach cmd: cmds
  if meson.version().version_compare('>=0.54')
    basename = [cmd.name()]
  else
    basename = [cmd.full_path().split('/')[-1]]
  endif
  name = ' '.join(basename + args)
  test(name, cmd, args: args, suite: suite)
endforeach

if build_ping
  subdir('ping')
endif

