# Copyright (c) 2021 Petr Vorel <pvorel@suse.cz>

# GitHub CI does not have working IPv6
# https://github.com/actions/virtual-environments/issues/668
ipfamily    = ['', '-4']
localhost   = 'localhost'
localhost4  = '127.0.0.1'
localhost6  = 'ip6-localhost'
localhost46 = [localhost4]
ip = find_program('ip', required: false)
if ip.found()
  ip6_cmd = [ip, '-6', 'address']
  if meson.version().version_compare('>=0.47')
    ip6_en = run_command(ip6_cmd, check: false)
  else
    ip6_en = run_command(ip6_cmd)
  endif
  if ip6_en.stdout().contains('::1')
    localhost46 += localhost6
    ipfamily    += '-6'
    message('IPv6 enabled')
  else
    message('WARNING: IPv6 disabled')
  endif
else
  message('WARNING: ip binary not found => disable IPv6 tests')
endif

run_as_root = false
id_cmd = ['id', '-u']
if meson.version().version_compare('>=0.47')
  r = run_command(id_cmd, check: false)
else
  r = run_command(id_cmd)
endif
if r.stdout().strip().to_int() == 0
  message('running as root')
  run_as_root = true
else
  message('running as normal user')
endif

cmd = ping
cmd_name = ['ping']
args = ['-V']

name = ' '.join(cmd_name + args)
test(name, cmd, args: args)

foreach dst: [localhost] + localhost46
  foreach switch: ipfamily
	if switch == '-6' and dst == localhost
		 continue # localhost [::1] is not mandatory
	endif
	fail = (switch == '-4' and dst == localhost6) or (switch == '-6' and dst == '127.0.0.1')
	args = switch == '' ? ['-c1', dst] : [switch, '-c1', dst]
	name = ' '.join(cmd_name + args)
	test(name, cmd, args: args, should_fail: fail)
  endforeach
endforeach

ping_tests_opt = [
  [ '-c1' ],
  [ '-c5', '-i0.1' ],
  [ '-c1', '-I', 'lo' ],
  [ '-c1', '-w1' ],
  [ '-c1', '-W1' ],
  [ '-c1', '-W1.1' ],
]
foreach dst : localhost46
  foreach args : ping_tests_opt
	args += [ dst ]
	name = ' '.join(cmd_name + args)
	test(name, cmd, args : args)
  endforeach
endforeach

ping_tests_opt_fail = [
  [ '-c1.1' ],
  [ '-I', 'nonexisting' ],
  [ '-w0.1' ],
  [ '-w0,1' ],
]
foreach dst : localhost46
  foreach args : ping_tests_opt_fail
	args += [ dst ]
	name = ' '.join(cmd_name + args)
	test(name, cmd, args : args, should_fail : true)
  endforeach
endforeach

ping_tests_user_fail = [
  [ '-c1', '-i0.001' ], # -c1 required to quit ping when running as root
]
foreach dst : localhost46
  foreach args : ping_tests_user_fail
	args += [ dst ]
	name = ' '.join(cmd_name + args)
	test(name, cmd, args : args, should_fail : not run_as_root)
  endforeach
endforeach
