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

id_cmd = ['id', '-u']
if meson.version().version_compare('>=0.47')
  r = run_command(id_cmd, check: false)
else
  r = run_command(id_cmd)
endif
run_as_root = r.stdout().strip().to_int() == 0
message('running as ' + (run_as_root ? 'root' : 'normal user'))

cmd = ping
if meson.version().version_compare('>=0.54')
  basename = [cmd.name()]
else
  basename = [cmd.path().split('/')[-1]]
endif

suite = 'base'
foreach dst: [localhost] + localhost46
  opts = ['-c', '1', dst]
  foreach switch: ipfamily
    if switch == '-6' and dst == localhost
      continue # localhost [::1] is not mandatory
    endif
    fail = (switch == '-4' and dst == localhost6) or (switch == '-6' and dst == '127.0.0.1')
    args = switch == '' ? opts : [switch] + opts
    name = ' '.join(basename + args)
    test(name, cmd, args: args, suite: suite, should_fail: fail)
  endforeach
endforeach

extra_suites = [ # list because no dictionaries before 0.47
  ['timeouts', true, [
    [ '-c', '5', '-i', '0.1' ],
    [ '-c', '1', '-I', 'lo'  ],
    [ '-c', '1', '-w', '1'   ],
    [ '-c', '1', '-W', '1'   ],
    [ '-c', '1', '-W', '1.1' ]]],
  ['fail', false, [
    [ '-c', '1.1'         ],
    [ '-I', 'nonexisting' ],
    [ '-w', '0.1'         ],
    [ '-w', '0,1'         ]]],
  ['root', run_as_root, [
    [ '-c', '1', '-i', '0.001']]], # -c1 required to quit ping when running as root
]

foreach param: extra_suites
  suite = param[0]
  fail  = not param[1]
  opts  = param[2]
  foreach dst: localhost46
    foreach args: opts
      args += dst
      name = ' '.join(basename + args)
      test(name, cmd, args: args, suite: suite, should_fail: fail)
    endforeach
  endforeach
endforeach

