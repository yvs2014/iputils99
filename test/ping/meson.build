# Copyright (c) 2021 Petr Vorel <pvorel@suse.cz>

# local edition by @yvs

ipfamily    = ['', '-4']
localhost   = 'localhost'
localhost4  = '127.0.0.1'
localhost6  = '::1'
localhost46 = [localhost4]
ip = find_program('ip', required: false)
ip6enabled = false
if ip.found()
  ip6_cmd = [ip, '-6', 'address']
  if meson.version().version_compare('>=0.47')
    ip6_en = run_command(ip6_cmd, check: false)
  else
    ip6_en = run_command(ip6_cmd)
  endif
  ip6enabled = ip6_en.stdout().contains('::1')
  if ip6enabled
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
  basename = [cmd.full_path().split('/')[-1]]
endif

suite = 'base'
foreach dst: [localhost] + localhost46
  opts = ['-c', '1', dst]
  foreach switch: ipfamily
    if not (switch == '-6' and dst == localhost) # localhost [::1] is not mandatory
      fail = (switch == '-4' and dst == localhost6) or (switch == '-6' and dst == '127.0.0.1')
      args = switch == '' ? opts : [switch] + opts
      name = ' '.join(basename + args)
      if meson.version().version_compare('>=0.58')
        name = name.replace(':', '_')
      endif
      test(name, cmd, args: args, suite: suite, should_fail: fail)
    endif
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
      if meson.version().version_compare('>=0.58')
        name = name.replace(':', '_')
      endif
      test(name, cmd, args: args, suite: suite, should_fail: fail)
    endforeach
  endforeach
endforeach

# test ip4 in ip6 space
if ip6enabled
  suite = 'ip4in6'
  fail  = false
  af_4in6   = ['',  '-4']
  args_4in6 = ['-c', '1']
  localhost_4in6 = ['::ffff:127.0.0.1', '::ffff:7f00:1' ]
  foreach af: af_4in6
    foreach dst: localhost_4in6
      args  = af != '' ? [af] : []
      args += args_4in6
      args += dst
      name = ' '.join(basename + args)
      if meson.version().version_compare('>=0.58')
        name = name.replace(':', '_')
      endif
      test(name, cmd, args: args, suite: suite, should_fail: fail)
    endforeach
  endforeach
endif

