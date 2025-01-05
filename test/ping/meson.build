# Copyright (c) 2021 Petr Vorel <pvorel@suse.cz>

# local edition: yvs, 2024

glibc_test = false
if cc.has_header('features.h')
  macrotest = '''#include <features.h>
#if !defined(__GLIBC__) || defined(__UCLIBC__)
#error "Not glibc"
#endif'''
  glibc_test = cc.compiles(macrotest, name: 'glibc test')
endif

ipfamily    = ['', '-4']
localhost   = 'localhost'
localhost4  = '127.0.0.1'
localhost6  = '::1'
localhost46 = [localhost4]
ip = find_program('ip', required: false)
ip6enabled = false
if ip.found()
  ip6_cmd = [ip, '-6', 'address']
  ip6_en = run_command(ip6_cmd, check: false)
  ip6enabled = ip6_en.stdout().contains('::1')
  if ip6enabled
    localhost46 += localhost6
    ipfamily    += '-6'
    message('IPv6 enabled')
  else
    warning('IPv6 disabled')
  endif
else
  warning('ip binary not found => disable IPv6 tests')
endif

id_cmd = ['id', '-u']
asroot = run_command(id_cmd, check: false).stdout().strip().to_int() == 0
message('running as ' + (asroot ? 'root' : 'normal user'))

cmd = ping
if meson.version().version_compare('>=0.54')
  basename = [cmd.name()]
else
  basename = [cmd.full_path().split('/')[-1]]
endif

suite = 'base'
foreach dst: [localhost] + localhost46
  opts = ['-c', '1', dst]
  foreach af: ipfamily
    if not (af == '-6' and dst == localhost) # localhost [::1] is not mandatory
      fail = (af == '-4' and dst == localhost6) or (af == '-6' and dst == '127.0.0.1')
      args = af == '' ? opts : [af] + opts
      name = ' '.join(basename + args)
      if meson.version().version_compare('>=0.58')
        name = name.replace(':', '_')
      endif
      test(name, cmd, args: args, suite: suite, should_fail: fail)
    endif
  endforeach
endforeach

suites = {
  'timeout': {'success': true,   'opts': [
    [ '-c', '5', '-i', '0.1' ],
    [ '-c', '1', '-I', 'lo'  ],
    [ '-c', '1', '-w', '1'   ],
    [ '-c', '1', '-W', '1'   ],
    [ '-c', '1', '-W', '1.1' ]]},
  'fail':    {'success': false,  'opts': [
    [ '-c', '1.1'         ],
    [ '-I', 'nonexisting' ],
    [ '-w', '0.1'         ],
    [ '-w', '0,1'         ]]},
  'root':    {'success': asroot, 'opts': [
    # -c1 to quit ping when running as root
    [ '-c', '1', '-i', '0.001']]},
}

foreach suite, params: suites
  fail = not params['success']
  opts = params['opts']
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
  af_4in6   = ['']
  if glibc_test
    af_4in6 += '-4'
  endif
  args_4in6 = ['-c', '1']
  localhost_4in6 = ['::ffff:127.0.0.1', '::ffff:7f00:1', '0:0:0:0:0:ffff:127.0.0.1' ]
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

