# Copyright (c) Iputils Project, 2017-2025

# local edition: yvs, 2024-2025

project('iputils99', 'c',
	default_options: [
		'c_std=c99',
		'warning_level=3',
#		'b_sanitize=address,undefined', # use for testing
	],
	meson_version: '>=0.47',
	version: find_program('git', required: false).found() ? run_command(
		'git', 'log', '-1', '--date=format:%Y%m%d', '--format=%cd',
			check: false).stdout().strip() : '20250115',
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')

base    = 'iputils'
name    = meson.project_name()
version = meson.project_version()
cc      = meson.get_compiler('c')
deps    = []
manpage = []
manexcl = {}

conf = configuration_data()
conf.set_quoted('PACKAGE_NAME',    name)
conf.set_quoted('PACKAGE_VERSION', version)
config_h = 'config.h'

build_ping      = get_option('BUILD_PING')
build_arping    = get_option('BUILD_ARPING')
build_clockdiff = get_option('BUILD_CLOCKDIFF')
build_tracepath = get_option('BUILD_TRACEPATH')
build_gai       = get_option('BUILD_GAI')

prefix    = get_option('prefix')
bindir    = join_paths(prefix, get_option('bindir'))
localedir = join_paths(prefix, get_option('localedir'))
sbindir   = join_paths(prefix, get_option('sbindir'))

setcap_ping      = false
setcap_arping    = false
setcap_clockdiff = false
if not get_option('NO_CAPS')
	setcap_ping      = get_option('PING_CAPS')
	setcap_arping    = get_option('ARPING_CAPS')
	setcap_clockdiff = get_option('CLOCKDIFF_CAPS')
endif

extra_funcs = {}
extra_funcs += {'getprogname':   {'hdr': ['stdlib.h']}}
extra_funcs += {'program_invocation_short_name': {'hdr': ['errno.h']}}
extra_funcs += {'clock_gettime': {'hdr': ['time.h'], 'lib': ['rt'], 'req': true}}

if host_machine.endian() == 'big'
	conf.set('WORDS_BIGENDIAN', '1')
endif

cap = get_option('CAP')
if cap
	deps += cc.find_library('cap')
	conf.set('HAVE_LIBCAP', 1, description: 'Defined if libcap exists')
endif

arping_device = get_option('ARPING_DEFAULT_DEVICE')
if arping_device != ''
	conf.set_quoted('DEFAULT_DEVICE', arping_device, description: 'arping default device')
endif

if build_ping
	extra_funcs += {'arc4random_uniform': {'hdr': ['stdlib.h']}}
	rfc4620 = get_option('RFC4620')
	if rfc4620	# RFC4620 builtin client
		conf.set('ENABLE_RFC4620', 1, description: 'build with RFC4620 NodeInfo client')
		if get_option('NONCE_MEMORY')
			conf.set('NONCE_MEMORY', 1,
				description: 'ping6 NodeInfo with nonce memory')
		endif
		extra_funcs += {'getrandom': {'hdr': ['sys/random.h']}}
	else
		manexcl += {'ping': ['N']}
	endif
endif

# warn if there's no PKTINFO
pkti_prfx = '#include <netinet/in.h>\n'
if cc.get_define('IP_PKTINFO', prefix: pkti_prfx) == ''
	warning('IP_PKTINFO: not found')
endif
if cc.get_define('IPV6_PKTINFO', prefix: pkti_prfx) == ''
	warning('IPV6_PKTINFO: not found')
endif

idn = get_option('IDN')
idn_via = '' # libc
if idn	# If available: use AI_IDN for getaddrinfo() queries
	ai_prfx = '#define _GNU_SOURCE\n#include <netdb.h>\n'
	if cc.get_define('AI_IDN', prefix: ai_prfx) == ''
		warning('IDN is not transparently supported')
		deps += dependency('libidn2', required: true)
		conf.set('USE_LIBIDN2', 1, description: 'Use libidn2 conversion')
		idn_via = '(libidn2)'
        endif
	conf.set('USE_IDN', 1, description: 'libc IDN support')
        if rfc4620	# idna_to_dns_encoding() for nodeinfo IDN
		extra_funcs += {'__idna_to_dns_encoding': {}}
        endif
endif

nls = get_option('NLS')
if nls
	conf.set('USE_NLS', 1, description: 'gettext NLS support')
	conf.set_quoted('LOCALEDIR', localedir)
	subdir('po')
	extra_funcs += {'gettext': {'hdr': ['libintl.h'], 'lib': ['intl'], 'req': true}}
endif

# Check functions availability
foreach f, ext: extra_funcs
	incl = ''
	hdrs = 'hdr' in ext ? ext['hdr'] : []
	foreach h: hdrs
#		incl += cc.has_header(h) ? '#include <' + h + '>\n' : ''
		incl += '#include <' + h + '>\n'
	endforeach
        found = cc.has_function(f, args: '-D_GNU_SOURCE', prefix: incl)
	if not found
		libs = 'lib' in ext ? ext['lib'] : []
		foreach l: libs
			lib = dependency('lib' + l, required: false)
			if not lib.found()
				lib = cc.find_library(l, required: false)
			endif
			if lib.found() and cc.has_function(f,
			args: '-D_GNU_SOURCE', prefix: incl, dependencies: lib)
				found = true
				deps += lib
                                break
			endif
		endforeach
	endif
	if found
		conf.set('HAVE_' + f.to_upper(), 1, description: 'Define if you have ' + f + ' function')
        else
		req = 'req' in ext ? ext['req'] : false
		if req
			error('Required function ' + f + '() is not found')
		endif
	endif
endforeach

configure_file(output: config_h, configuration: conf)
add_project_arguments('-include', config_h, language: 'c')

setcap = find_program('setcap', '/usr/sbin/setcap', '/sbin/setcap', required: false)
if cap and setcap.found()
	perm_type = 'caps'
	if meson.version().version_compare('>=0.55')
		setcap_path = setcap.full_path()
	else
		setcap_path = setcap.path()
	endif
else
	perm_type = 'setuid'
	setcap_path = '/dev/null'
endif


# build stage
#
aux = 'aux'
aux_src = []
ext_src = []
subdir(aux)
src = aux_src + ext_src

aux_inc = aux
cap_sh = join_paths(aux, 'setcap-setuid.sh')

if build_ping
	subdir('ping')
	if setcap_ping # TODO: combine ping/arping/clockdif
		meson.add_install_script(cap_sh, bindir,
			'ping', perm_type, setcap_path)
	endif
	manpage += 'ping'
endif

if build_arping
	arping = executable('arping', src + ['arping.c'],
		include_directories: include_directories(aux_inc),
		dependencies: deps, install: true)
	if setcap_arping
		meson.add_install_script(cap_sh, bindir,
			'arping', perm_type, setcap_path)
	endif
	manpage += 'arping'
endif

if build_clockdiff
	clockdiff = executable('clockdiff', src + ['clockdiff.c'],
		include_directories: include_directories(aux_inc),
		dependencies: deps, install: true)
	if setcap_clockdiff
		meson.add_install_script(cap_sh, bindir,
			'clockdiff', perm_type, setcap_path)
	endif
	manpage += 'clockdiff'
endif

if build_tracepath
	tracepath = executable('tracepath', aux_src + ['tracepath.c'],
		include_directories: include_directories(aux_inc),
		dependencies: deps, install: true)
	manpage += 'tracepath'
endif

if build_gai
	gai = executable('gai', aux_src + ['gai.c'],
		include_directories: include_directories(aux_inc),
		dependencies: deps, install: true)
	manpage += 'gai'
endif

if manpage.length() > 0
	subdir('man')
endif

tst = not get_option('SKIP_TESTS')
if tst
	subdir('test')
endif

# summary at the end
#
if meson.version().version_compare('>=0.53')
	sections = {}
	sections += {'APPLICATIONS': {
		'ping @0@'     .format(setcap_ping      ? '(with caps/suid)' : ''):
			build_ping,
		'arping @0@'   .format(setcap_arping    ? '(with caps/suid)' : ''):
			build_arping,
		'clockdiff @0@'.format(setcap_clockdiff ? '(with caps/suid)' : ''):
			build_clockdiff,
		'tracepath':
			build_tracepath,
		'gai':
			build_gai,
	}}
	sections += {'CONFIGURATION': {
		'Caps'    : cap,
		'IDN @0@ '.format(idn_via): idn,
		'NLS'     : nls,
		'RFC4620' : rfc4620,
		'Tests'   : tst,
	}}
	sections += {'DIRECTORIES': {
		'prefix'   : prefix,
		'bindir'   : bindir,
		'sbindir'  : sbindir,
		'localedir': localedir,
        }}
	foreach section, elements: sections
		foreach key, value: elements
			if '@0@'.format(value) != ''
				summary(key, value, bool_yn: true, section: section)
			endif
		endforeach
	endforeach
else # legacy

output = name + '-' + version + '\n'

output += '\nAPPLICATIONS (build)\n'
output += 'ping:\t\t'     + build_ping.to_string()
output += '  (caps/suid ' + setcap_ping.to_string()      + ')\n'
output += 'arping:\t\t'   + build_arping.to_string()
output += '  (caps/suid ' + setcap_arping.to_string()    + ')\n'
output += 'clockdiff:\t'  + build_clockdiff.to_string()
output += '  (caps/suid ' + setcap_clockdiff.to_string() + ')\n'
output += 'tracepath:\t'  + build_tracepath.to_string()  +  '\n'

output += '\nCONFIGURATION\n'
output += 'Caps:\t\t'  + cap.to_string()     + '\n'
output += 'IDN@0@\t'.format(idn_via != '' ? (' ' + idn_via + ':') : ':\t') + idn.to_string() + '\n'
output += 'NLS:\t\t'   + nls.to_string()     + '\n'
output += 'RFC4620:\t' + rfc4620.to_string() + '\n'
output += 'Tests:\t\t' + tst.to_string()     + '\n'

output += '\nDIRECTORIES\n'
output += 'prefix:\t\t'  + prefix    + '\n'
output += 'bindir:\t\t'  + bindir    + '\n'
output += 'sbindir:\t'   + sbindir   + '\n'
output += 'localedir:\t' + localedir + '\n'

message(output)

endif
