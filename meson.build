# Copyright (c) Iputils Project, 2017-2021

# local edition by @yvs

project('iputils', 'c',
	default_options: [
		'c_std=c99',
		'warning_level=3',
		'localstatedir=var',
#		'b_sanitize=address,undefined', # use for testing
	],
	meson_version: '>=0.47',
	version: find_program('git', required: false).found() ? run_command(
		'git', 'log', '-1', '--date=format:%Y%m%d', '--format=%cd',
			check: false).stdout().strip() : '20250104',
)

name    = meson.project_name()
version = meson.project_version()
cc      = meson.get_compiler('c')
deps    = []

conf = configuration_data()
conf.set_quoted('PACKAGE_NAME',    name)
conf.set_quoted('PACKAGE_VERSION', version)
config_h = 'config.h'

build_arping    = get_option('BUILD_ARPING')
build_clockdiff = get_option('BUILD_CLOCKDIFF')
build_ping      = get_option('BUILD_PING')
build_tracepath = get_option('BUILD_TRACEPATH')

build_man  = get_option('BUILD_MAN')
build_html = get_option('BUILD_HTML')

run_tests = not get_option('SKIP_TESTS')

prefix = get_option('prefix')
bindir = join_paths(prefix, get_option('bindir'))
localedir = join_paths(prefix, get_option('localedir'))
sbindir = join_paths(prefix, get_option('sbindir'))

systemd = dependency('systemd', required: false)
install_systemd_units = systemd.found() or get_option('INSTALL_SYSTEMD_UNITS')

systemdunitdir = get_option('systemdunitdir')
if systemdunitdir == '' and install_systemd_units
	unitdir_var = 'systemdsystemunitdir'
	if meson.version().version_compare('>=0.51')
		systemdunitdir = systemd.get_variable(pkgconfig: unitdir_var)
	else
		systemdunitdir = systemd.get_pkgconfig_variable(unitdir_var)
	endif
endif

setcap_arping = false
setcap_clockdiff = false
setcap_ping = false
if (not get_option('NO_SETCAP_OR_SUID'))
  setcap_arping = get_option('SETCAP_OR_SUID_ARPING')
  setcap_clockdiff = get_option('SETCAP_OR_SUID_CLOCKDIFF')
  setcap_ping = get_option('SETCAP_OR_SUID_PING')
endif

extra_funcs = {}
extra_funcs += {'getprogname':   {'hdr': ['stdlib.h']}}
extra_funcs += {'program_invocation_short_name': {'hdr': ['errno.h']}}
extra_funcs += {'getrandom':     {'hdr': ['sys/random.h']}}
extra_funcs += {'clock_gettime': {'hdr': ['time.h'], 'lib': ['rt'], 'req': true}}

cap = get_option('USE_CAP')
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
	extra_files = ['md5.c']
	ni6 = get_option('NI6')
        if ni6	# RFC4620 builtin client
		conf.set('ENABLE_NI6', 1, description: 'build with RFC4620 NodeInfo client')
		if get_option('PING6_NONCE_MEMORY')
			conf.set('PING6_NONCE_MEMORY', 1,
				description: 'ping6 NodeInfo with nonce memory')
		endif
		extra_files += name + '_ni_aux.c'
	endif
	ping_extra = files(extra_files)
endif

idn = get_option('USE_IDN')
if idn	# If available: use AI_IDN for getaddrinfo() queries
	ai_prfx = '#define _GNU_SOURCE\n#include <netdb.h>\n'
	if cc.get_define('AI_IDN', prefix: ai_prfx) == ''
		error('IDN is not transparently supported')
        endif
	add_project_arguments('-DUSE_IDN', language: 'c')
	conf.set('USE_IDN', 1, description: 'libc IDN support')
        if ni6 # idna_to_dns_encoding() for nodeinfo IDN
		extra_funcs += {'__idna_to_dns_encoding': {'req': true}}
        endif
endif

nls = get_option('USE_NLS')
if nls
	add_project_arguments('-DGETTEXT_PACKAGE="' + name + '"', language: 'c')
	conf.set('USE_NLS', 1, description: 'gettext NLS support')
	conf.set_quoted('LOCALEDIR', localedir)
	subdir('po')
	extra_funcs += {'gettext': {'hdr': ['libintl.h'], 'lib': ['intl'], 'req': true}}
endif

if host_machine.endian() == 'big'
	conf.set('WORDS_BIGENDIAN', '1')
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
common_sources = files(name + '_common.c')

if build_ping
	subdir('ping')
endif

if build_tracepath
	tracepath = executable('tracepath', common_sources + ['tracepath.c'],
		dependencies: deps, install: true)
endif

if build_clockdiff
	clockdiff = executable('clockdiff', common_sources + ['clockdiff.c'],
		dependencies: deps, install: true)
	if setcap_clockdiff
		meson.add_install_script('build-aux/setcap-setuid.sh',
			bindir, 'clockdiff', perm_type, setcap_path)
	endif
endif

if build_arping
	arping = executable('arping', common_sources + ['arping.c'],
		dependencies: deps, install: true)
	if setcap_arping
		meson.add_install_script('build-aux/setcap-setuid.sh',
			bindir, 'arping', perm_type, setcap_path)
	endif
endif

if build_man or build_html
	subdir('doc')
endif

if run_tests
	subdir('test')
endif


# summary at the end
#
if meson.version().version_compare('>=0.53')
	sections = {}
	sections += {'DOCUMENTATION': {
		'Manual pages': build_man,
		'HTML manuals': build_html,
	}}
	sections += {'APPLICATIONS': {
		'ping':         build_ping,
		'  caps/suid ping':       setcap_ping,
		'arping':       build_arping,
		'  caps/suid arping':     setcap_arping,
		'clockdiff':    build_clockdiff,
		'  caps/suid clockdiff ': setcap_clockdiff,
		'tracepath':    build_tracepath,
	}}
	sections += {'CONFIGURATION': {
		'Caps  (libcap)': cap,
		'IDN (via libc)': idn,
		'NLS  (gettext)': nls,
		'NI6  (rfc4620)': ni6,
		'Systemd':        install_systemd_units,
		'Tests':          run_tests,
	}}
	sections += {'DIRECTORIES': {
		'prefix':         prefix,
		'bindir':         bindir,
		'localedir':      localedir,
		'sbindir':        sbindir,
		'systemdunitdir': systemdunitdir,
        }}
	foreach section, elements: sections
		foreach key, value: elements
			if '@0@'.format(value) != ''
				summary(key, value, bool_yn: true, section: section)
			endif
		endforeach
	endforeach
else # legacy

output  = name + '-' + version
output += '\n\nAPPLICATIONS (build)\n'
output += 'Manual pages:   ' + build_man.to_string()  + '\n'
output += 'HTML maniuals:  ' + build_html.to_string() + '\n'
output += 'arping:         ' + build_arping.to_string()
output += '  (caps/suid ' + setcap_arping.to_string() + ')\n'
output += 'clockdiff:      ' + build_clockdiff.to_string()
output += '  (caps/suid ' + setcap_clockdiff.to_string() + ')\n'
output += 'ping:           ' + build_ping.to_string()
output += '  (caps/suid ' + setcap_ping.to_string() + ')\n'
output += 'tracepath:      ' + build_tracepath.to_string() + '\n'

output += '\nCONFIGURATION\n'
output += 'Caps  (libcap): ' + cap.to_string() + '\n'
output += 'IDN (via libc): ' + idn.to_string() + '\n'
output += 'NLS  (gettext): ' + nls.to_string() + '\n'
output += 'NI6  (rfc4620): ' + ni6.to_string() + '\n'
output += 'systemd:        ' + install_systemd_units.to_string() + '\n'
output += 'run tests:      ' + run_tests.to_string() + '\n'

output += '\nSYSTEM PATHS\n'
output += 'prefix:         ' + prefix + '\n'
output += 'bindir:         ' + bindir + '\n'
output += 'localedir:      ' + localedir + '\n'
output += 'sbindir:        ' + sbindir + '\n'
output += 'systemdunitdir: ' + systemdunitdir + '\n'

message(output)

endif
