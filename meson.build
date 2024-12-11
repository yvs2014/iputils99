# Copyright (c) Iputils Project, 2017-2021

# local edition by @yvs

project('iputils', 'c',
	default_options : [
		'c_std=c99',
		'warning_level=3',
		'localstatedir=var',
#		'b_sanitize=address,undefined', # use for testing
	],
	meson_version : '>=0.40',
	version : '20240117') # keep in sync with: git describe | awk -F- '{print $1}'

cc = meson.get_compiler('c')

add_project_arguments(
	'-include', 'config.h',
	'-include', 'git-version.h',
	language : 'c'
)

conf = configuration_data()
conf.set_quoted('PACKAGE_NAME', meson.project_name())

build_arping = get_option('BUILD_ARPING')
build_clockdiff = get_option('BUILD_CLOCKDIFF')
build_ping = get_option('BUILD_PING')
build_tracepath = get_option('BUILD_TRACEPATH')

build_mans = get_option('BUILD_MANS')
build_html_mans = get_option('BUILD_HTML_MANS')
run_tests = not get_option('SKIP_TESTS')

prefix = get_option('prefix')
bindir = join_paths(prefix, get_option('bindir'))
localedir = join_paths(prefix, get_option('localedir'))
sbindir = join_paths(prefix, get_option('sbindir'))

systemd = dependency('systemd', required : false)
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

extra_funcs = [
	'getprogname', 'program_invocation_short_name',
	'getrandom', 'nanosleep', '__fpending',
]

if cc.compiles('''
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netinet/icmp6.h>
	int main(void) {
		struct icmp6_nodeinfo nodeinfo;
		return 0;
	}
''', name: 'struct icmp6_nodeinfo')
	conf.set('HAVE_STRUCT_ICMP6_NODEINFO', 1, description: 'Defined if struct icmp6_nodeinfo exists')
endif

if cc.compiles('''
	#include <sys/types.h>
	#include <sys/time.h>
	#include <time.h>
	int main(void) {
		struct tm time;
		return 0;
	}
''', name: 'struct tm time;')
	conf.set('TIME_WITH_SYS_TIME', 1, description: 'Defined if struct tm exists')
endif

m_dep = cc.find_library('m')
resolv_dep = cc.find_library('resolv', required: false)

if cc.has_function('clock_gettime')
	rt_dep = cc.find_library('disabler-appears-to-disable-executable-build', required : false)
else
	rt_dep = cc.find_library('rt')
endif

cap = get_option('USE_CAP')
if cap
	cap_dep = cc.find_library('cap')
	conf.set('HAVE_LIBCAP', 1, description: 'Defined if libcap exists')
else
	cap_dep = dependency('disabler-appears-to-disable-executable-build', required : false)
endif

arping_device = get_option('ARPING_DEFAULT_DEVICE')
if arping_device != ''
	conf.set_quoted('DEFAULT_DEVICE', arping_device, description: 'arping default device')
endif

# Some systems need intl for gettext
intl_dep = []
i18_gettext = get_option('USE_GETTEXT')
if i18_gettext
	add_project_arguments(['-DGETTEXT_PACKAGE="iputils"'], language: 'c')
	conf.set('ENABLE_NLS', 1, description: 'If set enable I18N')
	conf.set_quoted('LOCALEDIR', localedir)
	subdir('po')
	intl_dep += cc.find_library('intl', required: false)
endif

idn = get_option('USE_IDN')
if idn	# If available: use AI_IDN for getaddrinfo() queries
	# and idna_to_dns_encoding() for nodeinfo IDN
	add_project_arguments('-DUSE_IDN', language: 'c')
	conf.set('USE_IDN', 1, description: 'If set use libc IDN support')
	extra_funcs += '__idna_to_dns_encoding'
endif

if build_ping
	ping_extra = files('md5.c')
	if get_option('PING6_NONCE_MEMORY')
		ping_extra += files('iputils_ni_aux.c')
		conf.set('PING6_NONCE_MEMORY', 1, description: 'Define to use ping6 NodeInfo with nonce memory')
	endif
endif

if host_machine.endian() == 'big'
	conf.set('WORDS_BIGENDIAN', '1')
endif

# Check functions availability
foreach f: extra_funcs
	if cc.has_function(f, args: '-D_GNU_SOURCE')
		conf.set('HAVE_' + f.to_upper(), 1, description: 'Define if you have ' + f + ' function')
	endif
endforeach

# Check headers availability
foreach h: ['error.h']
	if cc.has_header(h)
		conf.set('HAVE_' + h.to_upper().underscorify(), 1, description: 'Define if ' + h + ' can be included')
	endif
endforeach

git_version_h = vcs_tag(
	input:    'git-version.h.meson',
	output:   'git-version.h',
	fallback: meson.project_version()
)

config_h = configure_file(output: 'config.h', configuration: conf)

setcap = find_program('setcap', '/usr/sbin/setcap', '/sbin/setcap', required: false)
if cap_dep.found() and setcap.found()
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
common_sources = files('iputils_common.c') + [git_version_h]

if build_ping
	subdir('ping')
endif

if build_tracepath
	tracepath = executable('tracepath', common_sources + ['tracepath.c'],
		dependencies: [cap_dep, intl_dep], install: true)
endif

if build_clockdiff
	clockdiff = executable('clockdiff', common_sources + ['clockdiff.c'],
		dependencies: [cap_dep, intl_dep], install: true)
	if setcap_clockdiff
		meson.add_install_script('build-aux/setcap-setuid.sh',
			bindir, 'clockdiff', perm_type, setcap_path)
	endif
endif

if build_arping
	arping = executable('arping', common_sources + ['arping.c'],
		dependencies: [rt_dep, cap_dep, intl_dep], install: true)
	if setcap_arping
		meson.add_install_script('build-aux/setcap-setuid.sh',
			bindir, 'arping', perm_type, setcap_path)
	endif
endif

if build_mans or build_html_mans
	subdir ('doc')
endif

if run_tests
	subdir('test')
endif


# summary at the end
#
if meson.version().version_compare('>=0.53')
	sections = [ # lists because no dictionaries prior to 0.47
		['DOCUMENTATION', [
['Manual pages', build_mans],
['HTML manual',  build_html_mans],
		]], ['APPLICATIONS', [
['ping',         build_ping],
['  cap/suid ping',       setcap_ping],
['arping',       build_arping],
['  cap/suid arping',     setcap_arping],
['clockdiff',    build_clockdiff],
['  cap/suid clockdiff ', setcap_clockdiff],
['tracepath',    build_tracepath],
		]], ['CONFIGURATION', [
['Linux caps (libcap)', cap],
['IDN (via libc)',      idn],
['I18N (gettext)',      i18_gettext],
['Systemd',             install_systemd_units],
['Tests',               run_tests],
		]], ['DIRECTORIES', [
['prefix',         prefix],
['bindir',         bindir],
['localedir',      localedir],
['sbindir',        sbindir],
['systemdunitdir', systemdunitdir],
		]],
	]
	foreach part: sections
		foreach kv: part[1]
			if '@0@'.format(kv[1]) != ''
				summary(kv[0], kv[1], bool_yn: true, section: part[0])
			endif
		endforeach
	endforeach
else

output = '\n\nAPPLICATIONS (build)\n'
output += 'man: ' + build_mans.to_string() + '\n'
output += 'HTML man: ' + build_html_mans.to_string() + '\n'
output += 'arping: ' + build_arping.to_string()
output += ' (capability or suid: ' + setcap_arping.to_string() + ')\n'
output += 'clockdiff: ' + build_clockdiff.to_string()
output += ' (capability or suid: ' + setcap_clockdiff.to_string() + ')\n'
output += 'ping: ' + build_ping.to_string()
output += ' (capability or suid: ' + setcap_ping.to_string() + ')\n'
output += 'tracepath: ' + build_tracepath.to_string() + '\n'

output += '\nCONFIGURATION\n'
output += 'Capability (with libcap): ' + cap.to_string() + '\n'
output += 'IDN (via libc): ' + idn.to_string() + '\n'
output += 'I18N (with gettext): ' + i18_gettext.to_string() + '\n'
output += 'systemd: ' + install_systemd_units.to_string() + '\n'
output += 'run tests: ' + run_tests.to_string() + '\n'

output += '\nSYSTEM PATHS\n'
output += 'prefix: ' + prefix + '\n'
output += 'bindir: ' + bindir + '\n'
output += 'localedir: ' + localedir + '\n'
output += 'sbindir: ' + sbindir + '\n'
output += 'systemdunitdir: ' + systemdunitdir + '\n'

message(output)

endif
