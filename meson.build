# Copyright (c) Iputils Project, 2017-2025

# local edition: yvs, 2024-2025

project('iputils99', 'c',
	default_options: [
		'c_std=c99',
		'warning_level=3',
#		'b_sanitize=address,undefined', # use for testing
	],
	meson_version: '>=0.55',
	version: find_program('git', required: false).found() ? run_command(
		'git', 'log', '-1', '--date=format:%Y%m%d', '--format=%cd',
			check: false).stdout().strip() : '20250118',
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

iputils = ['ping', 'arping', 'clockdiff', 'tracepath', 'gai']

prefix    = get_option('prefix')
bindir    = join_paths(prefix, get_option('bindir'))
localedir = join_paths(prefix, get_option('localedir'))
sbindir   = join_paths(prefix, get_option('sbindir'))

build = {
	'ping':      get_option('BUILD_PING'),
	'arping':    get_option('BUILD_ARPING'),
	'clockdiff': get_option('BUILD_CLOCKDIFF'),
	'tracepath': get_option('BUILD_TRACEPATH'),
	'gai':       get_option('BUILD_GAI'),
}

libcap = get_option('CAP')
if libcap
	deps += cc.find_library('cap')
	conf.set('HAVE_LIBCAP', 1, description: 'Defined if libcap exists')
endif

rfc4620 = get_option('RFC4620')

extra_funcs = {}
extra_funcs += {'getprogname':   {'hdr': ['stdlib.h']}}
extra_funcs += {'program_invocation_short_name': {'hdr': ['errno.h']}}
extra_funcs += {'clock_gettime': {'hdr': ['time.h'], 'lib': ['rt'], 'req': true}}

if host_machine.endian() == 'big'
	conf.set('WORDS_BIGENDIAN', '1')
endif

arping_device = get_option('ARPING_DEFAULT_DEVICE')
if arping_device != ''
	conf.set_quoted('DEFAULT_DEVICE', arping_device, description: 'arping default device')
endif

if build['ping']
	extra_funcs += {'arc4random_uniform': {'hdr': ['stdlib.h']}}
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
		incl += cc.has_header(h) ? '#include <' + h + '>\n' : ''
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

set_caps = get_option('INSTALL_WITH_CAPS')
set_suid = get_option('INSTALL_WITH_SUID')

if set_caps and libcap
	setcap = find_program('setcap', '/usr/sbin/setcap', '/sbin/setcap')
endif
if get_option('NEED_NET_RAW')
	linuxcaps = {
		'ping':      'cap_net_raw+p',
		'arping':    'cap_net_raw+p',
		'clockdiff': 'cap_net_raw,cap_sys_nice+p',
	}
else
	linuxcaps = {
		'clockdiff': 'cap_sys_nice+p',
	}
endif


# build stage
#
aux = 'aux'
aux_src     = []
perm_src    = []
subdir(aux)
subfoldered = ['ping']

app = {}
foreach tool: iputils
	if build[tool]
		manpage += tool
		src = aux_src
		install_mode = []
		if tool in linuxcaps
			src += perm_src
			if set_caps and libcap
				message(tool + ' with ' + linuxcaps[tool] + ' caps')
meson.add_install_script(setcap, linuxcaps[tool], join_paths(bindir, tool))
			elif set_suid
				suid_perm = 'r-sr-xr-x'
				warning(tool + ' suid mode: ' + suid_perm)
				install_mode += suid_perm
			endif
		endif
                if tool in subfoldered
			subdir(tool)
                else
			app += { tool:
executable(tool, src + [tool + '.c'], dependencies: deps,
	include_directories: include_directories(aux),
        install: true, install_mode: install_mode)
			}
		endif
	endif
endforeach

if manpage.length() > 0
	subdir('man')
endif

tests = get_option('TESTS')
if tests
	subdir('test')
endif

docgen = get_option('DOCGEN')
docgen_okay = true
if docgen
	docgen_excl = ['gai']
	subdir('doc')
endif


# summary at the end
#

sect_app = {}
perm_sfx = libcap ? ' (caps) ' : ' '
foreach tool: iputils
	tool_sfx  = (tool in linuxcaps) ? perm_sfx : ' '
	sect_key  = '@0@@1@'.format(tool, tool_sfx)
	sect_app += {sect_key: build[tool]}
endforeach

sect_cnf = {
	'Caps'    : libcap,
	'IDN @0@ '.format(idn_via): idn,
	'NLS'     : nls,
	'RFC4620' : rfc4620,
	'Tests'   : tests,
}
if docgen or not docgen_okay
	sect_cnf += {'Generate docs': docgen and docgen_okay}
endif

sect_dir = {
	'prefix'   : prefix,
	'bindir'   : bindir,
	'sbindir'  : sbindir,
	'localedir': localedir,
}

sections = {
	'APPLICATIONS' : sect_app,
	'CONFIGURATION': sect_cnf,
	'DIRECTORIES'  : sect_dir,
}

foreach section, elems: sections
	foreach key, value: elems
		if '@0@'.format(value) != ''
			summary(key, value, bool_yn: true, section: section)
		endif
	endforeach
endforeach

