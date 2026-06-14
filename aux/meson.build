# Copyright (c) Iputils Project, 2017-2026

aux_src    += files('iputils.c')
aux_src    += files('str2num.c')
aux_subsrc += {'iface'  : files('nlink.c')  }
aux_subsrc += {'sock_pa': files('sock_pa.c')}
aux_subsrc += {'sock_pc': files('sock_pc.c')}
aux_subsrc += {'sock_pt': files('sock_pt.c')}
perm_src   += files(libcap ? 'caps.c' : 'perm.c')

