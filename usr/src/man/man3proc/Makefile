#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2018 Joyent, Inc.
# Copyright 2019, Carlos Neira <cneirabustos@gmail.com>
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.

include		$(SRC)/Makefile.master

MANSECT=	3proc

MANFILES=					\
		Lctlfd.3proc			\
		Lfree.3proc			\
		Lgrab_error.3proc		\
		Lgrab.3proc			\
		Lprochandle.3proc		\
		Lpsinfo.3proc			\
		Lstate.3proc			\
		Lstatus.3proc			\
		Paddr_to_ctf.3proc		\
		Paddr_to_loadobj.3proc		\
		Paddr_to_map.3proc		\
		Pasfd.3proc			\
		Pclearfault.3proc		\
		Pclearsig.3proc			\
		Pcontent.3proc			\
		Pcreate_agent.3proc		\
		Pcreate_error.3proc		\
		Pcreate.3proc			\
		Pcred.3proc			\
		Pctlfd.3proc			\
		Pcwd.3proc			\
		Pdelbkpt.3proc			\
		Pdelwapt.3proc			\
		Pdestroy_agent.3proc		\
		Penv_iter.3proc			\
		Perror_printf.3proc		\
		Pexecname.3proc			\
		Pfault.3proc			\
		Pfdinfo_iter.3proc		\
		Pgcore.3proc			\
		Pgetareg.3proc			\
		Pgetauxval.3proc		\
		Pgetauxvec.3proc		\
		Pgetenv.3proc			\
		Pgrab_core.3proc		\
		Pgrab_error.3proc		\
		Pgrab_file.3proc		\
		Pgrab.3proc			\
		Pisprocdir.3proc		\
		Pissyscall.3proc		\
		Pldt.3proc			\
		Plmid.3proc			\
		Plookup_by_addr.3proc		\
		Plwp_getasrs.3proc		\
		Plwp_getgwindows.3proc		\
		Plwp_getname.3proc		\
		Plwp_getpsinfo.3proc		\
		Plwp_getregs.3proc		\
		Plwp_getspymaster.3proc		\
		Plwp_getxregs.3proc		\
		Plwp_iter.3proc			\
		Plwp_stack.3proc		\
		Pmapping_iter.3proc		\
		Pobjname.3proc			\
		Pplatform.3proc			\
		Ppltdest.3proc			\
		Ppriv.3proc			\
		Ppsinfo.3proc			\
		pr_access.3proc			\
		pr_close.3proc			\
		pr_creat.3proc			\
		pr_door_info.3proc		\
		pr_exit.3proc			\
		pr_fcntl.3proc			\
		pr_fstatvfs.3proc		\
		pr_getitimer.3proc		\
		pr_getpeername.3proc		\
		pr_getpeerucred.3proc		\
		pr_getprojid.3proc		\
		pr_getrctl.3proc		\
		pr_getrlimit.3proc		\
		pr_getsockname.3proc		\
		pr_getsockopt.3proc		\
		pr_gettaskid.3proc		\
		pr_getzoneid.3proc		\
		pr_ioctl.3proc			\
		pr_link.3proc			\
		pr_llseek.3proc			\
		pr_lseek.3proc			\
		pr_memcntl.3proc		\
		pr_meminfo.3proc		\
		pr_mmap.3proc			\
		pr_munmap.3proc			\
		pr_open.3proc			\
		pr_processor_bind.3proc		\
		pr_rename.3proc			\
		pr_setitimer.3proc		\
		pr_setrctl.3proc		\
		pr_setrlimit.3proc		\
		pr_settaskid.3proc		\
		pr_sigaction.3proc		\
		pr_stat.3proc			\
		pr_statvfs.3proc		\
		pr_unlink.3proc			\
		pr_waitid.3proc			\
		Prd_agent.3proc			\
		Pread.3proc			\
		Prelease.3proc			\
		Preopen.3proc			\
		Preset_maps.3proc		\
		proc_arg_grab.3proc		\
		proc_arg_psinfo.3proc		\
		proc_content2str.3proc		\
		proc_fdinfo_misc.3proc		\
		proc_fdinfowalk.3proc		\
		proc_fdwalk.3proc		\
		proc_fltname.3proc		\
		proc_fltset2str.3proc		\
		proc_get_auxv.3proc		\
		proc_get_cred.3proc		\
		proc_get_fdinfo.3proc		\
		proc_get_lwpsinfo.3proc		\
		proc_get_priv.3proc		\
		proc_get_psinfo.3proc		\
		proc_get_status.3proc		\
		proc_initstdio.3proc		\
		proc_lwp_in_set.3proc		\
		proc_service.3proc		\
		proc_str2flt.3proc		\
		proc_str2fltset.3proc		\
		proc_unctrl_psinfo.3proc	\
		proc_walk.3proc			\
		Psecflags.3proc			\
		Psetbkpt.3proc			\
		Psetcred.3proc			\
		Psetfault.3proc			\
		Psetflags.3proc			\
		Psetpriv.3proc			\
		Psetrun.3proc			\
		Psetsignal.3proc		\
		Psetsysentry.3proc		\
		Psetwapt.3proc			\
		Psetzoneid.3proc		\
		Psignal.3proc			\
		Pstack_iter.3proc		\
		Pstate.3proc			\
		Pstatus.3proc			\
		Pstopstatus.3proc		\
		Psymbol_iter.3proc		\
		Psync.3proc			\
		Psysentry.3proc			\
		Puname.3proc			\
		Pupanic.3proc			\
		Pupdate_maps.3proc		\
		Pupdate_syms.3proc		\
		Pwrite.3proc			\
		Pxecbkpt.3proc			\
		Pzonename.3proc			\
		ps_lgetregs.3proc		\
		ps_pglobal_lookup.3proc		\
		ps_pread.3proc			\
		ps_pstop.3proc

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
