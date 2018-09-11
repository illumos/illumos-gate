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
# Copyright 2015 Joyent, Inc.
#

include		$(SRC)/Makefile.master

MANSECT= 	3proc

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
		proc_fltname.3proc		\
		proc_fltset2str.3proc		\
		proc_get_auxv.3proc		\
		proc_get_cred.3proc		\
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
		Pupdate_maps.3proc		\
		Pupdate_syms.3proc		\
		Pwrite.3proc			\
		Pxecbkpt.3proc			\
		Pzonename.3proc			\
	 	ps_lgetregs.3proc		\
	 	ps_pglobal_lookup.3proc		\
	 	ps_pread.3proc			\
	 	ps_pstop.3proc


MANLINKS=					\
		Lalt_stack.3proc		\
		Lclearfault.3proc		\
		Lclearsig.3proc			\
		Ldstop.3proc			\
		Lgetareg.3proc			\
		Lmain_stack.3proc		\
		Lputareg.3proc			\
		Lsetrun.3proc			\
		Lstack.3proc			\
		Lstop.3proc			\
		Lsync.3proc			\
		Lwait.3proc			\
		Lxecbkpt.3proc			\
		Lxecwapt.3proc			\
		Paddr_to_text_map.3proc		\
		Pcreate_callback.3proc		\
		Pdstop.3proc			\
		Pfgcore.3proc			\
		Pfgrab_core.3proc		\
		Pfree.3proc			\
		Pissyscall_prev.3proc		\
		Plmid_to_ctf.3proc		\
		Plmid_to_loadobj.3proc		\
		Plmid_to_map.3proc		\
		Plookup_by_name.3proc		\
		Plwp_alt_stack.3proc		\
		Plwp_getfpregs.3proc		\
		Plwp_iter_all.3proc		\
		Plwp_main_stack.3proc		\
		Plwp_setasrs.3proc		\
		Plwp_setfpregs.3proc		\
		Plwp_setregs.3proc		\
		Plwp_setxregs.3proc		\
		Pmapping_iter_resolved.3proc	\
		Pname_to_ctf.3proc		\
		Pname_to_loadobj.3proc		\
		Pname_to_map.3proc		\
		Pobject_iter_resolved.3proc	\
		Pobject_iter.3proc		\
		Pobjname_resolved.3proc		\
		Ppriv_free.3proc		\
		Pputareg.3proc			\
		pr_fstat.3proc			\
		pr_fstat64.3proc		\
		pr_getrlimit64.3proc		\
		pr_lstat.3proc			\
		pr_lstat64.3proc		\
		pr_setrlimit64.3proc		\
		pr_stat64.3proc			\
		Pread_string.3proc		\
		proc_arg_xgrab.3proc		\
		proc_arg_xpsinfo.3proc		\
		proc_finistdio.3proc		\
		proc_flushstdio.3proc		\
		proc_free_priv.3proc		\
		proc_get_ldt.3proc		\
		proc_lwp_range_valid.3proc	\
		proc_signame.3proc		\
		proc_sigset2str.3proc		\
		proc_str2content.3proc		\
		proc_str2sig.3proc		\
		proc_str2sigset.3proc		\
		proc_str2sys.3proc		\
		proc_str2sysset.3proc		\
		proc_sysname.3proc		\
		proc_sysset2str.3proc		\
		ps_kill.3proc			\
		ps_lcontinue.3proc		\
		ps_lgetfpregs.3proc		\
		ps_lgetxregs.3proc		\
		ps_lgetxregsize.3proc		\
		ps_lrolltoaddr.3proc		\
		ps_lsetfpregs.3proc		\
		ps_lsetregs.3proc		\
		ps_lsetxregs.3proc		\
		ps_lstop.3proc			\
		ps_pcontinue.3proc		\
		ps_pdread.3proc			\
		ps_pdwrite.3proc		\
		ps_pglobal_sym.3proc		\
		ps_ptread.3proc			\
		ps_ptwrite.3proc		\
		ps_pwrite.3proc			\
		Psetsysexit.3proc		\
		Pstop.3proc			\
		Psymbol_iter_by_addr.3proc	\
		Psymbol_iter_by_lmid.3proc	\
		Psymbol_iter_by_name.3proc	\
		Psysexit.3proc			\
		Punsetflags.3proc		\
		Pwait.3proc			\
		Pxcreate.3proc			\
		Pxecwapt.3proc			\
		Pxlookup_by_addr_resolved.3proc	\
		Pxlookup_by_addr.3proc		\
		Pxlookup_by_name.3proc		\
		Pxsymbol_iter.3proc		\
		Pzonepath.3proc			\
		Pzoneroot.3proc			


ps_lgetfpregs.3proc		:= LINKSRC = ps_lgetregs.3proc
ps_lgetxregs.3proc		:= LINKSRC = ps_lgetregs.3proc
ps_lgetxregsize.3proc		:= LINKSRC = ps_lgetregs.3proc
ps_lsetfpregs.3proc		:= LINKSRC = ps_lgetregs.3proc
ps_lsetregs.3proc		:= LINKSRC = ps_lgetregs.3proc
ps_lsetxregs.3proc		:= LINKSRC = ps_lgetregs.3proc

ps_pglobal_sym.3proc		:= LINKSRC = ps_pglobal_lookup.3proc

ps_pdread.3proc			:= LINKSRC = ps_pread.3proc
ps_pdwrite.3proc		:= LINKSRC = ps_pread.3proc
ps_ptread.3proc			:= LINKSRC = ps_pread.3proc
ps_ptwrite.3proc		:= LINKSRC = ps_pread.3proc
ps_pwrite.3proc			:= LINKSRC = ps_pread.3proc

ps_kill.3proc			:= LINKSRC = ps_pstop.3proc
ps_lcontinue.3proc		:= LINKSRC = ps_pstop.3proc
ps_lrolltoaddr.3proc		:= LINKSRC = ps_pstop.3proc
ps_lstop.3proc			:= LINKSRC = ps_pstop.3proc
ps_pcontinue.3proc		:= LINKSRC = ps_pstop.3proc


Pxcreate.3proc			:= LINKSRC = Pcreate.3proc
Pcreate_callback.3proc		:= LINKSRC = Pcreate.3proc

Pfgrab_core.3proc		:= LINKSRC = Pgrab_core.3proc

Pfree.3proc			:= LINKSRC = Prelease.3proc

Plwp_iter_all.3proc		:= LINKSRC = Plwp_iter.3proc

Pmapping_iter_resolved.3proc	:= LINKSRC = Pmapping_iter.3proc
Pobject_iter.3proc		:= LINKSRC = Pmapping_iter.3proc
Pobject_iter_resolved.3proc	:= LINKSRC = Pmapping_iter.3proc

Psymbol_iter_by_addr.3proc	:= LINKSRC = Psymbol_iter.3proc
Psymbol_iter_by_lmid.3proc	:= LINKSRC = Psymbol_iter.3proc
Psymbol_iter_by_name.3proc	:= LINKSRC = Psymbol_iter.3proc
Pxsymbol_iter.3proc		:= LINKSRC = Psymbol_iter.3proc

Plmid_to_ctf.3proc		:= LINKSRC = Paddr_to_ctf.3proc
Pname_to_ctf.3proc		:= LINKSRC = Paddr_to_ctf.3proc

Plmid_to_loadobj.3proc		:= LINKSRC = Paddr_to_loadobj.3proc
Pname_to_loadobj.3proc		:= LINKSRC = Paddr_to_loadobj.3proc

Paddr_to_text_map.3proc		:= LINKSRC = Paddr_to_map.3proc
Plmid_to_map.3proc		:= LINKSRC = Paddr_to_map.3proc
Pname_to_map.3proc		:= LINKSRC = Paddr_to_map.3proc

Pdstop.3proc			:= LINKSRC = Pstopstatus.3proc
Pstop.3proc			:= LINKSRC = Pstopstatus.3proc
Pwait.3proc			:= LINKSRC = Pstopstatus.3proc
Ldstop.3proc			:= LINKSRC = Pstopstatus.3proc
Lstop.3proc			:= LINKSRC = Pstopstatus.3proc
Lwait.3proc			:= LINKSRC = Pstopstatus.3proc

Lsync.3proc			:= LINKSRC = Psync.3proc

Pfgcore.3proc			:= LINKSRC = Pgcore.3proc

Pputareg.3proc			:= LINKSRC = Pgetareg.3proc
Lgetareg.3proc			:= LINKSRC = Pgetareg.3proc
Lputareg.3proc			:= LINKSRC = Pgetareg.3proc

Pissyscall_prev.3proc		:= LINKSRC = Pissyscall.3proc

Pxlookup_by_addr.3proc		:= LINKSRC = Plookup_by_addr.3proc
Pxlookup_by_addr_resolved.3proc	:= LINKSRC = Plookup_by_addr.3proc
Plookup_by_name.3proc		:= LINKSRC = Plookup_by_addr.3proc
Pxlookup_by_name.3proc		:= LINKSRC = Plookup_by_addr.3proc

Plwp_setregs.3proc		:= LINKSRC = Plwp_getregs.3proc
Plwp_getfpregs.3proc		:= LINKSRC = Plwp_getregs.3proc
Plwp_setfpregs.3proc		:= LINKSRC = Plwp_getregs.3proc

Plwp_alt_stack.3proc		:= LINKSRC = Plwp_stack.3proc
Plwp_main_stack.3proc		:= LINKSRC = Plwp_stack.3proc
Lalt_stack.3proc		:= LINKSRC = Plwp_stack.3proc
Lmain_stack.3proc		:= LINKSRC = Plwp_stack.3proc
Lstack.3proc			:= LINKSRC = Plwp_stack.3proc

Pobjname_resolved.3proc		:= LINKSRC = Pobjname.3proc

Ppriv_free.3proc		:= LINKSRC = Ppriv.3proc

Pread_string.3proc		:= LINKSRC = Pread.3proc

Punsetflags.3proc		:= LINKSRC = Psetflags.3proc

Psetsysexit.3proc		:= LINKSRC = Psetsysentry.3proc

Psysexit.3proc			:= LINKSRC = Psysentry.3proc

Pxecwapt.3proc			:= LINKSRC = Pxecbkpt.3proc
Lxecbkpt.3proc			:= LINKSRC = Pxecbkpt.3proc
Lxecwapt.3proc			:= LINKSRC = Pxecbkpt.3proc

Lclearfault.3proc		:= LINKSRC = Pclearfault.3proc

Lclearsig.3proc			:= LINKSRC = Pclearsig.3proc

Lsetrun.3proc			:= LINKSRC = Psetrun.3proc

Pzonepath.3proc			:= LINKSRC = Pzonename.3proc
Pzoneroot.3proc			:= LINKSRC = Pzonename.3proc

pr_fstat.3proc			:= LINKSRC = pr_stat.3proc
pr_fstat64.3proc		:= LINKSRC = pr_stat.3proc
pr_lstat.3proc			:= LINKSRC = pr_stat.3proc
pr_lstat64.3proc		:= LINKSRC = pr_stat.3proc
pr_stat64.3proc			:= LINKSRC = pr_stat.3proc

pr_getrlimit64.3proc		:= LINKSRC = pr_getrlimit.3proc

pr_setrlimit64.3proc		:= LINKSRC = pr_setrlimit.3proc

proc_arg_xgrab.3proc		:= LINKSRC = proc_arg_grab.3proc

proc_arg_xpsinfo.3proc		:= LINKSRC = proc_arg_psinfo.3proc

proc_str2content.3proc		:= LINKSRC = proc_content2str.3proc

proc_flushstdio.3proc		:= LINKSRC = proc_initstdio.3proc
proc_finistdio.3proc		:= LINKSRC = proc_initstdio.3proc

proc_signame.3proc		:= LINKSRC = proc_fltname.3proc
proc_sysname.3proc		:= LINKSRC = proc_fltname.3proc

proc_sigset2str.3proc		:= LINKSRC = proc_fltset2str.3proc
proc_sysset2str.3proc		:= LINKSRC = proc_fltset2str.3proc

proc_free_priv.3proc		:= LINKSRC = proc_get_priv.3proc

proc_lwp_range_valid.3proc	:= LINKSRC = proc_lwp_in_set.3proc

proc_str2sig.3proc		:= LINKSRC = proc_str2flt.3proc
proc_str2sys.3proc		:= LINKSRC = proc_str2flt.3proc

proc_str2sigset.3proc		:= LINKSRC = proc_str2fltset.3proc
proc_str2sysset.3proc		:= LINKSRC = proc_str2fltset.3proc

proc_get_ldt.3proc		:= LINKSRC = Pldt.3proc

Plwp_setxregs.3proc		:= LINKSRC = Plwp_getxregs.3proc

Plwp_setasrs.3proc		:= LINKSRC = Plwp_getasrs.3proc

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
