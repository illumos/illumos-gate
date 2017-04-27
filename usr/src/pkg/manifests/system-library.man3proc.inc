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
# Copyright 2015 Joyent, Inc.
#

file path=usr/share/man/man3proc/proc_service.3proc
file path=usr/share/man/man3proc/ps_lgetregs.3proc
file path=usr/share/man/man3proc/ps_pglobal_lookup.3proc
file path=usr/share/man/man3proc/ps_pread.3proc
file path=usr/share/man/man3proc/ps_pstop.3proc
link path=usr/share/man/man3proc/ps_kill.3proc target=ps_pstop.3proc
link path=usr/share/man/man3proc/ps_lcontinue.3proc target=ps_pstop.3proc
link path=usr/share/man/man3proc/ps_lgetfpregs.3proc target=ps_lgetregs.3proc
link path=usr/share/man/man3proc/ps_lgetxregs.3proc target=ps_lgetregs.3proc
link path=usr/share/man/man3proc/ps_lgetxregsize.3proc \
    target=ps_lgetregs.3proc
link path=usr/share/man/man3proc/ps_lrolltoaddr.3proc target=ps_pstop.3proc
link path=usr/share/man/man3proc/ps_lsetfpregs.3proc target=ps_lgetregs.3proc
link path=usr/share/man/man3proc/ps_lsetregs.3proc target=ps_lgetregs.3proc
link path=usr/share/man/man3proc/ps_lsetxregs.3proc target=ps_lgetregs.3proc
link path=usr/share/man/man3proc/ps_lstop.3proc target=ps_pstop.3proc
link path=usr/share/man/man3proc/ps_pcontinue.3proc target=ps_pstop.3proc
link path=usr/share/man/man3proc/ps_pdread.3proc target=ps_pread.3proc
link path=usr/share/man/man3proc/ps_pdwrite.3proc target=ps_pread.3proc
link path=usr/share/man/man3proc/ps_pglobal_sym.3proc \
    target=ps_pglobal_lookup.3proc
link path=usr/share/man/man3proc/ps_ptread.3proc target=ps_pread.3proc
link path=usr/share/man/man3proc/ps_ptwrite.3proc target=ps_pread.3proc
link path=usr/share/man/man3proc/ps_pwrite.3proc target=ps_pread.3proc
file path=usr/share/man/man3proc/Lctlfd.3proc
file path=usr/share/man/man3proc/Lfree.3proc
file path=usr/share/man/man3proc/Lgrab_error.3proc
file path=usr/share/man/man3proc/Lgrab.3proc
file path=usr/share/man/man3proc/Lprochandle.3proc
file path=usr/share/man/man3proc/Lpsinfo.3proc
file path=usr/share/man/man3proc/Lstate.3proc
file path=usr/share/man/man3proc/Lstatus.3proc
file path=usr/share/man/man3proc/Paddr_to_ctf.3proc
file path=usr/share/man/man3proc/Paddr_to_loadobj.3proc
file path=usr/share/man/man3proc/Paddr_to_map.3proc
file path=usr/share/man/man3proc/Pasfd.3proc
file path=usr/share/man/man3proc/Pclearfault.3proc
file path=usr/share/man/man3proc/Pclearsig.3proc
file path=usr/share/man/man3proc/Pcontent.3proc
file path=usr/share/man/man3proc/Pcreate_agent.3proc
file path=usr/share/man/man3proc/Pcreate_error.3proc
file path=usr/share/man/man3proc/Pcreate.3proc
file path=usr/share/man/man3proc/Pcred.3proc
file path=usr/share/man/man3proc/Pctlfd.3proc
file path=usr/share/man/man3proc/Pdelbkpt.3proc
file path=usr/share/man/man3proc/Pdelwapt.3proc
file path=usr/share/man/man3proc/Pdestroy_agent.3proc
file path=usr/share/man/man3proc/Penv_iter.3proc
file path=usr/share/man/man3proc/Perror_printf.3proc
file path=usr/share/man/man3proc/Pexecname.3proc
file path=usr/share/man/man3proc/Pfault.3proc
file path=usr/share/man/man3proc/Pfdinfo_iter.3proc
file path=usr/share/man/man3proc/Pgcore.3proc
file path=usr/share/man/man3proc/Pgetareg.3proc
file path=usr/share/man/man3proc/Pgetauxval.3proc
file path=usr/share/man/man3proc/Pgetauxvec.3proc
file path=usr/share/man/man3proc/Pgetenv.3proc
file path=usr/share/man/man3proc/Pgrab_core.3proc
file path=usr/share/man/man3proc/Pgrab_error.3proc
file path=usr/share/man/man3proc/Pgrab_file.3proc
file path=usr/share/man/man3proc/Pgrab.3proc
file path=usr/share/man/man3proc/Pisprocdir.3proc
file path=usr/share/man/man3proc/Pissyscall.3proc
file path=usr/share/man/man3proc/Pldt.3proc
file path=usr/share/man/man3proc/Plmid.3proc
file path=usr/share/man/man3proc/Plookup_by_addr.3proc
file path=usr/share/man/man3proc/Plwp_getasrs.3proc
file path=usr/share/man/man3proc/Plwp_getgwindows.3proc
file path=usr/share/man/man3proc/Plwp_getpsinfo.3proc
file path=usr/share/man/man3proc/Plwp_getregs.3proc
file path=usr/share/man/man3proc/Plwp_getspymaster.3proc
file path=usr/share/man/man3proc/Plwp_getxregs.3proc
file path=usr/share/man/man3proc/Plwp_iter.3proc
file path=usr/share/man/man3proc/Plwp_stack.3proc
file path=usr/share/man/man3proc/Pmapping_iter.3proc
file path=usr/share/man/man3proc/Pobjname.3proc
file path=usr/share/man/man3proc/Pplatform.3proc
file path=usr/share/man/man3proc/Ppltdest.3proc
file path=usr/share/man/man3proc/Ppriv.3proc
file path=usr/share/man/man3proc/Ppsinfo.3proc
file path=usr/share/man/man3proc/pr_access.3proc
file path=usr/share/man/man3proc/pr_close.3proc
file path=usr/share/man/man3proc/pr_creat.3proc
file path=usr/share/man/man3proc/pr_door_info.3proc
file path=usr/share/man/man3proc/pr_exit.3proc
file path=usr/share/man/man3proc/pr_fcntl.3proc
file path=usr/share/man/man3proc/pr_fstatvfs.3proc
file path=usr/share/man/man3proc/pr_getitimer.3proc
file path=usr/share/man/man3proc/pr_getpeername.3proc
file path=usr/share/man/man3proc/pr_getpeerucred.3proc
file path=usr/share/man/man3proc/pr_getprojid.3proc
file path=usr/share/man/man3proc/pr_getrctl.3proc
file path=usr/share/man/man3proc/pr_getrlimit.3proc
file path=usr/share/man/man3proc/pr_getsockname.3proc
file path=usr/share/man/man3proc/pr_getsockopt.3proc
file path=usr/share/man/man3proc/pr_gettaskid.3proc
file path=usr/share/man/man3proc/pr_getzoneid.3proc
file path=usr/share/man/man3proc/pr_ioctl.3proc
file path=usr/share/man/man3proc/pr_link.3proc
file path=usr/share/man/man3proc/pr_llseek.3proc
file path=usr/share/man/man3proc/pr_lseek.3proc
file path=usr/share/man/man3proc/pr_memcntl.3proc
file path=usr/share/man/man3proc/pr_meminfo.3proc
file path=usr/share/man/man3proc/pr_mmap.3proc
file path=usr/share/man/man3proc/pr_munmap.3proc
file path=usr/share/man/man3proc/pr_open.3proc
file path=usr/share/man/man3proc/pr_processor_bind.3proc
file path=usr/share/man/man3proc/pr_rename.3proc
file path=usr/share/man/man3proc/pr_setitimer.3proc
file path=usr/share/man/man3proc/pr_setrctl.3proc
file path=usr/share/man/man3proc/pr_setrlimit.3proc
file path=usr/share/man/man3proc/pr_settaskid.3proc
file path=usr/share/man/man3proc/pr_sigaction.3proc
file path=usr/share/man/man3proc/pr_stat.3proc
file path=usr/share/man/man3proc/pr_statvfs.3proc
file path=usr/share/man/man3proc/pr_unlink.3proc
file path=usr/share/man/man3proc/pr_waitid.3proc
file path=usr/share/man/man3proc/Prd_agent.3proc
file path=usr/share/man/man3proc/Pread.3proc
file path=usr/share/man/man3proc/Prelease.3proc
file path=usr/share/man/man3proc/Preopen.3proc
file path=usr/share/man/man3proc/Preset_maps.3proc
file path=usr/share/man/man3proc/proc_arg_grab.3proc
file path=usr/share/man/man3proc/proc_arg_psinfo.3proc
file path=usr/share/man/man3proc/proc_content2str.3proc
file path=usr/share/man/man3proc/proc_fltname.3proc
file path=usr/share/man/man3proc/proc_fltset2str.3proc
file path=usr/share/man/man3proc/proc_get_auxv.3proc
file path=usr/share/man/man3proc/proc_get_cred.3proc
file path=usr/share/man/man3proc/proc_get_priv.3proc
file path=usr/share/man/man3proc/proc_get_psinfo.3proc
file path=usr/share/man/man3proc/proc_get_status.3proc
file path=usr/share/man/man3proc/proc_initstdio.3proc
file path=usr/share/man/man3proc/proc_lwp_in_set.3proc
file path=usr/share/man/man3proc/proc_str2flt.3proc
file path=usr/share/man/man3proc/proc_str2fltset.3proc
file path=usr/share/man/man3proc/proc_unctrl_psinfo.3proc
file path=usr/share/man/man3proc/proc_walk.3proc
file path=usr/share/man/man3proc/Psecflags.3proc
file path=usr/share/man/man3proc/Psetbkpt.3proc
file path=usr/share/man/man3proc/Psetcred.3proc
file path=usr/share/man/man3proc/Psetfault.3proc
file path=usr/share/man/man3proc/Psetflags.3proc
file path=usr/share/man/man3proc/Psetpriv.3proc
file path=usr/share/man/man3proc/Psetrun.3proc
file path=usr/share/man/man3proc/Psetsignal.3proc
file path=usr/share/man/man3proc/Psetsysentry.3proc
file path=usr/share/man/man3proc/Psetwapt.3proc
file path=usr/share/man/man3proc/Psetzoneid.3proc
file path=usr/share/man/man3proc/Psignal.3proc
file path=usr/share/man/man3proc/Pstack_iter.3proc
file path=usr/share/man/man3proc/Pstate.3proc
file path=usr/share/man/man3proc/Pstatus.3proc
file path=usr/share/man/man3proc/Pstopstatus.3proc
file path=usr/share/man/man3proc/Psymbol_iter.3proc
file path=usr/share/man/man3proc/Psync.3proc
file path=usr/share/man/man3proc/Psysentry.3proc
file path=usr/share/man/man3proc/Puname.3proc
file path=usr/share/man/man3proc/Pupdate_maps.3proc
file path=usr/share/man/man3proc/Pupdate_syms.3proc
file path=usr/share/man/man3proc/Pwrite.3proc
file path=usr/share/man/man3proc/Pxecbkpt.3proc
file path=usr/share/man/man3proc/Pzonename.3proc
link path=usr/share/man/man3proc/Lalt_stack.3proc target=Plwp_stack.3proc
link path=usr/share/man/man3proc/Lclearfault.3proc target=Pclearfault.3proc
link path=usr/share/man/man3proc/Lclearsig.3proc target=Pclearsig.3proc
link path=usr/share/man/man3proc/Ldstop.3proc target=Pstopstatus.3proc
link path=usr/share/man/man3proc/Lgetareg.3proc target=Pgetareg.3proc
link path=usr/share/man/man3proc/Lmain_stack.3proc target=Plwp_stack.3proc
link path=usr/share/man/man3proc/Lputareg.3proc target=Pgetareg.3proc
link path=usr/share/man/man3proc/Lsetrun.3proc target=Psetrun.3proc
link path=usr/share/man/man3proc/Lstack.3proc target=Plwp_stack.3proc
link path=usr/share/man/man3proc/Lstop.3proc target=Pstopstatus.3proc
link path=usr/share/man/man3proc/Lsync.3proc target=Psync.3proc
link path=usr/share/man/man3proc/Lwait.3proc target=Pstopstatus.3proc
link path=usr/share/man/man3proc/Lxecbkpt.3proc target=Pxecbkpt.3proc
link path=usr/share/man/man3proc/Lxecwapt.3proc target=Pxecbkpt.3proc
link path=usr/share/man/man3proc/Paddr_to_text_map.3proc target=Paddr_to_map.3proc
link path=usr/share/man/man3proc/Pcreate_callback.3proc target=Pcreate.3proc
link path=usr/share/man/man3proc/Pdstop.3proc target=Pstopstatus.3proc
link path=usr/share/man/man3proc/Pfgcore.3proc target=Pgcore.3proc
link path=usr/share/man/man3proc/Pfgrab_core.3proc target=Pgrab_core.3proc
link path=usr/share/man/man3proc/Pfree.3proc target=Prelease.3proc
link path=usr/share/man/man3proc/Pissyscall_prev.3proc target=Pissyscall.3proc
link path=usr/share/man/man3proc/Plmid_to_ctf.3proc target=Paddr_to_ctf.3proc
link path=usr/share/man/man3proc/Plmid_to_loadobj.3proc target=Paddr_to_loadobj.3proc
link path=usr/share/man/man3proc/Plmid_to_map.3proc target=Paddr_to_map.3proc
link path=usr/share/man/man3proc/Plookup_by_name.3proc target=Plookup_by_addr.3proc
link path=usr/share/man/man3proc/Plwp_alt_stack.3proc target=Plwp_stack.3proc
link path=usr/share/man/man3proc/Plwp_getfpregs.3proc target=Plwp_getregs.3proc
link path=usr/share/man/man3proc/Plwp_iter_all.3proc target=Plwp_iter.3proc
link path=usr/share/man/man3proc/Plwp_main_stack.3proc target=Plwp_stack.3proc
link path=usr/share/man/man3proc/Plwp_setasrs.3proc target=Plwp_getasrs.3proc
link path=usr/share/man/man3proc/Plwp_setfpregs.3proc target=Plwp_getregs.3proc
link path=usr/share/man/man3proc/Plwp_setregs.3proc target=Plwp_getregs.3proc
link path=usr/share/man/man3proc/Plwp_setxregs.3proc target=Plwp_getxregs.3proc
link path=usr/share/man/man3proc/Pmapping_iter_resolved.3proc target=Pmapping_iter.3proc
link path=usr/share/man/man3proc/Pname_to_ctf.3proc target=Paddr_to_ctf.3proc
link path=usr/share/man/man3proc/Pname_to_loadobj.3proc target=Paddr_to_loadobj.3proc
link path=usr/share/man/man3proc/Pname_to_map.3proc target=Paddr_to_map.3proc
link path=usr/share/man/man3proc/Pobject_iter_resolved.3proc target=Pmapping_iter.3proc
link path=usr/share/man/man3proc/Pobject_iter.3proc target=Pmapping_iter.3proc
link path=usr/share/man/man3proc/Pobjname_resolved.3proc target=Pobjname.3proc
link path=usr/share/man/man3proc/Ppriv_free.3proc target=Ppriv.3proc
link path=usr/share/man/man3proc/Pputareg.3proc target=Pgetareg.3proc
link path=usr/share/man/man3proc/pr_fstat.3proc target=pr_stat.3proc
link path=usr/share/man/man3proc/pr_fstat64.3proc target=pr_stat.3proc
link path=usr/share/man/man3proc/pr_getrlimit64.3proc target=pr_getrlimit.3proc
link path=usr/share/man/man3proc/pr_lstat.3proc target=pr_stat.3proc
link path=usr/share/man/man3proc/pr_lstat64.3proc target=pr_stat.3proc
link path=usr/share/man/man3proc/pr_setrlimit64.3proc target=pr_setrlimit.3proc
link path=usr/share/man/man3proc/pr_stat64.3proc target=pr_stat.3proc
link path=usr/share/man/man3proc/Pread_string.3proc target=Pread.3proc
link path=usr/share/man/man3proc/proc_arg_xgrab.3proc target=proc_arg_grab.3proc
link path=usr/share/man/man3proc/proc_arg_xpsinfo.3proc target=proc_arg_psinfo.3proc
link path=usr/share/man/man3proc/proc_finistdio.3proc target=proc_initstdio.3proc
link path=usr/share/man/man3proc/proc_flushstdio.3proc target=proc_initstdio.3proc
link path=usr/share/man/man3proc/proc_free_priv.3proc target=proc_get_priv.3proc
link path=usr/share/man/man3proc/proc_get_ldt.3proc target=Pldt.3proc
link path=usr/share/man/man3proc/proc_lwp_range_valid.3proc target=proc_lwp_in_set.3proc
link path=usr/share/man/man3proc/proc_signame.3proc target=proc_fltname.3proc
link path=usr/share/man/man3proc/proc_sigset2str.3proc target=proc_fltset2str.3proc
link path=usr/share/man/man3proc/proc_str2content.3proc target=proc_content2str.3proc
link path=usr/share/man/man3proc/proc_str2sig.3proc target=proc_str2flt.3proc
link path=usr/share/man/man3proc/proc_str2sigset.3proc target=proc_str2fltset.3proc
link path=usr/share/man/man3proc/proc_str2sys.3proc target=proc_str2flt.3proc
link path=usr/share/man/man3proc/proc_str2sysset.3proc target=proc_str2fltset.3proc
link path=usr/share/man/man3proc/proc_sysname.3proc target=proc_fltname.3proc
link path=usr/share/man/man3proc/proc_sysset2str.3proc target=proc_fltset2str.3proc
link path=usr/share/man/man3proc/Psetsysexit.3proc target=Psetsysentry.3proc
link path=usr/share/man/man3proc/Pstop.3proc target=Pstopstatus.3proc
link path=usr/share/man/man3proc/Psymbol_iter_by_addr.3proc target=Psymbol_iter.3proc
link path=usr/share/man/man3proc/Psymbol_iter_by_lmid.3proc target=Psymbol_iter.3proc
link path=usr/share/man/man3proc/Psymbol_iter_by_name.3proc target=Psymbol_iter.3proc
link path=usr/share/man/man3proc/Psysexit.3proc target=Psysentry.3proc
link path=usr/share/man/man3proc/Punsetflags.3proc target=Psetflags.3proc
link path=usr/share/man/man3proc/Pwait.3proc target=Pstopstatus.3proc
link path=usr/share/man/man3proc/Pxcreate.3proc target=Pcreate.3proc
link path=usr/share/man/man3proc/Pxecwapt.3proc target=Pxecbkpt.3proc
link path=usr/share/man/man3proc/Pxlookup_by_addr_resolved.3proc target=Plookup_by_addr.3proc
link path=usr/share/man/man3proc/Pxlookup_by_addr.3proc target=Plookup_by_addr.3proc
link path=usr/share/man/man3proc/Pxlookup_by_name.3proc target=Plookup_by_addr.3proc
link path=usr/share/man/man3proc/Pxsymbol_iter.3proc target=Psymbol_iter.3proc
link path=usr/share/man/man3proc/Pzonepath.3proc target=Pzonename.3proc
link path=usr/share/man/man3proc/Pzoneroot.3proc target=Pzonename.3proc
