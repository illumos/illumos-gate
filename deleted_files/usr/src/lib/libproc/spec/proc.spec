#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libproc/spec/proc.spec
#
# See the versions file for important information on which version set
# names to use.
#
function	ps_lcontinue
include		<proc_service.h>
declaration	ps_err_e ps_lcontinue(struct ps_prochandle *ph, lwpid_t lwpid)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_lgetfpregs
include		<proc_service.h>
declaration	ps_err_e ps_lgetfpregs(struct ps_prochandle *ph, lwpid_t lwpid, prfpregset_t *fpregset)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_lgetregs
include		<proc_service.h>
declaration	ps_err_e ps_lgetregs(struct ps_prochandle *ph, lwpid_t lwpid, prgregset_t gregset)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_lsetfpregs
include		<proc_service.h>
declaration	ps_err_e ps_lsetfpregs(struct ps_prochandle *ph, lwpid_t lwpid, const prfpregset_t *fpregset)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_lsetregs
include		<proc_service.h>
declaration	ps_err_e ps_lsetregs(struct ps_prochandle *ph, lwpid_t lwpid, const prgregset_t gregset)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_lstop
include		<proc_service.h>
declaration	ps_err_e ps_lstop(struct ps_prochandle *ph, lwpid_t lwpid)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_pauxv
include		<proc_service.h>
declaration	ps_err_e ps_pauxv(struct ps_prochandle *, const auxv_t **)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_pcontinue
include		<proc_service.h>
declaration	ps_err_e ps_pcontinue(struct ps_prochandle *ph)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_pdmodel
include		<proc_service.h>
declaration	ps_err_e ps_pdmodel(struct ps_prochandle *, int *data_model)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_pdread
include		<proc_service.h>
declaration	ps_err_e ps_pdread(struct ps_prochandle *ph, psaddr_t addr, void *buf, size_t size)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_pdwrite
include		<proc_service.h>
declaration	ps_err_e ps_pdwrite(struct ps_prochandle *ph, psaddr_t addr, const void *buf, size_t size)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_pglobal_lookup
include		<proc_service.h>
declaration	ps_err_e ps_pglobal_lookup(struct ps_prochandle *ph, const char *ld_object_name, const char *ld_symbol_name, psaddr_t *ld_symbol_addr)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_pglobal_sym
include		<proc_service.h>
declaration	ps_err_e ps_pglobal_sym(struct ps_prochandle *ph, const char *object_name, const char *sym_name, ps_sym_t *sym)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_plog
include		<proc_service.h>
declaration	void ps_plog(const char *fmt, ...)
version		SUNWprivate_1.1
end

function	ps_pread
include		<proc_service.h>
declaration	ps_err_e ps_pread(struct ps_prochandle *ph, psaddr_t  addr, void *buf, size_t size)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_pstop
include		<proc_service.h>
declaration	ps_err_e ps_pstop(struct ps_prochandle *ph)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_ptread
include		<proc_service.h>
declaration	ps_err_e ps_ptread(struct ps_prochandle *ph, psaddr_t addr, void *buf, size_t size)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_ptwrite
include		<proc_service.h>
declaration	ps_err_e ps_ptwrite(struct ps_prochandle *ph, psaddr_t addr, const void *buf, size_t size)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_pwrite
include		<proc_service.h>
declaration	ps_err_e ps_pwrite(struct ps_prochandle *ph, psaddr_t  addr, const void *buf, size_t size)
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_lgetLDT
include		<proc_service.h>
declaration	ps_err_e ps_lgetLDT(struct ps_prochandle *ph, lwpid_t lwpid, struct ssd *ldt)
arch		i386
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_lgetxregs
include		<proc_service.h>
declaration	ps_err_e ps_lgetxregs(struct ps_prochandle *ph, lwpid_t lid, caddr_t xregset)
arch		sparc sparcv9
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_lgetxregsize
include		<proc_service.h>
declaration	ps_err_e ps_lgetxregsize(struct ps_prochandle *ph, lwpid_t lwpid, int *xregsize)
arch		sparc sparcv9
version		SUNWprivate_1.1
exception	$return != PS_OK
end

function	ps_lsetxregs
include		<proc_service.h>
declaration	ps_err_e ps_lsetxregs(struct ps_prochandle *ph, lwpid_t lwpid, caddr_t xregset)
arch		sparc sparcv9
version		SUNWprivate_1.1
exception	$return != PS_OK
end

data		_libproc_debug
version		SUNWprivate_1.1
end

function	Paddr_to_ctf
version		SUNWprivate_1.1
end

function	Paddr_to_loadobj
version		SUNWprivate_1.1
end

function	Paddr_to_map
version		SUNWprivate_1.1
end

function	Paddr_to_text_map
version		SUNWprivate_1.1
end

function	Pasfd
version		SUNWprivate_1.1
end

function	Pclearfault
version		SUNWprivate_1.1
end

function	Pclearsig
version		SUNWprivate_1.1
end

function	Pcontent
version		SUNWprivate_1.1
end

function	Pcreate
version		SUNWprivate_1.1
end

function	Pcreate_agent
version		SUNWprivate_1.1
end

function	Pcreate_callback
version		SUNWprivate_1.1
end

function	Pcreate_error
version		SUNWprivate_1.1
end

function	Ppriv
version		SUNWprivate_1.1
end

function	Psetpriv
version		SUNWprivate_1.1
end

function	Pprivinfo
version		SUNWprivate_1.1
end

function	Pcred
version		SUNWprivate_1.1
end

function	Pldt
arch		i386
version		SUNWprivate_1.1
end

function	Pctlfd
version		SUNWprivate_1.1
end

function	Pdelbkpt
version		SUNWprivate_1.1
end

function	Pdelwapt
version		SUNWprivate_1.1
end

function	Pdestroy_agent
version		SUNWprivate_1.1
end

function	Penv_iter
version		SUNWprivate_1.1
end

function	Perror_printf
version		SUNWprivate_1.1
end

function	Pexecname
version		SUNWprivate_1.1
end

function	Pfault
version		SUNWprivate_1.1
end

function	Pfgcore
version		SUNWprivate_1.1
end

function	Pfgrab_core
version		SUNWprivate_1.1
end

function	Pfree
version		SUNWprivate_1.1
end

function	Pgcore
version		SUNWprivate_1.1
end

function	Pgetareg
version		SUNWprivate_1.1
end

function	Pgetauxval
version		SUNWprivate_1.1
end

function	Pgetauxvec
version		SUNWprivate_1.1
end

function	Pgetenv
version		SUNWprivate_1.1
end

function	Pgrab
version		SUNWprivate_1.1
end

function	Pgrab_core
version		SUNWprivate_1.1
end

function	Pgrab_error
version		SUNWprivate_1.1
end

function	Pgrab_file
version		SUNWprivate_1.1
end

function	Pisprocdir
version		SUNWprivate_1.1
end

function	Pissyscall_prev
version		SUNWprivate_1.1
end

function	Plmid
version		SUNWprivate_1.1
end

function	Plmid_to_loadobj
version		SUNWprivate_1.1
end

function	Plmid_to_map
version		SUNWprivate_1.1
end

function	Plookup_by_addr
version		SUNWprivate_1.1
end

function	Plookup_by_name
version		SUNWprivate_1.1
end

function	Plwp_alt_stack
version		SUNWprivate_1.1
end

function	Plwp_getasrs
arch		sparcv9
version		SUNWprivate_1.1
end

function	Plwp_getregs
version		SUNWprivate_1.1
end

function	Plwp_getgwindows
arch		sparc sparcv9
version		SUNWprivate_1.1
end

function	Plwp_getxregs
arch		sparc sparcv9
version		SUNWprivate_1.1
end

function	Plwp_getfpregs
version		SUNWprivate_1.1
end

function	Plwp_getpsinfo
version		SUNWprivate_1.1
end

function	Plwp_iter
version		SUNWprivate_1.1
end

function	Plwp_iter_all
version		SUNWprivate_1.1
end

function	Plwp_main_stack
version		SUNWprivate_1.1
end

function	Plwp_setasrs
arch		sparcv9
version		SUNWprivate_1.1
end

function	Plwp_setfpregs
version		SUNWprivate_1.1
end

function	Plwp_setregs
version		SUNWprivate_1.1
end

function	Plwp_setxregs
arch		sparc sparcv9
version		SUNWprivate_1.1
end

function	Plwp_stack
version		SUNWprivate_1.1
end

function	Pmapping_iter
version		SUNWprivate_1.1
end

function	Pname_to_ctf
version		SUNWprivate_1.1
end

function	Pname_to_loadobj
version		SUNWprivate_1.1
end

function	Pname_to_map
version		SUNWprivate_1.1
end

function	Pobject_iter
version		SUNWprivate_1.1
end

function	Pobjname
version		SUNWprivate_1.1
end

function	Pplatform
version		SUNWprivate_1.1
end

function	Ppltdest
version		SUNWprivate_1.1
end

function	Ppsinfo
version		SUNWprivate_1.1
end

function	Pputareg
version		SUNWprivate_1.1
end

function	Prd_agent
version		SUNWprivate_1.1
end

function	Pread
version		SUNWprivate_1.1
end

function	Pread_string
version		SUNWprivate_1.1
end

function	Prelease
version		SUNWprivate_1.1
end

function	Preopen
version		SUNWprivate_1.1
end

function	Preset_maps
version		SUNWprivate_1.1
end

function	Psetbkpt
version		SUNWprivate_1.1
end

function	Psetcred
version		SUNWprivate_1.1
end

function	Psetfault
version		SUNWprivate_1.1
end

function	Psetflags
version		SUNWprivate_1.1
end

function	Psetrun
version		SUNWprivate_1.1
end

function	Psetsignal
version		SUNWprivate_1.1
end

function	Psetsysentry
version		SUNWprivate_1.1
end

function	Psetzoneid
version		SUNWprivate_1.1
end

function	Psetsysexit
version		SUNWprivate_1.1
end

function	Psetwapt
version		SUNWprivate_1.1
end

function	Psignal
version		SUNWprivate_1.1
end

function	Pstack_iter
version		SUNWprivate_1.1
end

function	Pstate
version		SUNWprivate_1.1
end

function	Pstatus
version		SUNWprivate_1.1
end

function	Pstop
version		SUNWprivate_1.1
end

function	Pstopstatus
version		SUNWprivate_1.1
end

function	Pdstop
version		SUNWprivate_1.1
end

function	Psymbol_iter
version		SUNWprivate_1.1
end

function	Psymbol_iter_by_addr
version		SUNWprivate_1.1
end

function	Psymbol_iter_by_lmid
version		SUNWprivate_1.1
end

function	Psymbol_iter_by_name
version		SUNWprivate_1.1
end

function	Psync
version		SUNWprivate_1.1
end

function	Psyscall
version		SUNWprivate_1.1
end

function	Psysentry
version		SUNWprivate_1.1
end

function	Psysexit
version		SUNWprivate_1.1
end

function	Puname
version		SUNWprivate_1.1
end

function	Punsetflags
version		SUNWprivate_1.1
end

function	Pupdate_maps
version		SUNWprivate_1.1
end

function	Pupdate_syms
version		SUNWprivate_1.1
end

function	Pwait
version		SUNWprivate_1.1
end

function	Pwrite
version		SUNWprivate_1.1
end

function	Pxcreate
version		SUNWprivate_1.1
end

function	Pxecbkpt
version		SUNWprivate_1.1
end

function	Pxecwapt
version		SUNWprivate_1.1
end

function	Pxlookup_by_addr
version		SUNWprivate_1.1
end

function	Pxlookup_by_name
version		SUNWprivate_1.1
end

function	Pxsymbol_iter
version		SUNWprivate_1.1
end

function	Pzonename
version		SUNWprivate_1.1
end

function	pr_access
version		SUNWprivate_1.1
end

function	pr_close
version		SUNWprivate_1.1
end

function	pr_creat
version		SUNWprivate_1.1
end

function	pr_door_info
version		SUNWprivate_1.1
end

function	pr_exit
version		SUNWprivate_1.1
end

function	pr_fcntl
version		SUNWprivate_1.1
end

function	pr_fstat
version		SUNWprivate_1.1
end

function	pr_fstat64
version		SUNWprivate_1.1
end

function	pr_fstatvfs
version		SUNWprivate_1.1
end

function	pr_getitimer
version		SUNWprivate_1.1
end

function	pr_getpeername
version		SUNWprivate_1.1
end

function	pr_getprojid
version		SUNWprivate_1.1
end

function	pr_getrctl
version		SUNWprivate_1.1
end

function	pr_getrlimit
version		SUNWprivate_1.1
end

function	pr_getrlimit64
version		SUNWprivate_1.1
end

function	pr_getsockname
version		SUNWprivate_1.1
end

function	pr_getsockopt
declaration	int pr_getsockopt(struct ps_prochandle *Pr, \
	int sock, int level, int optname, void *optval, int *optlen)
version		SUNWprivate_1.1
end

function	pr_getzoneid
version		SUNWprivate_1.1
end

function	pr_gettaskid
version		SUNWprivate_1.1
end

function	pr_ioctl
version		SUNWprivate_1.1
end

function	pr_link
version		SUNWprivate_1.1
end

function	pr_lseek
version		SUNWprivate_1.1
end

function	pr_llseek
version		SUNWprivate_1.1
end

function	pr_lstat
version		SUNWprivate_1.1
end

function	pr_lstat64
version		SUNWprivate_1.1
end

function	pr_lwp_exit
version		SUNWprivate_1.1
end

function	pr_memcntl
version		SUNWprivate_1.1
end

function	pr_meminfo
version		SUNWprivate_1.1
end

function	pr_mmap
version		SUNWprivate_1.1
end

function	pr_munmap
version		SUNWprivate_1.1
end

function	pr_open
version		SUNWprivate_1.1
end

function	pr_processor_bind
version		SUNWprivate_1.1
end

function	pr_pset_bind
version		SUNWprivate_1.1
end

function	pr_rename
version		SUNWprivate_1.1
end

function	pr_setrctl
version		SUNWprivate_1.1
end

function	pr_setitimer
version		SUNWprivate_1.1
end

function	pr_setrlimit
version		SUNWprivate_1.1
end

function	pr_setrlimit64
version		SUNWprivate_1.1
end

function	pr_settaskid
version		SUNWprivate_1.1
end

function	pr_sigaction
version		SUNWprivate_1.1
end

function	pr_stat
version		SUNWprivate_1.1
end

function	pr_stat64
version		SUNWprivate_1.1
end

function	pr_statvfs
version		SUNWprivate_1.1
end

function	pr_unlink
version		SUNWprivate_1.1
end

function	pr_waitid
version		SUNWprivate_1.1
end

function	pr_zmap
version		SUNWprivate_1.1
end

function	proc_arg_grab
version		SUNWprivate_1.1
end

function	proc_arg_xgrab
version		SUNWprivate_1.1
end

function	proc_arg_psinfo
version		SUNWprivate_1.1
end

function	proc_arg_xpsinfo
version		SUNWprivate_1.1
end

function	proc_content2str
version		SUNWprivate_1.1
end

function	proc_finistdio
version		SUNWprivate_1.1
end

function	proc_fltname
version		SUNWprivate_1.1
end

function	proc_fltset2str
version		SUNWprivate_1.1
end

function	proc_flushstdio
version		SUNWprivate_1.1
end

function	proc_get_auxv
version		SUNWprivate_1.1
end

function	proc_get_priv
version		SUNWprivate_1.1
end

function	proc_get_cred
version		SUNWprivate_1.1
end

function	proc_get_ldt
arch		i386
version		SUNWprivate_1.1
end

function	proc_get_psinfo
version		SUNWprivate_1.1
end

function	proc_get_status
version		SUNWprivate_1.1
end

function	proc_initstdio
version		SUNWprivate_1.1
end

function	proc_lwp_in_set
version		SUNWprivate_1.1
end

function	proc_lwp_range_valid
version		SUNWprivate_1.1
end

function	proc_signame
version		SUNWprivate_1.1
end

function	proc_sigset2str
version		SUNWprivate_1.1
end

function	proc_str2content
version		SUNWprivate_1.1
end

function	proc_str2flt
version		SUNWprivate_1.1
end

function	proc_str2fltset
version		SUNWprivate_1.1
end

function	proc_str2sig
version		SUNWprivate_1.1
end

function	proc_str2sigset
version		SUNWprivate_1.1
end

function	proc_str2sys
version		SUNWprivate_1.1
end

function	proc_str2sysset
version		SUNWprivate_1.1
end

function	proc_sysname
version		SUNWprivate_1.1
end

function	proc_sysset2str
version		SUNWprivate_1.1
end

function	proc_unctrl_psinfo
version		SUNWprivate_1.1
end

function	proc_walk
version		SUNWprivate_1.1
end

function	Lalt_stack
version		SUNWprivate_1.1
end

function	Lclearfault
version		SUNWprivate_1.1
end

function	Lclearsig
version		SUNWprivate_1.1
end

function	Lctlfd
version		SUNWprivate_1.1
end

function	Ldstop
version		SUNWprivate_1.1
end

function	Lfree
version		SUNWprivate_1.1
end

function	Lgetareg
version		SUNWprivate_1.1
end

function	Lgrab
version		SUNWprivate_1.1
end

function	Lgrab_error
version		SUNWprivate_1.1
end

function	Lmain_stack
version		SUNWprivate_1.1
end

function	Lprochandle
version		SUNWprivate_1.1
end

function	Lpsinfo
version		SUNWprivate_1.1
end

function	Lputareg
version		SUNWprivate_1.1
end

function	Lsetrun
version		SUNWprivate_1.1
end

function	Lstack
version		SUNWprivate_1.1
end

function	Lstate
version		SUNWprivate_1.1
end

function	Lstatus
version		SUNWprivate_1.1
end

function	Lstop
version		SUNWprivate_1.1
end

function	Lsync
version		SUNWprivate_1.1
end

function	Lwait
version		SUNWprivate_1.1
end

function	Lxecbkpt
version		SUNWprivate_1.1
end

function	Lxecwapt
version		SUNWprivate_1.1
end

