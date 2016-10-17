/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 */
#include <struct_layout.h>


static const sl_auxv_layout_t auxv_layout = {
	{ 0,	8,	0,	0 },		/* sizeof (auxv_t) */
	{ 0,	4,	0,	1 },		/* a_type */
	{ 4,	4,	0,	1 },		/* a_un.a_val */
	{ 4,	4,	0,	0 },		/* a_un.a_ptr */
	{ 4,	4,	0,	0 },		/* a_un.a_fcn */
};


static const sl_prgregset_layout_t prgregset_layout = {
	{ 0,	152,	0,	0 },		/* sizeof (prgregset_t) */
	{ 0,	4,	38,	0 },		/* elt0 */
};


static const sl_lwpstatus_layout_t lwpstatus_layout = {
	{ 0,	896,	0,	0 },		/* sizeof (lwpstatus_t) */
	{ 0,	4,	0,	0 },		/* pr_flags */
	{ 4,	4,	0,	0 },		/* pr_lwpid */
	{ 8,	2,	0,	0 },		/* pr_why */
	{ 10,	2,	0,	0 },		/* pr_what */
	{ 12,	2,	0,	0 },		/* pr_cursig */
	{ 16,	128,	0,	0 },		/* pr_info */
	{ 144,	16,	0,	0 },		/* pr_lwppend */
	{ 160,	16,	0,	0 },		/* pr_lwphold */
	{ 176,	32,	0,	0 },		/* pr_action */
	{ 208,	12,	0,	0 },		/* pr_altstack */
	{ 220,	4,	0,	0 },		/* pr_oldcontext */
	{ 224,	2,	0,	0 },		/* pr_syscall */
	{ 226,	2,	0,	0 },		/* pr_nsysarg */
	{ 228,	4,	0,	0 },		/* pr_errno */
	{ 232,	4,	8,	0 },		/* pr_sysarg[] */
	{ 264,	4,	0,	0 },		/* pr_rval1 */
	{ 268,	4,	0,	0 },		/* pr_rval2 */
	{ 272,	1,	8,	0 },		/* pr_clname[] */
	{ 280,	8,	0,	0 },		/* pr_tstamp */
	{ 288,	8,	0,	0 },		/* pr_utime */
	{ 296,	8,	0,	0 },		/* pr_stime */
	{ 332,	4,	0,	0 },		/* pr_errpriv */
	{ 336,	4,	0,	0 },		/* pr_ustack */
	{ 340,	4,	0,	0 },		/* pr_instr */
	{ 344,	152,	0,	0 },		/* pr_reg */
	{ 496,	400,	0,	0 },		/* pr_fpreg */
};


static const sl_pstatus_layout_t pstatus_layout = {
	{ 0,	1232,	0,	0 },		/* sizeof (pstatus_t) */
	{ 0,	4,	0,	1 },		/* pr_flags */
	{ 4,	4,	0,	1 },		/* pr_nlwp */
	{ 8,	4,	0,	0 },		/* pr_pid */
	{ 12,	4,	0,	0 },		/* pr_ppid */
	{ 16,	4,	0,	0 },		/* pr_pgid */
	{ 20,	4,	0,	0 },		/* pr_sid */
	{ 24,	4,	0,	1 },		/* pr_aslwpid */
	{ 28,	4,	0,	1 },		/* pr_agentid */
	{ 32,	16,	0,	0 },		/* pr_sigpend */
	{ 48,	4,	0,	0 },		/* pr_brkbase */
	{ 52,	4,	0,	0 },		/* pr_brksize */
	{ 56,	4,	0,	0 },		/* pr_stkbase */
	{ 60,	4,	0,	0 },		/* pr_stksize */
	{ 64,	8,	0,	0 },		/* pr_utime */
	{ 72,	8,	0,	0 },		/* pr_stime */
	{ 80,	8,	0,	0 },		/* pr_cutime */
	{ 88,	8,	0,	0 },		/* pr_cstime */
	{ 96,	16,	0,	0 },		/* pr_sigtrace */
	{ 112,	16,	0,	0 },		/* pr_flttrace */
	{ 128,	64,	0,	0 },		/* pr_sysentry */
	{ 192,	64,	0,	0 },		/* pr_sysexit */
	{ 256,	1,	0,	0 },		/* pr_dmodel */
	{ 260,	4,	0,	1 },		/* pr_taskid */
	{ 264,	4,	0,	1 },		/* pr_projid */
	{ 268,	4,	0,	1 },		/* pr_nzomb */
	{ 272,	4,	0,	1 },		/* pr_zoneid */
	{ 336,	896,	0,	0 },		/* pr_lwp */
};


static const sl_prstatus_layout_t prstatus_layout = {
	{ 0,	508,	0,	0 },		/* sizeof (prstatus_t) */
	{ 0,	4,	0,	1 },		/* pr_flags */
	{ 4,	2,	0,	1 },		/* pr_why */
	{ 6,	2,	0,	1 },		/* pr_what */
	{ 8,	128,	0,	0 },		/* pr_info */
	{ 136,	2,	0,	1 },		/* pr_cursig */
	{ 138,	2,	0,	0 },		/* pr_nlwp */
	{ 140,	16,	0,	0 },		/* pr_sigpend */
	{ 156,	16,	0,	0 },		/* pr_sighold */
	{ 172,	12,	0,	0 },		/* pr_altstack */
	{ 184,	32,	0,	0 },		/* pr_action */
	{ 216,	4,	0,	0 },		/* pr_pid */
	{ 220,	4,	0,	0 },		/* pr_ppid */
	{ 224,	4,	0,	0 },		/* pr_pgrp */
	{ 228,	4,	0,	0 },		/* pr_sid */
	{ 232,	8,	0,	0 },		/* pr_utime */
	{ 240,	8,	0,	0 },		/* pr_stime */
	{ 248,	8,	0,	0 },		/* pr_cutime */
	{ 256,	8,	0,	0 },		/* pr_cstime */
	{ 264,	1,	8,	0 },		/* pr_clname[] */
	{ 272,	2,	0,	1 },		/* pr_syscall */
	{ 274,	2,	0,	1 },		/* pr_nsysarg */
	{ 276,	4,	8,	1 },		/* pr_sysarg[] */
	{ 308,	4,	0,	0 },		/* pr_who */
	{ 312,	16,	0,	0 },		/* pr_lwppend */
	{ 328,	4,	0,	0 },		/* pr_oldcontext */
	{ 332,	4,	0,	0 },		/* pr_brkbase */
	{ 336,	4,	0,	0 },		/* pr_brksize */
	{ 340,	4,	0,	0 },		/* pr_stkbase */
	{ 344,	4,	0,	0 },		/* pr_stksize */
	{ 348,	2,	0,	1 },		/* pr_processor */
	{ 350,	2,	0,	1 },		/* pr_bind */
	{ 352,	4,	0,	1 },		/* pr_instr */
	{ 356,	152,	0,	0 },		/* pr_reg */
};


static const sl_psinfo_layout_t psinfo_layout = {
	{ 0,	336,	0,	0 },		/* sizeof (psinfo_t) */
	{ 0,	4,	0,	1 },		/* pr_flag */
	{ 4,	4,	0,	1 },		/* pr_nlwp */
	{ 8,	4,	0,	0 },		/* pr_pid */
	{ 12,	4,	0,	0 },		/* pr_ppid */
	{ 16,	4,	0,	0 },		/* pr_pgid */
	{ 20,	4,	0,	0 },		/* pr_sid */
	{ 24,	4,	0,	0 },		/* pr_uid */
	{ 28,	4,	0,	0 },		/* pr_euid */
	{ 32,	4,	0,	0 },		/* pr_gid */
	{ 36,	4,	0,	0 },		/* pr_egid */
	{ 40,	4,	0,	0 },		/* pr_addr */
	{ 44,	4,	0,	0 },		/* pr_size */
	{ 48,	4,	0,	0 },		/* pr_rssize */
	{ 56,	4,	0,	0 },		/* pr_ttydev */
	{ 60,	2,	0,	0 },		/* pr_pctcpu */
	{ 62,	2,	0,	0 },		/* pr_pctmem */
	{ 64,	8,	0,	0 },		/* pr_start */
	{ 72,	8,	0,	0 },		/* pr_time */
	{ 80,	8,	0,	0 },		/* pr_ctime */
	{ 88,	1,	16,	0 },		/* pr_fname[] */
	{ 104,	1,	80,	0 },		/* pr_psargs[] */
	{ 184,	4,	0,	1 },		/* pr_wstat */
	{ 188,	4,	0,	1 },		/* pr_argc */
	{ 192,	4,	0,	0 },		/* pr_argv */
	{ 196,	4,	0,	0 },		/* pr_envp */
	{ 200,	1,	0,	0 },		/* pr_dmodel */
	{ 204,	4,	0,	0 },		/* pr_taskid */
	{ 208,	4,	0,	0 },		/* pr_projid */
	{ 212,	4,	0,	1 },		/* pr_nzomb */
	{ 216,	4,	0,	0 },		/* pr_poolid */
	{ 220,	4,	0,	0 },		/* pr_zoneid */
	{ 224,	4,	0,	0 },		/* pr_contract */
	{ 232,	104,	0,	0 },		/* pr_lwp */
};


static const sl_prpsinfo_layout_t prpsinfo_layout = {
	{ 0,	260,	0,	0 },		/* sizeof (prpsinfo_t) */
	{ 0,	1,	0,	0 },		/* pr_state */
	{ 1,	1,	0,	0 },		/* pr_sname */
	{ 2,	1,	0,	0 },		/* pr_zomb */
	{ 3,	1,	0,	0 },		/* pr_nice */
	{ 4,	4,	0,	0 },		/* pr_flag */
	{ 8,	4,	0,	0 },		/* pr_uid */
	{ 12,	4,	0,	0 },		/* pr_gid */
	{ 16,	4,	0,	0 },		/* pr_pid */
	{ 20,	4,	0,	0 },		/* pr_ppid */
	{ 24,	4,	0,	0 },		/* pr_pgrp */
	{ 28,	4,	0,	0 },		/* pr_sid */
	{ 32,	4,	0,	0 },		/* pr_addr */
	{ 36,	4,	0,	0 },		/* pr_size */
	{ 40,	4,	0,	0 },		/* pr_rssize */
	{ 44,	4,	0,	0 },		/* pr_wchan */
	{ 48,	8,	0,	0 },		/* pr_start */
	{ 56,	8,	0,	0 },		/* pr_time */
	{ 64,	4,	0,	1 },		/* pr_pri */
	{ 68,	1,	0,	0 },		/* pr_oldpri */
	{ 69,	1,	0,	0 },		/* pr_cpu */
	{ 70,	2,	0,	0 },		/* pr_ottydev */
	{ 72,	4,	0,	0 },		/* pr_lttydev */
	{ 76,	1,	8,	0 },		/* pr_clname[] */
	{ 84,	1,	16,	0 },		/* pr_fname[] */
	{ 100,	1,	80,	0 },		/* pr_psargs[] */
	{ 180,	2,	0,	1 },		/* pr_syscall */
	{ 184,	8,	0,	0 },		/* pr_ctime */
	{ 192,	4,	0,	0 },		/* pr_bysize */
	{ 196,	4,	0,	0 },		/* pr_byrssize */
	{ 200,	4,	0,	1 },		/* pr_argc */
	{ 204,	4,	0,	0 },		/* pr_argv */
	{ 208,	4,	0,	0 },		/* pr_envp */
	{ 212,	4,	0,	1 },		/* pr_wstat */
	{ 216,	2,	0,	0 },		/* pr_pctcpu */
	{ 218,	2,	0,	0 },		/* pr_pctmem */
	{ 220,	4,	0,	0 },		/* pr_euid */
	{ 224,	4,	0,	0 },		/* pr_egid */
	{ 228,	4,	0,	0 },		/* pr_aslwpid */
	{ 232,	1,	0,	0 },		/* pr_dmodel */
};


static const sl_lwpsinfo_layout_t lwpsinfo_layout = {
	{ 0,	104,	0,	0 },		/* sizeof (lwpsinfo_t) */
	{ 0,	4,	0,	1 },		/* pr_flag */
	{ 4,	4,	0,	0 },		/* pr_lwpid */
	{ 8,	4,	0,	0 },		/* pr_addr */
	{ 12,	4,	0,	0 },		/* pr_wchan */
	{ 16,	1,	0,	0 },		/* pr_stype */
	{ 17,	1,	0,	0 },		/* pr_state */
	{ 18,	1,	0,	0 },		/* pr_sname */
	{ 19,	1,	0,	0 },		/* pr_nice */
	{ 20,	2,	0,	0 },		/* pr_syscall */
	{ 22,	1,	0,	0 },		/* pr_oldpri */
	{ 23,	1,	0,	0 },		/* pr_cpu */
	{ 24,	4,	0,	1 },		/* pr_pri */
	{ 28,	2,	0,	0 },		/* pr_pctcpu */
	{ 32,	8,	0,	0 },		/* pr_start */
	{ 40,	8,	0,	0 },		/* pr_time */
	{ 48,	1,	8,	0 },		/* pr_clname[] */
	{ 56,	1,	16,	0 },		/* pr_name[] */
	{ 72,	4,	0,	1 },		/* pr_onpro */
	{ 76,	4,	0,	1 },		/* pr_bindpro */
	{ 80,	4,	0,	1 },		/* pr_bindpset */
	{ 84,	4,	0,	1 },		/* pr_lgrp */
};


static const sl_prcred_layout_t prcred_layout = {
	{ 0,	32,	0,	0 },		/* sizeof (prcred_t) */
	{ 0,	4,	0,	0 },		/* pr_euid */
	{ 4,	4,	0,	0 },		/* pr_ruid */
	{ 8,	4,	0,	0 },		/* pr_suid */
	{ 12,	4,	0,	0 },		/* pr_egid */
	{ 16,	4,	0,	0 },		/* pr_rgid */
	{ 20,	4,	0,	0 },		/* pr_sgid */
	{ 24,	4,	0,	1 },		/* pr_ngroups */
	{ 28,	4,	1,	0 },		/* pr_groups[] */
};


static const sl_prpriv_layout_t prpriv_layout = {
	{ 0,	16,	0,	0 },		/* sizeof (prpriv_t) */
	{ 0,	4,	0,	0 },		/* pr_nsets */
	{ 4,	4,	0,	0 },		/* pr_setsize */
	{ 8,	4,	0,	0 },		/* pr_infosize */
	{ 12,	4,	1,	0 },		/* pr_sets[] */
};


static const sl_priv_impl_info_layout_t priv_impl_info_layout = {
	{ 0,	28,	0,	0 },		/* sizeof (priv_impl_info_t) */
	{ 0,	4,	0,	0 },		/* priv_headersize */
	{ 4,	4,	0,	0 },		/* priv_flags */
	{ 8,	4,	0,	0 },		/* priv_nsets */
	{ 12,	4,	0,	0 },		/* priv_setsize */
	{ 16,	4,	0,	0 },		/* priv_max */
	{ 20,	4,	0,	0 },		/* priv_infosize */
	{ 24,	4,	0,	0 },		/* priv_globalinfosize */
};


static const sl_fltset_layout_t fltset_layout = {
	{ 0,	16,	0,	0 },		/* sizeof (fltset_t) */
	{ 0,	4,	4,	0 },		/* word[] */
};


static const sl_siginfo_layout_t siginfo_layout = {
	{ 0,	128,	0,	0 },		/* sizeof (siginfo_t) */
	{ 0,	4,	0,	0 },		/* si_signo */
	{ 8,	4,	0,	0 },		/* si_errno */
	{ 4,	4,	0,	1 },		/* si_code */
	{ 20,	4,	0,	0 },		/* si_value.sival_int */
	{ 20,	4,	0,	0 },		/* si_value.sival_ptr */
	{ 12,	4,	0,	0 },		/* si_pid */
	{ 16,	4,	0,	0 },		/* si_uid */
	{ 28,	4,	0,	0 },		/* si_ctid */
	{ 32,	4,	0,	0 },		/* si_zoneid */
	{ 12,	4,	0,	0 },		/* si_entity */
	{ 12,	4,	0,	0 },		/* si_addr */
	{ 20,	4,	0,	0 },		/* si_status */
	{ 16,	4,	0,	0 },		/* si_band */
};


static const sl_sigset_layout_t sigset_layout = {
	{ 0,	16,	0,	0 },		/* sizeof (sigset_t) */
	{ 0,	4,	4,	0 },		/* __sigbits[] */
};


static const sl_sigaction_layout_t sigaction_layout = {
	{ 0,	32,	0,	0 },		/* sizeof (struct sigaction) */
	{ 0,	4,	0,	0 },		/* sa_flags */
	{ 4,	4,	0,	0 },		/* sa_handler */
	{ 4,	4,	0,	0 },		/* sa_sigaction */
	{ 8,	16,	0,	0 },		/* sa_mask */
};


static const sl_stack_layout_t stack_layout = {
	{ 0,	12,	0,	0 },		/* sizeof (stack_t) */
	{ 0,	4,	0,	0 },		/* ss_sp */
	{ 4,	4,	0,	0 },		/* ss_size */
	{ 8,	4,	0,	0 },		/* ss_flags */
};


static const sl_sysset_layout_t sysset_layout = {
	{ 0,	64,	0,	0 },		/* sizeof (sysset_t) */
	{ 0,	4,	16,	0 },		/* word[] */
};


static const sl_timestruc_layout_t timestruc_layout = {
	{ 0,	8,	0,	0 },		/* sizeof (timestruc_t) */
	{ 0,	4,	0,	0 },		/* tv_sec */
	{ 4,	4,	0,	0 },		/* tv_nsec */
};


static const sl_utsname_layout_t utsname_layout = {
	{ 0,	1285,	0,	0 },		/* sizeof (struct utsname) */
	{ 0,	1,	257,	0 },		/* sysname[] */
	{ 257,	1,	257,	0 },		/* nodename[] */
	{ 514,	1,	257,	0 },		/* release[] */
	{ 771,	1,	257,	0 },		/* version[] */
	{ 1028,	1,	257,	0 },		/* machine[] */
};


static const sl_prfdinfo_layout_t prfdinfo_layout = {
	{ 0,	1088,	0,	0 },		/* sizeof (prfdinfo_t) */
	{ 0,	4,	0,	0 },		/* pr_fd */
	{ 4,	4,	0,	0 },		/* pr_mode */
	{ 8,	4,	0,	0 },		/* pr_uid */
	{ 12,	4,	0,	0 },		/* pr_gid */
	{ 16,	4,	0,	0 },		/* pr_major */
	{ 20,	4,	0,	0 },		/* pr_minor */
	{ 24,	4,	0,	0 },		/* pr_rmajor */
	{ 28,	4,	0,	0 },		/* pr_rminor */
	{ 32,	8,	0,	0 },		/* pr_ino */
	{ 40,	8,	0,	0 },		/* pr_offset */
	{ 48,	8,	0,	0 },		/* pr_size */
	{ 56,	4,	0,	0 },		/* pr_fileflags */
	{ 60,	4,	0,	0 },		/* pr_fdflags */
	{ 64,	1,	1024,	0 },		/* pr_path[] */
};


static const sl_prsecflags_layout_t prsecflags_layout = {
	{ 0,	40,	0,	0 },		 /* sizeof (prsecflags_t) */
	{ 0,	4,	0,	0 },		 /* pr_version */
	{ 8,	8,	0,	0 },		 /* pr_effective */
	{ 16,	8,	0,	0 },		 /* pr_inherit */
	{ 24,	8,	0,	0 },		 /* pr_lower */
	{ 32,	8,	0,	0 },		 /* pr_upper */
};




static const sl_arch_layout_t layout_sparc = {
	&auxv_layout,
	&fltset_layout,
	&lwpsinfo_layout,
	&lwpstatus_layout,
	&prcred_layout,
	&priv_impl_info_layout,
	&prpriv_layout,
	&psinfo_layout,
	&pstatus_layout,
	&prgregset_layout,
	&prpsinfo_layout,
	&prstatus_layout,
	&sigaction_layout,
	&siginfo_layout,
	&sigset_layout,
	&stack_layout,
	&sysset_layout,
	&timestruc_layout,
	&utsname_layout,
	&prfdinfo_layout,
	&prsecflags_layout,
};


const sl_arch_layout_t *
struct_layout_sparc(void)
{
	return (&layout_sparc);
}
