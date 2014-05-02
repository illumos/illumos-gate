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
	{ 0,	16,	0,	0 },		/* sizeof (auxv_t) */
	{ 0,	4,	0,	1 },		/* a_type */
	{ 8,	8,	0,	1 },		/* a_un.a_val */
	{ 8,	8,	0,	0 },		/* a_un.a_ptr */
	{ 8,	8,	0,	0 },		/* a_un.a_fcn */
};


static const sl_prgregset_layout_t prgregset_layout = {
	{ 0,	224,	0,	0 },		/* sizeof (prgregset_t) */
	{ 0,	8,	28,	0 },		/* elt0 */
};


static const sl_lwpstatus_layout_t lwpstatus_layout = {
	{ 0,	1296,	0,	0 },		/* sizeof (lwpstatus_t) */
	{ 0,	4,	0,	0 },		/* pr_flags */
	{ 4,	4,	0,	0 },		/* pr_lwpid */
	{ 8,	2,	0,	0 },		/* pr_why */
	{ 10,	2,	0,	0 },		/* pr_what */
	{ 12,	2,	0,	0 },		/* pr_cursig */
	{ 16,	256,	0,	0 },		/* pr_info */
	{ 272,	16,	0,	0 },		/* pr_lwppend */
	{ 288,	16,	0,	0 },		/* pr_lwphold */
	{ 304,	32,	0,	0 },		/* pr_action */
	{ 336,	24,	0,	0 },		/* pr_altstack */
	{ 360,	8,	0,	0 },		/* pr_oldcontext */
	{ 368,	2,	0,	0 },		/* pr_syscall */
	{ 370,	2,	0,	0 },		/* pr_nsysarg */
	{ 372,	4,	0,	0 },		/* pr_errno */
	{ 376,	8,	8,	0 },		/* pr_sysarg[] */
	{ 440,	8,	0,	0 },		/* pr_rval1 */
	{ 448,	8,	0,	0 },		/* pr_rval2 */
	{ 456,	1,	8,	0 },		/* pr_clname[] */
	{ 464,	16,	0,	0 },		/* pr_tstamp */
	{ 480,	16,	0,	0 },		/* pr_utime */
	{ 496,	16,	0,	0 },		/* pr_stime */
	{ 524,	4,	0,	0 },		/* pr_errpriv */
	{ 528,	8,	0,	0 },		/* pr_ustack */
	{ 536,	8,	0,	0 },		/* pr_instr */
	{ 544,	224,	0,	0 },		/* pr_reg */
	{ 768,	528,	0,	0 },		/* pr_fpreg */
};


static const sl_pstatus_layout_t pstatus_layout = {
	{ 0,	1680,	0,	0 },		/* sizeof (pstatus_t) */
	{ 0,	4,	0,	1 },		/* pr_flags */
	{ 4,	4,	0,	1 },		/* pr_nlwp */
	{ 8,	4,	0,	0 },		/* pr_pid */
	{ 12,	4,	0,	0 },		/* pr_ppid */
	{ 16,	4,	0,	0 },		/* pr_pgid */
	{ 20,	4,	0,	0 },		/* pr_sid */
	{ 24,	4,	0,	1 },		/* pr_aslwpid */
	{ 28,	4,	0,	1 },		/* pr_agentid */
	{ 32,	16,	0,	0 },		/* pr_sigpend */
	{ 48,	8,	0,	0 },		/* pr_brkbase */
	{ 56,	8,	0,	0 },		/* pr_brksize */
	{ 64,	8,	0,	0 },		/* pr_stkbase */
	{ 72,	8,	0,	0 },		/* pr_stksize */
	{ 80,	16,	0,	0 },		/* pr_utime */
	{ 96,	16,	0,	0 },		/* pr_stime */
	{ 112,	16,	0,	0 },		/* pr_cutime */
	{ 128,	16,	0,	0 },		/* pr_cstime */
	{ 144,	16,	0,	0 },		/* pr_sigtrace */
	{ 160,	16,	0,	0 },		/* pr_flttrace */
	{ 176,	64,	0,	0 },		/* pr_sysentry */
	{ 240,	64,	0,	0 },		/* pr_sysexit */
	{ 304,	1,	0,	0 },		/* pr_dmodel */
	{ 308,	4,	0,	1 },		/* pr_taskid */
	{ 312,	4,	0,	1 },		/* pr_projid */
	{ 316,	4,	0,	1 },		/* pr_nzomb */
	{ 320,	4,	0,	1 },		/* pr_zoneid */
	{ 384,	1296,	0,	0 },		/* pr_lwp */
};


static const sl_prstatus_layout_t prstatus_layout = {
	{ 0,	824,	0,	0 },		/* sizeof (prstatus_t) */
	{ 0,	4,	0,	1 },		/* pr_flags */
	{ 4,	2,	0,	1 },		/* pr_why */
	{ 6,	2,	0,	1 },		/* pr_what */
	{ 8,	256,	0,	0 },		/* pr_info */
	{ 264,	2,	0,	1 },		/* pr_cursig */
	{ 266,	2,	0,	0 },		/* pr_nlwp */
	{ 268,	16,	0,	0 },		/* pr_sigpend */
	{ 284,	16,	0,	0 },		/* pr_sighold */
	{ 304,	24,	0,	0 },		/* pr_altstack */
	{ 328,	32,	0,	0 },		/* pr_action */
	{ 360,	4,	0,	0 },		/* pr_pid */
	{ 364,	4,	0,	0 },		/* pr_ppid */
	{ 368,	4,	0,	0 },		/* pr_pgrp */
	{ 372,	4,	0,	0 },		/* pr_sid */
	{ 376,	16,	0,	0 },		/* pr_utime */
	{ 392,	16,	0,	0 },		/* pr_stime */
	{ 408,	16,	0,	0 },		/* pr_cutime */
	{ 424,	16,	0,	0 },		/* pr_cstime */
	{ 440,	1,	8,	0 },		/* pr_clname[] */
	{ 448,	2,	0,	1 },		/* pr_syscall */
	{ 450,	2,	0,	1 },		/* pr_nsysarg */
	{ 456,	8,	8,	1 },		/* pr_sysarg[] */
	{ 520,	4,	0,	0 },		/* pr_who */
	{ 524,	16,	0,	0 },		/* pr_lwppend */
	{ 544,	8,	0,	0 },		/* pr_oldcontext */
	{ 552,	8,	0,	0 },		/* pr_brkbase */
	{ 560,	8,	0,	0 },		/* pr_brksize */
	{ 568,	8,	0,	0 },		/* pr_stkbase */
	{ 576,	8,	0,	0 },		/* pr_stksize */
	{ 584,	2,	0,	1 },		/* pr_processor */
	{ 586,	2,	0,	1 },		/* pr_bind */
	{ 592,	8,	0,	1 },		/* pr_instr */
	{ 600,	224,	0,	0 },		/* pr_reg */
};


static const sl_psinfo_layout_t psinfo_layout = {
	{ 0,	416,	0,	0 },		/* sizeof (psinfo_t) */
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
	{ 40,	8,	0,	0 },		/* pr_addr */
	{ 48,	8,	0,	0 },		/* pr_size */
	{ 56,	8,	0,	0 },		/* pr_rssize */
	{ 72,	8,	0,	0 },		/* pr_ttydev */
	{ 80,	2,	0,	0 },		/* pr_pctcpu */
	{ 82,	2,	0,	0 },		/* pr_pctmem */
	{ 88,	16,	0,	0 },		/* pr_start */
	{ 104,	16,	0,	0 },		/* pr_time */
	{ 120,	16,	0,	0 },		/* pr_ctime */
	{ 136,	1,	16,	0 },		/* pr_fname[] */
	{ 152,	1,	80,	0 },		/* pr_psargs[] */
	{ 232,	4,	0,	1 },		/* pr_wstat */
	{ 236,	4,	0,	1 },		/* pr_argc */
	{ 240,	8,	0,	0 },		/* pr_argv */
	{ 248,	8,	0,	0 },		/* pr_envp */
	{ 256,	1,	0,	0 },		/* pr_dmodel */
	{ 260,	4,	0,	0 },		/* pr_taskid */
	{ 264,	4,	0,	0 },		/* pr_projid */
	{ 268,	4,	0,	1 },		/* pr_nzomb */
	{ 272,	4,	0,	0 },		/* pr_poolid */
	{ 276,	4,	0,	0 },		/* pr_zoneid */
	{ 280,	4,	0,	0 },		/* pr_contract */
	{ 288,	128,	0,	0 },		/* pr_lwp */
};


static const sl_prpsinfo_layout_t prpsinfo_layout = {
	{ 0,	328,	0,	0 },		/* sizeof (prpsinfo_t) */
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
	{ 32,	8,	0,	0 },		/* pr_addr */
	{ 40,	8,	0,	0 },		/* pr_size */
	{ 48,	8,	0,	0 },		/* pr_rssize */
	{ 56,	8,	0,	0 },		/* pr_wchan */
	{ 64,	16,	0,	0 },		/* pr_start */
	{ 80,	16,	0,	0 },		/* pr_time */
	{ 96,	4,	0,	1 },		/* pr_pri */
	{ 100,	1,	0,	0 },		/* pr_oldpri */
	{ 101,	1,	0,	0 },		/* pr_cpu */
	{ 102,	2,	0,	0 },		/* pr_ottydev */
	{ 104,	8,	0,	0 },		/* pr_lttydev */
	{ 112,	1,	8,	0 },		/* pr_clname[] */
	{ 120,	1,	16,	0 },		/* pr_fname[] */
	{ 136,	1,	80,	0 },		/* pr_psargs[] */
	{ 216,	2,	0,	1 },		/* pr_syscall */
	{ 224,	16,	0,	0 },		/* pr_ctime */
	{ 240,	8,	0,	0 },		/* pr_bysize */
	{ 248,	8,	0,	0 },		/* pr_byrssize */
	{ 256,	4,	0,	1 },		/* pr_argc */
	{ 264,	8,	0,	0 },		/* pr_argv */
	{ 272,	8,	0,	0 },		/* pr_envp */
	{ 280,	4,	0,	1 },		/* pr_wstat */
	{ 284,	2,	0,	0 },		/* pr_pctcpu */
	{ 286,	2,	0,	0 },		/* pr_pctmem */
	{ 288,	4,	0,	0 },		/* pr_euid */
	{ 292,	4,	0,	0 },		/* pr_egid */
	{ 296,	4,	0,	0 },		/* pr_aslwpid */
	{ 300,	1,	0,	0 },		/* pr_dmodel */
};


static const sl_lwpsinfo_layout_t lwpsinfo_layout = {
	{ 0,	128,	0,	0 },		/* sizeof (lwpsinfo_t) */
	{ 0,	4,	0,	1 },		/* pr_flag */
	{ 4,	4,	0,	0 },		/* pr_lwpid */
	{ 8,	8,	0,	0 },		/* pr_addr */
	{ 16,	8,	0,	0 },		/* pr_wchan */
	{ 24,	1,	0,	0 },		/* pr_stype */
	{ 25,	1,	0,	0 },		/* pr_state */
	{ 26,	1,	0,	0 },		/* pr_sname */
	{ 27,	1,	0,	0 },		/* pr_nice */
	{ 28,	2,	0,	0 },		/* pr_syscall */
	{ 30,	1,	0,	0 },		/* pr_oldpri */
	{ 31,	1,	0,	0 },		/* pr_cpu */
	{ 32,	4,	0,	1 },		/* pr_pri */
	{ 36,	2,	0,	0 },		/* pr_pctcpu */
	{ 40,	16,	0,	0 },		/* pr_start */
	{ 56,	16,	0,	0 },		/* pr_time */
	{ 72,	1,	8,	0 },		/* pr_clname[] */
	{ 80,	1,	16,	0 },		/* pr_name[] */
	{ 96,	4,	0,	1 },		/* pr_onpro */
	{ 100,	4,	0,	1 },		/* pr_bindpro */
	{ 104,	4,	0,	1 },		/* pr_bindpset */
	{ 108,	4,	0,	1 },		/* pr_lgrp */
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
	{ 0,	256,	0,	0 },		/* sizeof (siginfo_t) */
	{ 0,	4,	0,	0 },		/* si_signo */
	{ 8,	4,	0,	0 },		/* si_errno */
	{ 4,	4,	0,	1 },		/* si_code */
	{ 32,	4,	0,	0 },		/* si_value.sival_int */
	{ 32,	8,	0,	0 },		/* si_value.sival_ptr */
	{ 16,	4,	0,	0 },		/* si_pid */
	{ 24,	4,	0,	0 },		/* si_uid */
	{ 48,	4,	0,	0 },		/* si_ctid */
	{ 52,	4,	0,	0 },		/* si_zoneid */
	{ 16,	4,	0,	0 },		/* si_entity */
	{ 16,	8,	0,	0 },		/* si_addr */
	{ 32,	4,	0,	0 },		/* si_status */
	{ 24,	8,	0,	0 },		/* si_band */
};


static const sl_sigset_layout_t sigset_layout = {
	{ 0,	16,	0,	0 },		/* sizeof (sigset_t) */
	{ 0,	4,	4,	0 },		/* __sigbits[] */
};


static const sl_sigaction_layout_t sigaction_layout = {
	{ 0,	32,	0,	0 },		/* sizeof (struct sigaction) */
	{ 0,	4,	0,	0 },		/* sa_flags */
	{ 8,	8,	0,	0 },		/* sa_handler */
	{ 8,	8,	0,	0 },		/* sa_sigaction */
	{ 16,	16,	0,	0 },		/* sa_mask */
};


static const sl_stack_layout_t stack_layout = {
	{ 0,	24,	0,	0 },		/* sizeof (stack_t) */
	{ 0,	8,	0,	0 },		/* ss_sp */
	{ 8,	8,	0,	0 },		/* ss_size */
	{ 16,	4,	0,	0 },		/* ss_flags */
};


static const sl_sysset_layout_t sysset_layout = {
	{ 0,	64,	0,	0 },		/* sizeof (sysset_t) */
	{ 0,	4,	16,	0 },		/* word[] */
};


static const sl_timestruc_layout_t timestruc_layout = {
	{ 0,	16,	0,	0 },		/* sizeof (timestruc_t) */
	{ 0,	8,	0,	0 },		/* tv_sec */
	{ 8,	8,	0,	0 },		/* tv_nsec */
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




static const sl_arch_layout_t layout_amd64 = {
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
};


const sl_arch_layout_t *
struct_layout_amd64(void)
{
	return (&layout_amd64);
}
