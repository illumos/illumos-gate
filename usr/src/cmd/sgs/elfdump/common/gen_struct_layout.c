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

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/corectl.h>
#include <procfs.h>
#include <sys/auxv.h>
#include <sys/old_procfs.h>
#include <sys/utsname.h>



/*
 * This standalone program is used to generate the contents
 * of the struct_layout_XXX.c files that contain per-archtecture
 * structure layout information.
 *
 * Although not part of elfdump, it is built by the makefile
 * along with it.
 * To use it:
 *
 *	1) Run it, capturing the output in a file.
 *	2) If this is a replacement for an existing file,
 *		diff the new and old copies to ensure only
 *		the changes you expected are present.
 *	3) Put the new file in the common directory under the name
 *		struct_layout_XXX.c, where XXX is the name of
 *		the architecture (i386, amd64, sparc, sparcv9, etc).
 *	2) Add any necessary header and copyright comments.
 *	3) If this is a new architecture:
 *		- Add an extern statement for struct_layout_XXX()
 *			to struct_layout.h
 *		- Add a case for it to the function sl_struct_layout()
 *			in struct_layout.c.
 */


/*
 * Which machine is this build for?
 */
#if defined(__i386)

#define	MACH	"i386"

#elif defined(__amd64)

#define	MACH	"amd64"

#elif defined(__sparcv9)

#define	MACH	"sparcv9"

#elif defined(__sparc)

#define	MACH	"sparc"

#else

#error "unrecognized build host type"

#endif


/*
 * START and END bracket a struct layout definition. They issue
 * the typedef boilerplate, and the standard first element (sizeof)
 * which captures the overall size of the structure.
 *
 * SCALAR_FIELD is for scalar struct fields
 *
 * ARRAY_FIELD is for  array struct fields
 *
 * ARRAY is for plain (non-struct) array types
 */
#define	START(_name, _type) \
	(void) printf("\n\nstatic const sl_" #_name \
	    "_layout_t " #_name "_layout = {\n"); \
	(void) printf("\t{ 0,\t%d,\t0,\t0 },\t\t/* sizeof (%s) */\n", \
	    sizeof (_type), #_type)
#define	SCALAR_FIELD(_type, _field, _sign) \
	(void) printf("\t{ %d,\t%d,\t0,\t%d },\t\t/* " #_field " */\n", \
	    offsetof(_type, _field), sizeof (((_type *)0)->_field), _sign)
#define	ARRAY_FIELD(_type, _field, _sign) \
	(void) printf("\t{ %d,\t%d,\t%d,\t%d },\t\t/* " #_field "[] */\n", \
	    offsetof(_type, _field), sizeof (((_type *)0)->_field[0]), \
	    sizeof (((_type *)0)->_field) / sizeof (((_type *)0)->_field[0]), \
	    _sign)
#define	ARRAY(_type, _sign) \
	(void) printf("\t{ 0,\t%d,\t%d,\t%d },\t\t/* elt0 */\n", \
	    sizeof (*((_type *)0)[0]), \
	    sizeof (_type) / sizeof (*((_type *)0)[0]), _sign)
#define	END (void) printf("};\n")


/* auxv_t, <sys/auxv.h> */
static void
gen_auxv(void)
{
	START(auxv, auxv_t);

	SCALAR_FIELD(auxv_t,	a_type,	1);
	SCALAR_FIELD(auxv_t,	a_un.a_val,	1);
	SCALAR_FIELD(auxv_t,	a_un.a_ptr,	0);
	SCALAR_FIELD(auxv_t,	a_un.a_fcn,	0);

	END;
}


/* prgregset_t, <sys/prgregset.h> */
static void
gen_prgregset(void)
{
	START(prgregset, prgregset_t);

	ARRAY(prgregset_t,	0);

	END;
}


/* lwpstatus_t, <sys/procfs.h> */
static void
gen_lwpstatus(void)
{
	START(lwpstatus, lwpstatus_t);

	SCALAR_FIELD(lwpstatus_t,	pr_flags,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_lwpid,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_why,		0);
	SCALAR_FIELD(lwpstatus_t,	pr_what,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_cursig,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_info,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_lwppend,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_lwphold,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_action,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_altstack,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_oldcontext,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_syscall,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_nsysarg,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_errno,	0);
	ARRAY_FIELD(lwpstatus_t,	pr_sysarg,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_rval1,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_rval2,	0);
	ARRAY_FIELD(lwpstatus_t,	pr_clname,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_tstamp,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_utime,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_stime,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_errpriv,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_ustack,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_instr,	0);
	SCALAR_FIELD(lwpstatus_t,	pr_reg,		0);
	SCALAR_FIELD(lwpstatus_t,	pr_fpreg,	0);

	END;
}


/* pstatus_t, <sys/procfs.h> */
static void
gen_pstatus(void)
{
	START(pstatus, pstatus_t);

	SCALAR_FIELD(pstatus_t,		pr_flags,	1);
	SCALAR_FIELD(pstatus_t,		pr_nlwp,	1);
	SCALAR_FIELD(pstatus_t,		pr_pid,		0);
	SCALAR_FIELD(pstatus_t,		pr_ppid,	0);
	SCALAR_FIELD(pstatus_t,		pr_pgid,	0);
	SCALAR_FIELD(pstatus_t,		pr_sid,		0);
	SCALAR_FIELD(pstatus_t,		pr_aslwpid,	1);
	SCALAR_FIELD(pstatus_t,		pr_agentid,	1);
	SCALAR_FIELD(pstatus_t,		pr_sigpend,	0);
	SCALAR_FIELD(pstatus_t,		pr_brkbase,	0);
	SCALAR_FIELD(pstatus_t,		pr_brksize,	0);
	SCALAR_FIELD(pstatus_t,		pr_stkbase,	0);
	SCALAR_FIELD(pstatus_t,		pr_stksize,	0);
	SCALAR_FIELD(pstatus_t,		pr_utime,	0);
	SCALAR_FIELD(pstatus_t,		pr_stime,	0);
	SCALAR_FIELD(pstatus_t,		pr_cutime,	0);
	SCALAR_FIELD(pstatus_t,		pr_cstime,	0);
	SCALAR_FIELD(pstatus_t,		pr_sigtrace,	0);
	SCALAR_FIELD(pstatus_t,		pr_flttrace,	0);
	SCALAR_FIELD(pstatus_t,		pr_sysentry,	0);
	SCALAR_FIELD(pstatus_t,		pr_sysexit,	0);
	SCALAR_FIELD(pstatus_t,		pr_dmodel,	0);
	SCALAR_FIELD(pstatus_t,		pr_taskid,	1);
	SCALAR_FIELD(pstatus_t,		pr_projid,	1);
	SCALAR_FIELD(pstatus_t,		pr_nzomb,	1);
	SCALAR_FIELD(pstatus_t,		pr_zoneid,	1);
	SCALAR_FIELD(pstatus_t,		pr_lwp,		0);

	END;
}


/* prstatus_t, <sys/old_procfs.h> */
static void
gen_prstatus(void)
{
	START(prstatus, prstatus_t);

	SCALAR_FIELD(prstatus_t,	pr_flags,	1);
	SCALAR_FIELD(prstatus_t,	pr_why,		1);
	SCALAR_FIELD(prstatus_t,	pr_what,	1);
	SCALAR_FIELD(prstatus_t,	pr_info,	0);
	SCALAR_FIELD(prstatus_t,	pr_cursig,	1);
	SCALAR_FIELD(prstatus_t,	pr_nlwp,	0);
	SCALAR_FIELD(prstatus_t,	pr_sigpend,	0);
	SCALAR_FIELD(prstatus_t,	pr_sighold,	0);
	SCALAR_FIELD(prstatus_t,	pr_altstack,	0);
	SCALAR_FIELD(prstatus_t,	pr_action,	0);
	SCALAR_FIELD(prstatus_t,	pr_pid,		0);
	SCALAR_FIELD(prstatus_t,	pr_ppid,	0);
	SCALAR_FIELD(prstatus_t,	pr_pgrp,	0);
	SCALAR_FIELD(prstatus_t,	pr_sid,		0);
	SCALAR_FIELD(prstatus_t,	pr_utime,	0);
	SCALAR_FIELD(prstatus_t,	pr_stime,	0);
	SCALAR_FIELD(prstatus_t,	pr_cutime,	0);
	SCALAR_FIELD(prstatus_t,	pr_cstime,	0);
	ARRAY_FIELD(prstatus_t,		pr_clname,	0);
	SCALAR_FIELD(prstatus_t,	pr_syscall,	1);
	SCALAR_FIELD(prstatus_t,	pr_nsysarg,	1);
	ARRAY_FIELD(prstatus_t,		pr_sysarg,	1);
	SCALAR_FIELD(prstatus_t,	pr_who,		0);
	SCALAR_FIELD(prstatus_t,	pr_lwppend,	0);
	SCALAR_FIELD(prstatus_t,	pr_oldcontext,	0);
	SCALAR_FIELD(prstatus_t,	pr_brkbase,	0);
	SCALAR_FIELD(prstatus_t,	pr_brksize,	0);
	SCALAR_FIELD(prstatus_t,	pr_stkbase,	0);
	SCALAR_FIELD(prstatus_t,	pr_stksize,	0);
	SCALAR_FIELD(prstatus_t,	pr_processor,	1);
	SCALAR_FIELD(prstatus_t,	pr_bind,	1);
	SCALAR_FIELD(prstatus_t,	pr_instr,	1);
	SCALAR_FIELD(prstatus_t,	pr_reg,		0);

	END;
}


/* psinfo_t, <sys/procfs.h> */
static void
gen_psinfo(void)
{
	START(psinfo, psinfo_t);

	SCALAR_FIELD(psinfo_t,		pr_flag,	1);
	SCALAR_FIELD(psinfo_t,		pr_nlwp,	1);
	SCALAR_FIELD(psinfo_t,		pr_pid,		0);
	SCALAR_FIELD(psinfo_t,		pr_ppid,	0);
	SCALAR_FIELD(psinfo_t,		pr_pgid,	0);
	SCALAR_FIELD(psinfo_t,		pr_sid,		0);
	SCALAR_FIELD(psinfo_t,		pr_uid,		0);
	SCALAR_FIELD(psinfo_t,		pr_euid,	0);
	SCALAR_FIELD(psinfo_t,		pr_gid,		0);
	SCALAR_FIELD(psinfo_t,		pr_egid,	0);
	SCALAR_FIELD(psinfo_t,		pr_addr,	0);
	SCALAR_FIELD(psinfo_t,		pr_size,	0);
	SCALAR_FIELD(psinfo_t,		pr_rssize,	0);
	SCALAR_FIELD(psinfo_t,		pr_ttydev,	0);
	SCALAR_FIELD(psinfo_t,		pr_pctcpu,	0);
	SCALAR_FIELD(psinfo_t,		pr_pctmem,	0);
	SCALAR_FIELD(psinfo_t,		pr_start,	0);
	SCALAR_FIELD(psinfo_t,		pr_time,	0);
	SCALAR_FIELD(psinfo_t,		pr_ctime,	0);
	ARRAY_FIELD(psinfo_t,		pr_fname,	0);
	ARRAY_FIELD(psinfo_t,		pr_psargs,	0);
	SCALAR_FIELD(psinfo_t,		pr_wstat,	1);
	SCALAR_FIELD(psinfo_t,		pr_argc,	1);
	SCALAR_FIELD(psinfo_t,		pr_argv,	0);
	SCALAR_FIELD(psinfo_t,		pr_envp,	0);
	SCALAR_FIELD(psinfo_t,		pr_dmodel,	0);
	SCALAR_FIELD(psinfo_t,		pr_taskid,	0);
	SCALAR_FIELD(psinfo_t,		pr_projid,	0);
	SCALAR_FIELD(psinfo_t,		pr_nzomb,	1);
	SCALAR_FIELD(psinfo_t,		pr_poolid,	0);
	SCALAR_FIELD(psinfo_t,		pr_zoneid,	0);
	SCALAR_FIELD(psinfo_t,		pr_contract,	0);
	SCALAR_FIELD(psinfo_t,		pr_lwp,		0);

	END;
}

/* prpsinfo_t, <sys/old_procfs.h> */
static void
gen_prpsinfo(void)
{
	START(prpsinfo, prpsinfo_t);

	SCALAR_FIELD(prpsinfo_t,	pr_state,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_sname,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_zomb,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_nice,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_flag,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_uid,		0);
	SCALAR_FIELD(prpsinfo_t,	pr_gid,		0);
	SCALAR_FIELD(prpsinfo_t,	pr_pid,		0);
	SCALAR_FIELD(prpsinfo_t,	pr_ppid,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_pgrp,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_sid,		0);
	SCALAR_FIELD(prpsinfo_t,	pr_addr,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_size,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_rssize,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_wchan,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_start,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_time,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_pri,		1);
	SCALAR_FIELD(prpsinfo_t,	pr_oldpri,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_cpu,		0);
	SCALAR_FIELD(prpsinfo_t,	pr_ottydev,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_lttydev,	0);
	ARRAY_FIELD(prpsinfo_t,		pr_clname,	0);
	ARRAY_FIELD(prpsinfo_t,		pr_fname,	0);
	ARRAY_FIELD(prpsinfo_t,		pr_psargs,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_syscall,	1);
	SCALAR_FIELD(prpsinfo_t,	pr_ctime,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_bysize,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_byrssize,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_argc,	1);
	SCALAR_FIELD(prpsinfo_t,	pr_argv,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_envp,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_wstat,	1);
	SCALAR_FIELD(prpsinfo_t,	pr_pctcpu,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_pctmem,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_euid,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_egid,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_aslwpid,	0);
	SCALAR_FIELD(prpsinfo_t,	pr_dmodel,	0);

	END;
}

/* lwpsinfo_t, <sys/procfs.h> */
static void
gen_lwpsinfo(void)
{
	START(lwpsinfo, lwpsinfo_t);

	SCALAR_FIELD(lwpsinfo_t,	pr_flag,	1);
	SCALAR_FIELD(lwpsinfo_t,	pr_lwpid,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_addr,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_wchan,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_stype,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_state,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_sname,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_nice,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_syscall,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_oldpri,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_cpu,		0);
	SCALAR_FIELD(lwpsinfo_t,	pr_pri,		1);
	SCALAR_FIELD(lwpsinfo_t,	pr_pctcpu,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_start,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_time,	0);
	ARRAY_FIELD(lwpsinfo_t,		pr_clname,	0);
	ARRAY_FIELD(lwpsinfo_t,		pr_name,	0);
	SCALAR_FIELD(lwpsinfo_t,	pr_onpro,	1);
	SCALAR_FIELD(lwpsinfo_t,	pr_bindpro,	1);
	SCALAR_FIELD(lwpsinfo_t,	pr_bindpset,	1);
	SCALAR_FIELD(lwpsinfo_t,	pr_lgrp,	1);

	END;
}

/* prcred_t, <sys/procfs.h> */
static void
gen_prcred(void)
{
	START(prcred, prcred_t);

	SCALAR_FIELD(prcred_t,		pr_euid,	0);
	SCALAR_FIELD(prcred_t,		pr_ruid,	0);
	SCALAR_FIELD(prcred_t,		pr_suid,	0);
	SCALAR_FIELD(prcred_t,		pr_egid,	0);
	SCALAR_FIELD(prcred_t,		pr_rgid,	0);
	SCALAR_FIELD(prcred_t,		pr_sgid,	0);
	SCALAR_FIELD(prcred_t,		pr_ngroups,	1);
	ARRAY_FIELD(prcred_t,		pr_groups,	0);

	END;
}

/* prpriv_t, <sys/procfs.h> */
static void
gen_prpriv(void)
{
	START(prpriv, prpriv_t);

	SCALAR_FIELD(prpriv_t,		pr_nsets,	0);
	SCALAR_FIELD(prpriv_t,		pr_setsize,	0);
	SCALAR_FIELD(prpriv_t,		pr_infosize,	0);
	ARRAY_FIELD(prpriv_t,		pr_sets,	0);

	END;
}


/* priv_impl_info_t, <sys/priv.h> */
static void
gen_priv_impl_info(void)
{
	START(priv_impl_info, priv_impl_info_t);

	SCALAR_FIELD(priv_impl_info_t,	priv_headersize,	0);
	SCALAR_FIELD(priv_impl_info_t,	priv_flags,		0);
	SCALAR_FIELD(priv_impl_info_t,	priv_nsets,		0);
	SCALAR_FIELD(priv_impl_info_t,	priv_setsize,		0);
	SCALAR_FIELD(priv_impl_info_t,	priv_max,		0);
	SCALAR_FIELD(priv_impl_info_t,	priv_infosize,		0);
	SCALAR_FIELD(priv_impl_info_t,	priv_globalinfosize,	0);

	END;
}


/* fltset_t, <sys/fault.h> */
static void
gen_fltset(void)
{
	START(fltset, fltset_t);

	ARRAY_FIELD(fltset_t,	word,	0);

	END;
}

/* Layout description of siginfo_t, <sys/siginfo.h> */
static void
gen_siginfo(void)
{
	START(siginfo, siginfo_t);

	SCALAR_FIELD(siginfo_t,		si_signo,		0);
	SCALAR_FIELD(siginfo_t,		si_errno,		0);
	SCALAR_FIELD(siginfo_t,		si_code,		1);
	SCALAR_FIELD(siginfo_t,		si_value.sival_int,	0);
	SCALAR_FIELD(siginfo_t,		si_value.sival_ptr,	0);
	SCALAR_FIELD(siginfo_t,		si_pid,			0);
	SCALAR_FIELD(siginfo_t,		si_uid,			0);
	SCALAR_FIELD(siginfo_t,		si_ctid,		0);
	SCALAR_FIELD(siginfo_t,		si_zoneid,		0);
	SCALAR_FIELD(siginfo_t,		si_entity,		0);
	SCALAR_FIELD(siginfo_t,		si_addr,		0);
	SCALAR_FIELD(siginfo_t,		si_status,		0);
	SCALAR_FIELD(siginfo_t,		si_band,		0);

	END;
}

/* sigset_t, <sys/signal.h> */
static void
gen_sigset(void)
{
	START(sigset, sigset_t);

	ARRAY_FIELD(sigset_t,	__sigbits,	0);

	END;
}


/* struct sigaction, <sys/signal.h> */
static void
gen_sigaction(void)
{
	START(sigaction, struct sigaction);

	SCALAR_FIELD(struct sigaction,	sa_flags,	0);
	SCALAR_FIELD(struct sigaction,	sa_handler,	0);
	SCALAR_FIELD(struct sigaction,	sa_sigaction,	0);
	SCALAR_FIELD(struct sigaction,	sa_mask,	0);

	END;
}

/* stack_t, <sys/signal.h> */
static void
gen_stack(void)
{
	START(stack, stack_t);

	SCALAR_FIELD(stack_t,	ss_sp,		0);
	SCALAR_FIELD(stack_t,	ss_size,	0);
	SCALAR_FIELD(stack_t,	ss_flags,	0);

	END;
}

/* sysset_t, <sys/syscall.h> */
static void
gen_sysset(void)
{
	START(sysset, sysset_t);

	ARRAY_FIELD(sysset_t,	word,	0);

	END;
}

/* timestruc_t, <sys/time_impl.h> */
static void
gen_timestruc(void)
{
	START(timestruc, timestruc_t);

	SCALAR_FIELD(timestruc_t,	tv_sec,		0);
	SCALAR_FIELD(timestruc_t,	tv_nsec,	0);

	END;
}

/* struct utsname, <sys/utsname.h> */
static void
gen_utsname(void)
{
	START(utsname, struct utsname);

	ARRAY_FIELD(struct utsname,	sysname,	0);
	ARRAY_FIELD(struct utsname,	nodename,	0);
	ARRAY_FIELD(struct utsname,	release,	0);
	ARRAY_FIELD(struct utsname,	version,	0);
	ARRAY_FIELD(struct utsname,	machine,	0);

	END;
}

static void
gen_prfdinfo(void)
{
	START(prfdinfo, prfdinfo_t);

	SCALAR_FIELD(prfdinfo_t,	pr_fd,		0);
	SCALAR_FIELD(prfdinfo_t,	pr_mode,	0);
	SCALAR_FIELD(prfdinfo_t,	pr_uid,		0);
	SCALAR_FIELD(prfdinfo_t,	pr_gid,		0);
	SCALAR_FIELD(prfdinfo_t,	pr_major,	0);
	SCALAR_FIELD(prfdinfo_t,	pr_minor,	0);
	SCALAR_FIELD(prfdinfo_t,	pr_rmajor,	0);
	SCALAR_FIELD(prfdinfo_t,	pr_rminor,	0);
	SCALAR_FIELD(prfdinfo_t,	pr_ino,		0);
	SCALAR_FIELD(prfdinfo_t,	pr_offset,	0);
	SCALAR_FIELD(prfdinfo_t,	pr_size,	0);
	SCALAR_FIELD(prfdinfo_t,	pr_fileflags,	0);
	SCALAR_FIELD(prfdinfo_t,	pr_fdflags,	0);
	ARRAY_FIELD(prfdinfo_t,		pr_path,	0);

	END;
}


/*ARGSUSED*/
int
main(int argc, char *argv[])
{
	const char *fmt = "\t&%s_layout,\n";

	printf("#include <struct_layout.h>\n");

	gen_auxv();
	gen_prgregset();
	gen_lwpstatus();
	gen_pstatus();
	gen_prstatus();
	gen_psinfo();
	gen_prpsinfo();
	gen_lwpsinfo();
	gen_prcred();
	gen_prpriv();
	gen_priv_impl_info();
	gen_fltset();
	gen_siginfo();
	gen_sigset();
	gen_sigaction();
	gen_stack();
	gen_sysset();
	gen_timestruc();
	gen_utsname();
	gen_prfdinfo();


	/*
	 * Generate the full arch_layout description
	 */
	(void) printf(
	    "\n\n\n\nstatic const sl_arch_layout_t layout_%s = {\n",
	    MACH);
	(void) printf(fmt, "auxv");
	(void) printf(fmt, "fltset");
	(void) printf(fmt, "lwpsinfo");
	(void) printf(fmt, "lwpstatus");
	(void) printf(fmt, "prcred");
	(void) printf(fmt, "priv_impl_info");
	(void) printf(fmt, "prpriv");
	(void) printf(fmt, "psinfo");
	(void) printf(fmt, "pstatus");
	(void) printf(fmt, "prgregset");
	(void) printf(fmt, "prpsinfo");
	(void) printf(fmt, "prstatus");
	(void) printf(fmt, "sigaction");
	(void) printf(fmt, "siginfo");
	(void) printf(fmt, "sigset");
	(void) printf(fmt, "stack");
	(void) printf(fmt, "sysset");
	(void) printf(fmt, "timestruc");
	(void) printf(fmt, "utsname");
	(void) printf(fmt, "prfdinfo");
	(void) printf("};\n");

	/*
	 * A public function, to make the information available
	 */
	(void) printf("\n\nconst sl_arch_layout_t *\n");
	(void) printf("struct_layout_%s(void)\n", MACH);
	(void) printf("{\n\treturn (&layout_%s);\n}\n", MACH);

	return (0);
}
