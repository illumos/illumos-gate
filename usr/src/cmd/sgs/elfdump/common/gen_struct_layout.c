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
 *
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This program is used to generate the contents of the
 * struct_layout_XXX.c files that contain per-archtecture
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <err.h>
#include <sys/types.h>
#include <libctf.h>

/*
 * This extracts CTF information from a temporary object file.
 *
 * START and END bracket a struct layout definition. They issue
 * the typedef boilerplate, and the standard first element (sizeof)
 * which captures the overall size of the structure.
 *
 * SCALAR_FIELD is for scalar struct fields
 *
 * ARRAY_FIELD is for  array struct fields
 *
 * ARRAY_TYPE is for plain (non-struct) array types
 */
#define	START(_name, _type) \
	do_start(#_name, #_type)
#define	END (void) \
	do_end()
#define	SCALAR_FIELD(_type, _field, _sign) \
	do_scalar_field(#_type, #_field, _sign, NULL)
#define	SCALAR_FIELD4(_type, _field, _sign, _rtype) \
	do_scalar_field(#_type, #_field, _sign, _rtype)
#define	ARRAY_FIELD(_type, _field, _sign) \
	do_array_field(#_type, #_field, _sign, NULL)
#define	ARRAY_TYPE(_type, _sign) \
	do_array_type(#_type, "elt0", _sign)

static void do_start(char *_name, char *_type);
static void do_end(void);
static void do_start_name(char *name);
static void do_start_sizeof(char *_type, char *realtype);
static void do_scalar_field(char *_type, char *_field,
	int _sign, char *dotfield);
static void do_array_field(char *_type, char *_field,
	int _sign, char *dotfield);
static void do_array_type(char *_type, char *_field, int _sign);

static void get_ctf_file(char *fname);
static int get_field_info(char *tname, char *fname, char *dotname,
	int *offp, int *sizep);

static ctf_file_t *ctf;
static char *objfile;
static char *machname;

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

	ARRAY_TYPE(prgregset_t,	0);

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

/*
 * Layout description of siginfo_t, <sys/siginfo.h>
 *
 * Note: many siginfo_t members are #defines mapping to
 * long dotted members of sub-structs or unions, and
 * we need the full member spec (with dots) for those.
 */
static void
gen_siginfo(void)
{
	START(siginfo, siginfo_t);

	SCALAR_FIELD(siginfo_t,		si_signo,		0);
	SCALAR_FIELD(siginfo_t,		si_errno,		0);
	SCALAR_FIELD(siginfo_t,		si_code,		1);

	SCALAR_FIELD4(siginfo_t,	si_value.sival_int,	0,
	    "__data.__proc.__pdata.__kill.__value.sival_int");

	SCALAR_FIELD4(siginfo_t,	si_value.sival_ptr,	0,
	    "__data.__proc.__pdata.__kill.__value.sival_ptr");

	SCALAR_FIELD4(siginfo_t,	si_pid,			0,
	    "__data.__proc.__pid");

	SCALAR_FIELD4(siginfo_t,	si_uid,			0,
	    "__data.__proc.__pdata.__kill.__uid");

	SCALAR_FIELD4(siginfo_t,	si_ctid,		0,
	    "__data.__proc.__ctid");

	SCALAR_FIELD4(siginfo_t,	si_zoneid,		0,
	    "__data.__proc.__zoneid");

	SCALAR_FIELD4(siginfo_t,	si_entity,		0,
	    "__data.__rctl.__entity");

	SCALAR_FIELD4(siginfo_t,	si_addr,		0,
	    "__data.__fault.__addr");

	SCALAR_FIELD4(siginfo_t,	si_status,		0,
	    "__data.__proc.__pdata.__cld.__status");

	SCALAR_FIELD4(siginfo_t,	si_band,		0,
	    "__data.__file.__band");

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

	SCALAR_FIELD4(struct sigaction,	sa_handler,	0,
	    "_funcptr._handler");

	SCALAR_FIELD4(struct sigaction,	sa_sigaction,	0,
	    "_funcptr._sigaction");

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

	/* get obj file for input */
	if (argc < 3) {
		(void) fprintf(stderr,
		    "usage: %s {object_file} {MACH}\n", argv[0]);
		exit(1);
	}

	objfile = argv[1];
	machname = argv[2];

	get_ctf_file(objfile);

	(void) printf("#include <struct_layout.h>\n");

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
	    machname);
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
	(void) printf("struct_layout_%s(void)\n", machname);
	(void) printf("{\n\treturn (&layout_%s);\n}\n", machname);

	return (0);
}

/*
 * Helper functions using the CTF library to get type info.
 */

static void
get_ctf_file(char *fname)
{
	int ctferr;

	objfile = fname;
	if ((ctf = ctf_open(objfile, &ctferr)) == NULL) {
		errx(1, "Couldn't open object file %s: %s\n", objfile,
		    ctf_errmsg(ctferr));
	}
}

static void
print_row(int boff, int eltlen, int nelts, int issigned, char *comment)
{
	(void) printf("\t{ %d,\t%d,\t%d,\t%d },\t\t/* %s */\n",
	    boff, eltlen, nelts, issigned, comment);
}

static void
do_start(char *sname, char *tname)
{
	do_start_name(sname);
	do_start_sizeof(tname, NULL);
}

static void
do_start_name(char *sname)
{
	(void) printf("\n\nstatic const sl_%s_layout_t %s_layout = {\n",
	    sname, sname);
}

static void
do_end(void)
{
	(void) printf("};\n");
}

static void
do_start_sizeof(char *tname, char *rtname)
{
	char comment[100];
	ctf_id_t stype;
	int sz;

	if (rtname == NULL)
		rtname = tname;

	if ((stype = ctf_lookup_by_name(ctf, rtname)) == CTF_ERR)
		errx(1, "Couldn't find type %s", rtname);
	if ((stype = ctf_type_resolve(ctf, stype)) == CTF_ERR)
		errx(1, "Couldn't resolve type %s", tname);

	if ((sz = (int)ctf_type_size(ctf, stype)) < 0) {
		errx(1, "Couldn't get size for type %s", tname);
	} else if (sz == 0) {
		errx(1, "Invalid type size 0 for %s", tname);
	}

	(void) snprintf(comment, sizeof (comment), "sizeof (%s)", tname);
	print_row(0, sz, 0, 0, comment);
}

static void
do_scalar_field(char *tname, char *fname, int _sign, char *dotfield)
{
	int rc, off, sz, ftype;

	rc = get_field_info(tname, fname, dotfield, &off, &ftype);
	if (rc < 0)
		errx(1, "Can't get field info for %s->%s", tname, fname);

	if ((ftype = ctf_type_resolve(ctf, ftype)) == CTF_ERR)
		errx(1, "Couldn't resolve type of %s->%s", tname, fname);

	if ((sz = (int)ctf_type_size(ctf, ftype)) < 0) {
		errx(1, "Couldn't get size for type ID %d", ftype);
	} else if (sz == 0) {
		errx(1, "Invalid type size 0 for type ID %d", ftype);
	}

	print_row(off, sz, 0, _sign, fname);
}

static void
do_array_field(char *tname, char *fname,
	int _sign, char *dotfield)
{
	char comment[100];
	ctf_arinfo_t ai;
	int typekind;
	int esz, rc, off, ftype;

	rc = get_field_info(tname, fname, dotfield, &off, &ftype);
	if (rc < 0)
		errx(1, "Can't get field info for %s->%s", tname, fname);

	if ((ftype = ctf_type_resolve(ctf, ftype)) == CTF_ERR)
		errx(1, "Couldn't resolve type of %s->%s", tname, fname);

	typekind = ctf_type_kind(ctf, ftype);
	if (typekind != CTF_K_ARRAY)
		errx(1, "Wrong type for %s->%s", tname, fname);

	rc = ctf_array_info(ctf, ftype, &ai);
	if (rc != 0)
		errx(1, "Can't get array info for %s->%s\n", tname, fname);
	esz = ctf_type_size(ctf, ai.ctr_contents);
	if (esz < 0)
		errx(1, "Can't get element size for %s->%s\n", tname, fname);

	(void) snprintf(comment, sizeof (comment), "%s[]", fname);
	print_row(off, esz, ai.ctr_nelems, _sign, comment);
}

static void
do_array_type(char *tname, char *fname,	int _sign)
{
	ctf_arinfo_t ai;
	int stype, typekind;
	int esz, rc;

	if ((stype = ctf_lookup_by_name(ctf, tname)) == CTF_ERR)
		errx(1, "Couldn't find type %s", tname);
	if ((stype = ctf_type_resolve(ctf, stype)) == CTF_ERR)
		errx(1, "Couldn't resolve type %s", tname);

	typekind = ctf_type_kind(ctf, stype);
	if (typekind != CTF_K_ARRAY)
		errx(1, "Wrong type for %s->%s", tname, fname);

	rc = ctf_array_info(ctf, stype, &ai);
	if (rc != 0)
		errx(1, "Can't get array info for %s->%s\n", tname, fname);
	esz = ctf_type_size(ctf, ai.ctr_contents);
	if (esz < 0)
		errx(1, "Can't get element size for %s->%s\n", tname, fname);

	print_row(0, esz, ai.ctr_nelems, _sign, fname);
}


struct gfinfo {
	char *tname;	/* top type name, i.e. the struct */
	char *fname;	/* field name */
	char *dotname;	/* full field name with dots (optional) */
	char *prefix;	/* current field search prefix */
	int base_off;
	int fld_off;
	int fld_type;
};

static int gfi_iter(const char *fname, ctf_id_t mbrtid,
	ulong_t off, void *varg);

/*
 * Lookup field "fname" in type "tname".  If "dotname" is non-NULL,
 * that's the full field name with dots, i.e. a_un.un_foo, which
 * we must search for by walking the struct CTF recursively.
 */
static int
get_field_info(char *tname, char *fname, char *dotname,
	int *offp, int *tidp)
{
	struct gfinfo gfi;
	ctf_id_t stype;
	int typekind;
	int rc;

	if ((stype = ctf_lookup_by_name(ctf, tname)) == CTF_ERR)
		errx(1, "Couldn't find type %s", tname);
	if ((stype = ctf_type_resolve(ctf, stype)) == CTF_ERR)
		errx(1, "Couldn't resolve type %s", tname);

	/* If fname has a dot, use it as dotname too. */
	if (dotname == NULL && strchr(fname, '.') != NULL)
		dotname = fname;

	gfi.tname = tname;
	gfi.fname = fname;
	gfi.dotname = dotname;
	gfi.prefix = "";
	gfi.base_off = 0;
	gfi.fld_off = 0;
	gfi.fld_type = 0;

	typekind = ctf_type_kind(ctf, stype);
	switch (typekind) {

	case CTF_K_STRUCT:
	case CTF_K_UNION:
		rc = ctf_member_iter(ctf, stype, gfi_iter, &gfi);
		break;

	default:
		errx(1, "Unexpected top-level type for %s", tname);
		break;
	}

	if (rc < 0)
		errx(1, "Error getting info for %s.%s", stype, fname);
	if (rc == 0)
		errx(1, "Did not find %s.%s", tname, fname);

	*offp = gfi.fld_off;
	*tidp = gfi.fld_type;

	return (0);
}

/*
 * Iteration callback for ctf_member_iter
 * Return <0 on error, 0 to keep looking, >0 for found.
 *
 * If no dotname, simple search for fieldname.
 * If we're asked to search with dotname, we need to do a full
 * recursive walk of the types under the dotname.
 */
int
gfi_iter(const char *fieldname, ctf_id_t mbrtid, ulong_t off, void *varg)
{
	char namebuf[100];
	struct gfinfo *gfi = varg;
	char *saveprefix;
	int saveoff;
	int typekind;
	int byteoff;
	int len, rc;

	byteoff = gfi->base_off + (int)(off >> 3);

	/* Easy cases first: no dotname */
	if (gfi->dotname == NULL) {
		if (strcmp(gfi->fname, fieldname) == 0) {
			gfi->fld_off = byteoff;
			gfi->fld_type = mbrtid;
			return (1);
		}
		return (0);
	}

	/* Exact match on the dotname? */
	(void) snprintf(namebuf, sizeof (namebuf), "%s%s",
	    gfi->prefix, fieldname);
	if (strcmp(gfi->dotname, namebuf) == 0) {
		gfi->fld_off = byteoff;
		gfi->fld_type = mbrtid;
		return (1);
	}

	/*
	 * May need to recurse under this field, but
	 * only if there's a match through '.'
	 */
	(void) strlcat(namebuf, ".", sizeof (namebuf));
	len = strlen(namebuf);
	if (strncmp(gfi->dotname, namebuf, len) != 0)
		return (0);

	typekind = ctf_type_kind(ctf, mbrtid);
	switch (typekind) {
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		break;
	default:
		return (0);
	}

	/* Recursively walk members */
	saveprefix = gfi->prefix;
	saveoff = gfi->base_off;
	gfi->prefix = namebuf;
	gfi->base_off = byteoff;
	rc = ctf_member_iter(ctf, mbrtid, gfi_iter, gfi);
	gfi->prefix = saveprefix;
	gfi->base_off = saveoff;

	return (rc);
}
