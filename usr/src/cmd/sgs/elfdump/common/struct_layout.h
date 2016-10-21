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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 */

#ifndef	_STRUCT_LAYOUT_H
#define	_STRUCT_LAYOUT_H

#include	<conv.h>
#include	<_machelf.h>

/*
 * Local include file for elfdump, used to define structure layout
 * definitions for various system structs.
 */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Solaris defines system structs that elfdump needs to display
 * data from. We have a variety of hurdles to overcome in doing this:
 *
 *	- The size of system types can differ between ELFCLASS32 and
 *		ELFCLASS64.
 *	- Stucture layout can differ between architectures, so a given
 *		field can have a different struct offset than is native
 *		for the system running elfdump. Depending on the struct
 *		in question, the layout for one platform may be impossible
 *		to achieve on another.
 *	- The byte order of the core object can differ from that
 *		of the system running elfdump.
 *
 * The result is that in the fully general case, each architecture
 * can have a slightly different definition of these structures.
 * The usual approach of assigning a pointer of the desired structure
 * type and then accessing fields through that pointer cannot be used
 * here. That approach can only be used to access structures with the
 * native layout of the elfdump host. We want any instance of elfdump
 * to be able to examine a Solaris object for any supported architecture,
 * so we need a more flexible approach.
 *
 * The solution to this problem lies in the fact that the binary
 * layout of these public types cannot be changed, except in backward
 * compatible ways. They are written to core files or published in
 * other ways such that we can't make changes that would make it
 * impossible to analyze old files. This means that we can build
 * table of offsets and sizes for each field of each struct, on
 * a per-archecture basis. These tables can be used to access the
 * struct fields directly from the note desc data, and elfdump
 * on any host can read the data from any other host.
 *
 * When reading these tables, it can be very helpful to examine
 * the struct definition at the same time.
 */

/*
 * sl_field_t is used to describe a struct field
 */
typedef struct {
	ushort_t	slf_offset;	/* Offset from start of struct */
	ushort_t	slf_eltlen;	/* Size of datum, in bytes */
	ushort_t	slf_nelts;	/* 0 for scalar, # of els for array */
	uchar_t		slf_sign;	/* True (1) if signed quantity */
} sl_field_t;

/*
 * This type is used to extract and manipulate data described by
 * sl_field_t. We rely on the C guarantee that all the fields in
 * a union have offset 0.
 */
typedef union {
	char		sld_i8;
	uchar_t 	sld_ui8;
	short		sld_i16;
	ushort_t	sld_ui16;
	int32_t		sld_i32;
	uint32_t	sld_ui32;
	int64_t		sld_i64;
	uint64_t	sld_ui64;
} sl_data_t;

/*
 * Buffer large enough to format any integral value in a field
 */
typedef char sl_fmtbuf_t[CONV_INV_BUFSIZE * 2];

/*
 * Types of formatting done by fmt_num()
 */
typedef enum {
	SL_FMT_NUM_DEC = 0,	/* Decimal integer */
	SL_FMT_NUM_HEX = 1,	/* Hex integer, with natural width */
	SL_FMT_NUM_ZHEX = 2,	/* Hex integer, fixed width with zero fill  */
} sl_fmt_num_t;




/*
 * Layout description of auxv_t, from <sys/auxv.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		a_type;
	sl_field_t		a_val;
	sl_field_t		a_ptr;
	sl_field_t		a_fcn;
} sl_auxv_layout_t;

/*
 * Layout description of prgregset_t, an architecture specific
 * array of general register c values
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		elt0;
} sl_prgregset_layout_t;

/*
 * Layout description of lwpstatus_t, from <sys/procfs.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_flags;
	sl_field_t		pr_lwpid;
	sl_field_t		pr_why;
	sl_field_t		pr_what;
	sl_field_t		pr_cursig;
	sl_field_t		pr_info;
	sl_field_t		pr_lwppend;
	sl_field_t		pr_lwphold;
	sl_field_t		pr_action;
	sl_field_t		pr_altstack;
	sl_field_t		pr_oldcontext;
	sl_field_t		pr_syscall;
	sl_field_t		pr_nsysarg;
	sl_field_t		pr_errno;
	sl_field_t		pr_sysarg;
	sl_field_t		pr_rval1;
	sl_field_t		pr_rval2;
	sl_field_t		pr_clname;
	sl_field_t		pr_tstamp;
	sl_field_t		pr_utime;
	sl_field_t		pr_stime;
	sl_field_t		pr_errpriv;
	sl_field_t		pr_ustack;
	sl_field_t		pr_instr;
	sl_field_t		pr_reg;
	sl_field_t		pr_fpreg;
} sl_lwpstatus_layout_t;

/*
 * Layout description of pstatus_t, from <sys/procfs.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_flags;
	sl_field_t		pr_nlwp;
	sl_field_t		pr_pid;
	sl_field_t		pr_ppid;
	sl_field_t		pr_pgid;
	sl_field_t		pr_sid;
	sl_field_t		pr_aslwpid;
	sl_field_t		pr_agentid;
	sl_field_t		pr_sigpend;
	sl_field_t		pr_brkbase;
	sl_field_t		pr_brksize;
	sl_field_t		pr_stkbase;
	sl_field_t		pr_stksize;
	sl_field_t		pr_utime;
	sl_field_t		pr_stime;
	sl_field_t		pr_cutime;
	sl_field_t		pr_cstime;
	sl_field_t		pr_sigtrace;
	sl_field_t		pr_flttrace;
	sl_field_t		pr_sysentry;
	sl_field_t		pr_sysexit;
	sl_field_t		pr_dmodel;
	sl_field_t		pr_taskid;
	sl_field_t		pr_projid;
	sl_field_t		pr_nzomb;
	sl_field_t		pr_zoneid;
	sl_field_t		pr_lwp;
} sl_pstatus_layout_t;

/*
 * Layout description of prstatus_t, from <sys/old_procfs.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_flags;
	sl_field_t		pr_why;
	sl_field_t		pr_what;
	sl_field_t		pr_info;
	sl_field_t		pr_cursig;
	sl_field_t		pr_nlwp;
	sl_field_t		pr_sigpend;
	sl_field_t		pr_sighold;
	sl_field_t		pr_altstack;
	sl_field_t		pr_action;
	sl_field_t		pr_pid;
	sl_field_t		pr_ppid;
	sl_field_t		pr_pgrp;
	sl_field_t		pr_sid;
	sl_field_t		pr_utime;
	sl_field_t		pr_stime;
	sl_field_t		pr_cutime;
	sl_field_t		pr_cstime;
	sl_field_t		pr_clname;
	sl_field_t		pr_syscall;
	sl_field_t		pr_nsysarg;
	sl_field_t		pr_sysarg;
	sl_field_t		pr_who;
	sl_field_t		pr_lwppend;
	sl_field_t		pr_oldcontext;
	sl_field_t		pr_brkbase;
	sl_field_t		pr_brksize;
	sl_field_t		pr_stkbase;
	sl_field_t		pr_stksize;
	sl_field_t		pr_processor;
	sl_field_t		pr_bind;
	sl_field_t		pr_instr;
	sl_field_t		pr_reg;
} sl_prstatus_layout_t;

/*
 * Layout description of psinfo_t, from <sys/procfs.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_flag;
	sl_field_t		pr_nlwp;
	sl_field_t		pr_pid;
	sl_field_t		pr_ppid;
	sl_field_t		pr_pgid;
	sl_field_t		pr_sid;
	sl_field_t		pr_uid;
	sl_field_t		pr_euid;
	sl_field_t		pr_gid;
	sl_field_t		pr_egid;
	sl_field_t		pr_addr;
	sl_field_t		pr_size;
	sl_field_t		pr_rssize;
	sl_field_t		pr_ttydev;
	sl_field_t		pr_pctcpu;
	sl_field_t		pr_pctmem;
	sl_field_t		pr_start;
	sl_field_t		pr_time;
	sl_field_t		pr_ctime;
	sl_field_t		pr_fname;
	sl_field_t		pr_psargs;
	sl_field_t		pr_wstat;
	sl_field_t		pr_argc;
	sl_field_t		pr_argv;
	sl_field_t		pr_envp;
	sl_field_t		pr_dmodel;
	sl_field_t		pr_taskid;
	sl_field_t		pr_projid;
	sl_field_t		pr_nzomb;
	sl_field_t		pr_poolid;
	sl_field_t		pr_zoneid;
	sl_field_t		pr_contract;
	sl_field_t		pr_lwp;
} sl_psinfo_layout_t;

/*
 * Layout description of prpsinfo_t, from <sys/old_procfs.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_state;
	sl_field_t		pr_sname;
	sl_field_t		pr_zomb;
	sl_field_t		pr_nice;
	sl_field_t		pr_flag;
	sl_field_t		pr_uid;
	sl_field_t		pr_gid;
	sl_field_t		pr_pid;
	sl_field_t		pr_ppid;
	sl_field_t		pr_pgrp;
	sl_field_t		pr_sid;
	sl_field_t		pr_addr;
	sl_field_t		pr_size;
	sl_field_t		pr_rssize;
	sl_field_t		pr_wchan;
	sl_field_t		pr_start;
	sl_field_t		pr_time;
	sl_field_t		pr_pri;
	sl_field_t		pr_oldpri;
	sl_field_t		pr_cpu;
	sl_field_t		pr_ottydev;
	sl_field_t		pr_lttydev;
	sl_field_t		pr_clname;
	sl_field_t		pr_fname;
	sl_field_t		pr_psargs;
	sl_field_t		pr_syscall;
	sl_field_t		pr_ctime;
	sl_field_t		pr_bysize;
	sl_field_t		pr_byrssize;
	sl_field_t		pr_argc;
	sl_field_t		pr_argv;
	sl_field_t		pr_envp;
	sl_field_t		pr_wstat;
	sl_field_t		pr_pctcpu;
	sl_field_t		pr_pctmem;
	sl_field_t		pr_euid;
	sl_field_t		pr_egid;
	sl_field_t		pr_aslwpid;
	sl_field_t		pr_dmodel;
} sl_prpsinfo_layout_t;

/*
 * Layout description of lwpsinfo_t, from <sys/procfs.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_flag;
	sl_field_t		pr_lwpid;
	sl_field_t		pr_addr;
	sl_field_t		pr_wchan;
	sl_field_t		pr_stype;
	sl_field_t		pr_state;
	sl_field_t		pr_sname;
	sl_field_t		pr_nice;
	sl_field_t		pr_syscall;
	sl_field_t		pr_oldpri;
	sl_field_t		pr_cpu;
	sl_field_t		pr_pri;
	sl_field_t		pr_pctcpu;
	sl_field_t		pr_start;
	sl_field_t		pr_time;
	sl_field_t		pr_clname;
	sl_field_t		pr_name;
	sl_field_t		pr_onpro;
	sl_field_t		pr_bindpro;
	sl_field_t		pr_bindpset;
	sl_field_t		pr_lgrp;
} sl_lwpsinfo_layout_t;

/*
 * Layout description of prcred_t, from <sys/procfs.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_euid;
	sl_field_t		pr_ruid;
	sl_field_t		pr_suid;
	sl_field_t		pr_egid;
	sl_field_t		pr_rgid;
	sl_field_t		pr_sgid;
	sl_field_t		pr_ngroups;
	sl_field_t		pr_groups;
} sl_prcred_layout_t;

/*
 * Layout description of prpriv_t, from <sys/procfs.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_nsets;
	sl_field_t		pr_setsize;
	sl_field_t		pr_infosize;
	sl_field_t		pr_sets;
} sl_prpriv_layout_t;

/*
 * Layout description of priv_impl_info_t, from <sys/priv.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		priv_headersize;
	sl_field_t		priv_flags;
	sl_field_t		priv_nsets;
	sl_field_t		priv_setsize;
	sl_field_t		priv_max;
	sl_field_t		priv_infosize;
	sl_field_t		priv_globalinfosize;
} sl_priv_impl_info_layout_t;

/*
 * Layout description of fltset_t, from <sys/fault.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		word;
} sl_fltset_layout_t;

/*
 * Layout description of siginfo_t, from <sys/siginfo.h>.
 *
 * siginfo_t is unusual, in that it contains a large union
 * full of private fields. There are macros defined to give
 * access to these fields via the names documented in the
 * siginfo manpage. We stick to the documented names
 * rather than try to unravel the undocumented blob. Hence,
 * the layout description below is a "logical" view of siginfo_t.
 * The fields below are not necessarily in the same order as
 * they appear in siginfo_t, nor are they everything that is in
 * that struct. They may also overlap each other, if they are
 * contained within of the union.
 *
 * The f_ prefixes are used to prevent our field names from
 * clashing with the macros defined in siginfo.h.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		f_si_signo;
	sl_field_t		f_si_errno;
	sl_field_t		f_si_code;
	sl_field_t		f_si_value_int;
	sl_field_t		f_si_value_ptr;
	sl_field_t		f_si_pid;
	sl_field_t		f_si_uid;
	sl_field_t		f_si_ctid;
	sl_field_t		f_si_zoneid;
	sl_field_t		f_si_entity;
	sl_field_t		f_si_addr;
	sl_field_t		f_si_status;
	sl_field_t		f_si_band;
} sl_siginfo_layout_t;

/*
 * Layout description of sigset_t, from <sys/signal.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		sigbits;
} sl_sigset_layout_t;

/*
 * Layout description of struct sigaction, from <sys/signal.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		sa_flags;
	sl_field_t		sa_hand;
	sl_field_t		sa_sigact;
	sl_field_t		sa_mask;
} sl_sigaction_layout_t;

/*
 * Layout description of stack_t, from <sys/signal.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		ss_sp;
	sl_field_t		ss_size;
	sl_field_t		ss_flags;
} sl_stack_layout_t;

/*
 * Layout description of sysset_t, from <sys/syscall.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		word;
} sl_sysset_layout_t;

/*
 * Layout description of timestruc_t, from <sys/time_impl.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		tv_sec;
	sl_field_t		tv_nsec;
} sl_timestruc_layout_t;

/*
 * Layout description of struct utsname, from <sys/utsname.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		sysname;
	sl_field_t		nodename;
	sl_field_t		release;
	sl_field_t		version;
	sl_field_t		machine;
} sl_utsname_layout_t;

/*
 * Layout description of prdinfo_t, from <sys/procfs.h>.
 */
typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_fd;
	sl_field_t		pr_mode;
	sl_field_t		pr_uid;
	sl_field_t		pr_gid;
	sl_field_t		pr_major;
	sl_field_t		pr_minor;
	sl_field_t		pr_rmajor;
	sl_field_t		pr_rminor;
	sl_field_t		pr_ino;
	sl_field_t		pr_offset;
	sl_field_t		pr_size;
	sl_field_t		pr_fileflags;
	sl_field_t		pr_fdflags;
	sl_field_t		pr_path;
} sl_prfdinfo_layout_t;

typedef struct {
	sl_field_t		sizeof_struct;
	sl_field_t		pr_version;
	sl_field_t		pr_effective;
	sl_field_t		pr_inherit;
	sl_field_t		pr_lower;
	sl_field_t		pr_upper;
} sl_prsecflags_layout_t;

/*
 * This type collects all of the layout definitions for
 * a given architecture.
 */
typedef struct {
	const sl_auxv_layout_t		*auxv;		/* auxv_t */
	const sl_fltset_layout_t	*fltset;	/* fltset_t */
	const sl_lwpsinfo_layout_t	*lwpsinfo;	/* lwpsinfo_t */
	const sl_lwpstatus_layout_t	*lwpstatus;	/* lwpstatus_t */
	const sl_prcred_layout_t	*prcred;	/* prcred_t */
	const sl_priv_impl_info_layout_t *priv_impl_info; /* priv_impl_info_t */
	const sl_prpriv_layout_t	*prpriv;	/* prpriv_t */
	const sl_psinfo_layout_t	*psinfo;	/* psinfo_t */
	const sl_pstatus_layout_t	*pstatus;	/* pstatus_t */
	const sl_prgregset_layout_t	*prgregset;	/* prgregset_t */
	const sl_prpsinfo_layout_t	*prpsinfo;	/* prpsinfo_t */
	const sl_prstatus_layout_t	*prstatus;	/* prstatus_t */
	const sl_sigaction_layout_t	*sigaction;	/* struct sigaction */
	const sl_siginfo_layout_t	*siginfo;	/* siginfo_t */
	const sl_sigset_layout_t	*sigset;	/* sigset_t */
	const sl_stack_layout_t		*stack;		/* stack_t */
	const sl_sysset_layout_t	*sysset;	/* sysset_t */
	const sl_timestruc_layout_t	*timestruc;	/* timestruc_t */
	const sl_utsname_layout_t	*utsname;	/* struct utsname */
	const sl_prfdinfo_layout_t	*prfdinfo;	/* prdinfo_t */
	const sl_prsecflags_layout_t	*prsecflags;	/* prsecflags_t */
} sl_arch_layout_t;



extern	void		sl_extract_num_field(const char *data, int do_swap,
			    const sl_field_t *fdesc, sl_data_t *field_data);
extern	Word		sl_extract_as_word(const char *data, int do_swap,
			    const sl_field_t *fdesc);
extern	Lword		sl_extract_as_lword(const char *data, int do_swap,
			    const sl_field_t *fdesc);
extern	Sword		sl_extract_as_sword(const char *data, int do_swap,
			    const sl_field_t *fdesc);
extern	const char	*sl_fmt_num(const char *data, int do_swap,
			    const sl_field_t *fdesc, sl_fmt_num_t fmt_type,
			    sl_fmtbuf_t buf);


extern	const sl_arch_layout_t	*sl_mach(Half);
extern	const sl_arch_layout_t	*struct_layout_i386(void);
extern	const sl_arch_layout_t	*struct_layout_amd64(void);
extern	const sl_arch_layout_t	*struct_layout_sparc(void);
extern	const sl_arch_layout_t	*struct_layout_sparcv9(void);



#ifdef	__cplusplus
}
#endif

#endif	/* _STRUCT_LAYOUT_H */
