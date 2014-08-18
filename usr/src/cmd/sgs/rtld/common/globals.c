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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include	<sys/types.h>
#include	<sys/mman.h>
#include	<signal.h>
#include	<dlfcn.h>
#include	<synch.h>
#include	<debug.h>
#include	"_rtld.h"

/*
 * Declarations of global variables used in ld.so.
 */
Rt_lock		rtldlock;
int		thr_flg_nolock = 0;
int		thr_flg_reenter = 0;

/*
 * Major link-map lists.
 */
Lm_list		lml_main =	{ 0 };		/* the `main's link map list */
Lm_list		lml_rtld =	{ 0 };		/* rtld's link map list */

/*
 * Entrance count.  Each time ld.so.1 is entered following initial process
 * setup, this count is bumped.  This value serves to identify the present
 * ld.so.1 operation.
 *
 * An ld.so.1 operation can result in many symbol lookup requests (i.e., loading
 * objects and relocating all symbolic bindings).  This count is used to protect
 * against attempting to re-load a failed lazy load within a single call to
 * ld.so.1, while allowing such attempts across calls.  Should a lazy load fail,
 * the present operation identifier is saved in the current symbol lookup data
 * block (Slookup).  Should a lazy load fall back operation be triggered, the
 * identifier in the symbol lookup block is compared to the current ld.so.1
 * entry count, and if the two are equal the fall back is skipped.
 *
 * With this count, there is a danger of wrap-around, although as an unsigned
 * 32-bit value, it is highly unlikely that any application could usefully make
 * 4.3 giga-calls into ld.so.1.  The worst that can occur is that a fall back
 * lazy load isn't triggered.  However, most lazy loads that fail typically
 * continue to fail unless the user takes corrective action (adds the necessary
 * (fixed) dependencies to the system).
 */
ulong_t		ld_entry_cnt = 1;

/*
 * BEGIN: Exposed to rtld_db, don't change without a coordinated handshake with
 * librtld_db (remembering that librtld_db must be able to read old as well as
 * current core files).
 */
APlist		*dynlm_list = NULL;	/* dynamic list of link-maps */
/*
 * END: Exposed to rtld_db
 */

Reglist		*reglist = NULL;	/* list of register symbols */

/*
 * Set of integers to track how many of what type of PLT's have been bound.
 * This is only really interesting for SPARC since ia32 has only one PLT.
 */
uint32_t	pltcnt21d = 0;
uint32_t	pltcnt24d = 0;
uint32_t	pltcntu32 = 0;
uint32_t	pltcntu44 = 0;
uint32_t	pltcntfull = 0;
uint32_t	pltcntfar = 0;

/*
 * AVL tree pointers.
 */
avl_tree_t	*capavl = NULL;		/* capabilities files */
avl_tree_t	*nfavl = NULL;		/* not-found path names */
avl_tree_t	*spavl = NULL;		/* secure path names */

/*
 * Various other global data.
 */
uint_t		rtld_flags = 0;
uint_t		rtld_flags2 = 0;

Lc_desc		glcs[CI_MAX];		/* global external interfaces */

const char	*procname = NULL;
const char	*rtldname = MSG_ORIG(MSG_FIL_RTLD);

char		*lasterr = NULL;	/* string describing last error */
					/*    cleared by each dlerror() */
Interp		*interp = NULL;		/* ELF interpreter info */
APlist		*hdl_alp[HDLIST_SZ+2];	/* dlopen() handle list */
size_t		syspagsz = 0;		/* system page size */
ulong_t		at_flags = 0;		/* machine specific file flags */
Uts_desc	*uts = NULL; 		/* utsname descriptor */
Isa_desc	*isa = NULL;		/* isalist descriptor */

uint_t		audit_argcnt = 64;	/* no. of stack args to copy (default */
					/*    is all) */
Audit_desc	*auditors = NULL;	/* global auditors (LD_AUDIT) */
APlist		*aud_preinit = NULL;	/* list of objects defining local */
APlist		*aud_activity = NULL;	/*    preinit and activity auditors */

const char	*rpl_audit = NULL;	/* replaceable LD_AUDIT string */
const char	*rpl_debug = NULL;	/* replaceable LD_DEBUG string */
const char	*rpl_ldflags = NULL;	/* replaceable LD_FLAGS string */
const char	*rpl_libpath = NULL;	/* replaceable LD_LIBRARY_PATH string */
Alist		*rpl_libdirs = NULL;	/*    and associated Pdesc list */
const char	*rpl_preload = NULL;	/* replaceable LD_PRELOAD string */
const char	*rpl_ldtoxic = NULL;	/* replaceable LD_TOXIC string */
Alist		*rpl_toxdirs = NULL;	/*    and associated Pdesc list */

const char	*prm_audit = NULL;	/* permanent LD_AUDIT string */
const char	*prm_debug = NULL;	/* permanent LD_DEBUG string */
const char	*prm_ldflags = NULL;	/* permanent LD_FLAGS string */
const char	*prm_libpath = NULL;	/* permanent LD_LIBRARY_PATH string */
Alist		*prm_libdirs = NULL;	/*    and associated Pdesc list */
const char	*prm_preload = NULL;	/* permanent LD_PRELOAD string */

uint_t		env_info = 0;		/* information regarding environment */
					/*    variables */
int		killsig = SIGKILL;	/* signal sent on fatal exit */
APlist		*free_alp = NULL;	/* defragmentation list */

/*
 * Capabilities are provided by the system.  However, users can define an
 * alternative set of system capabilities, where they can add, subtract, or
 * override the system capabilities for testing purposes.  Furthermore, these
 * alternative capabilities can be specified such that they only apply to
 * specified files rather than to all objects.
 *
 * The org_scapset is relied upon by the amd64 version of elf_rtbndr to
 * determine whether or not AVX registers are present in the system.
 */
static Syscapset	scapset = { 0 };
Syscapset	*org_scapset = &scapset;	/* original system and */
Syscapset	*alt_scapset = &scapset;	/* alternative system */
						/*	capabilities */

const char	*rpl_hwcap = NULL;	/* replaceable hwcap str */
const char	*rpl_sfcap = NULL;	/* replaceable sfcap str */
const char	*rpl_machcap = NULL;	/* replaceable machcap str */
const char	*rpl_platcap = NULL;	/* replaceable platcap str */
const char	*rpl_cap_files = NULL;	/* associated files */

const char	*prm_hwcap = NULL;	/* permanent hwcap str */
const char	*prm_sfcap = NULL;	/* permanent sfcap str */
const char	*prm_machcap = NULL;	/* permanent machcap str */
const char	*prm_platcap = NULL;	/* permanent platcap str */
const char	*prm_cap_files = NULL;	/* associated files */

/*
 * Note, the debugging descriptor interposes on the default definition provided
 * by liblddbg.  This is required as ld.so.1 must only have outstanding relative
 * relocations.
 */
static Dbg_desc	_dbg_desc = {0, 0, 0};
Dbg_desc	*dbg_desc = &_dbg_desc;	/* debugging descriptor */
const char	*dbg_file = NULL;	/* debugging directed to file */

#pragma weak	environ = _environ	/* environ for PLT tracing - we */
char		**_environ = NULL;	/* supply the pair to satisfy any */
					/* libc requirements (hwmuldiv) */

const char	*profile_name = NULL;	/* object being profiled */
const char	*profile_out = NULL;	/* profile output file */
const char	*profile_lib = NULL;	/* audit library to perform profile */

uchar_t		search_rules[] = {	/* dependency search rules */
		RPLENV,			/*	replaceable LD_LIBRARY_PATH */
		PRMENV,			/*	permanent LD_LIBRARY_PATH */
		RUNPATH,		/*	callers runpath */
		DEFAULT,		/*	default library path */
		0
};

Dl_argsinfo	argsinfo = { 0 };	/* process argument, environment and */
					/*	auxv information. */

/*
 * Frequently used messages are cached here to reduce _dgettext() overhead and
 * also provide for resetting should the locale change (see _ld_libc()).
 */
const char	*err_strs[ERR_NUM] = { NULL };
const char	*nosym_str = NULL;


/*
 * Rejection error message tables.
 */
const Msg
ldd_reject[SGS_REJ_NUM] = {
		MSG_STR_EMPTY,
		MSG_LDD_REJ_MACH,	/* MSG_INTL(MSG_LDD_REJ_MACH) */
		MSG_LDD_REJ_CLASS,	/* MSG_INTL(MSG_LDD_REJ_CLASS) */
		MSG_LDD_REJ_DATA,	/* MSG_INTL(MSG_LDD_REJ_DATA) */
		MSG_LDD_REJ_TYPE,	/* MSG_INTL(MSG_LDD_REJ_TYPE) */
		MSG_LDD_REJ_BADFLAG,	/* MSG_INTL(MSG_LDD_REJ_BADFLAG) */
		MSG_LDD_REJ_MISFLAG,	/* MSG_INTL(MSG_LDD_REJ_MISFLAG) */
		MSG_LDD_REJ_VERSION,	/* MSG_INTL(MSG_LDD_REJ_VERSION) */
		MSG_LDD_REJ_HAL,	/* MSG_INTL(MSG_LDD_REJ_HAL) */
		MSG_LDD_REJ_US3,	/* MSG_INTL(MSG_LDD_REJ_US3) */
		MSG_LDD_REJ_STR,	/* MSG_INTL(MSG_LDD_REJ_STR) */
		MSG_LDD_REJ_UNKFILE,	/* MSG_INTL(MSG_LDD_REJ_UNKFILE) */
		MSG_LDD_REJ_UNKCAP,	/* MSG_INTL(MSG_LDD_REJ_UNKCAP) */
		MSG_LDD_REJ_HWCAP_1,	/* MSG_INTL(MSG_LDD_REJ_HWCAP_1) */
		MSG_LDD_REJ_SFCAP_1,	/* MSG_INTL(MSG_LDD_REJ_SFCAP_1) */
		MSG_LDD_REJ_MACHCAP,	/* MSG_INTL(MSG_LDD_REJ_MACHCAP) */
		MSG_LDD_REJ_PLATCAP,	/* MSG_INTL(MSG_LDD_REJ_PLATCAP) */
		MSG_LDD_REJ_HWCAP_2,	/* MSG_INTL(MSG_LDD_REJ_HWCAP_2) */
		MSG_LDD_REJ_ARCHIVE	/* MSG_INTL(MSG_LDD_REJ_ARCHIVE) */
	};
#if SGS_REJ_NUM != (SGS_REJ_ARCHIVE + 1)
#error SGS_REJ_NUM has changed
#endif

const Msg
err_reject[SGS_REJ_NUM] = {
		MSG_STR_EMPTY,
		MSG_ERR_REJ_MACH,	/* MSG_INTL(MSG_ERR_REJ_MACH) */
		MSG_ERR_REJ_CLASS,	/* MSG_INTL(MSG_ERR_REJ_CLASS) */
		MSG_ERR_REJ_DATA,	/* MSG_INTL(MSG_ERR_REJ_DATA) */
		MSG_ERR_REJ_TYPE,	/* MSG_INTL(MSG_ERR_REJ_TYPE) */
		MSG_ERR_REJ_BADFLAG,	/* MSG_INTL(MSG_ERR_REJ_BADFLAG) */
		MSG_ERR_REJ_MISFLAG,	/* MSG_INTL(MSG_ERR_REJ_MISFLAG) */
		MSG_ERR_REJ_VERSION,	/* MSG_INTL(MSG_ERR_REJ_VERSION) */
		MSG_ERR_REJ_HAL,	/* MSG_INTL(MSG_ERR_REJ_HAL) */
		MSG_ERR_REJ_US3,	/* MSG_INTL(MSG_ERR_REJ_US3) */
		MSG_ERR_REJ_STR,	/* MSG_INTL(MSG_ERR_REJ_STR) */
		MSG_ERR_REJ_UNKFILE,	/* MSG_INTL(MSG_ERR_REJ_UNKFILE) */
		MSG_ERR_REJ_UNKCAP,	/* MSG_INTL(MSG_ERR_REJ_UNKCAP) */
		MSG_ERR_REJ_HWCAP_1,	/* MSG_INTL(MSG_ERR_REJ_HWCAP_1) */
		MSG_ERR_REJ_SFCAP_1,	/* MSG_INTL(MSG_ERR_REJ_SFCAP_1) */
		MSG_ERR_REJ_MACHCAP,	/* MSG_INTL(MSG_ERR_REJ_MACHCAP) */
		MSG_ERR_REJ_PLATCAP,	/* MSG_INTL(MSG_ERR_REJ_PLATCAP) */
		MSG_ERR_REJ_HWCAP_2,	/* MSG_INTL(MSG_ERR_REJ_HWCAP_2) */
		MSG_ERR_REJ_ARCHIVE,	/* MSG_INTL(MSG_ERR_REJ_ARCHIVE) */
	};
#if SGS_REJ_NUM != (SGS_REJ_ARCHIVE + 1)
#error SGS_REJ_NUM has changed
#endif

const Msg
ldd_warn[SGS_REJ_NUM] = {
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_STR_EMPTY,
		MSG_LDD_WARN_UNKCAP,	/* MSG_INTL(MSG_LDD_WARN_UNKCAP) */
		MSG_LDD_WARN_HWCAP_1,	/* MSG_INTL(MSG_LDD_WARN_HWCAP_1) */
		MSG_LDD_WARN_SFCAP_1,	/* MSG_INTL(MSG_LDD_WARN_SFCAP_1) */
		MSG_LDD_WARN_MACHCAP,	/* MSG_INTL(MSG_LDD_WARN_MACHCAP) */
		MSG_LDD_WARN_PLATCAP,	/* MSG_INTL(MSG_LDD_WARN_PLATCAP) */
		MSG_LDD_WARN_HWCAP_2,	/* MSG_INTL(MSG_LDD_WARN_HWCAP_2) */
		MSG_STR_EMPTY
	};
#if SGS_REJ_NUM != (SGS_REJ_ARCHIVE + 1)
#error SGS_REJ_NUM has changed
#endif
