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

#ifndef	_SGS_PROFV_H
#define	_SGS_PROFV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Header file for processing versioned, *new-style* mon.out files.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/elf.h>
#include "gelf.h"
#include "monv.h"
#include "_machelf.h"

/*
 * Booleans.
 */
typedef int	bool;

#define	TRUE	1
#define	FALSE	0

/*
 * Bit macro and flag bit definitions. These and the sort_flags below,
 * need to be always in sync with the set in prof.c
 */
extern int		flags;

#define	F_SORT		0x1
#define	F_VERBOSE	0x2
#define	F_ZSYMS		0x4
#define	F_PADDR		0x8
#define	F_NHEAD		0x10

/*
 * Sort flags. Mutually exclusive.
 */
extern unsigned char	sort_flag;

#define	BY_ADDRESS	0x1
#define	BY_NCALLS	0x2
#define	BY_NAME		0x4
#define	BY_TIME		0x8

/*
 * Error codes
 */
#define	ERR_SYSCALL	1
#define	ERR_INPUT	2
#define	ERR_ELF		3
#define	ERR_MEMORY	4

/*
 * Other useful macros.
 */
#define	BUCKET_SZ	4096
#define	PRF_END		"_end"

extern int		gflag, Cflag;
extern char		*atitle, *aformat,
			*cmdname, *sym_fn, *mon_fn;

/*
 * Module info.
 */
struct mod_info {
	char		*path;		/* pathname of module */
	int		id;		/* id (used while printing) */
	bool		active;		/* is this module active or not ? */
	Address		load_base;	/* base addr where module is loaded */
	Address		load_end;	/* end addr of loaded module */
	GElf_Addr	txt_origin;	/* txt start as given in PHT */
	GElf_Addr	data_end;	/* data end as found from `_end' */
	struct nl	*nl;		/* ptr to module's namelist */
	size_t		nfuncs;		/* number of functions in `nl' */
	struct mod_info	*next;		/* link to next module */
};
typedef struct mod_info	mod_info_t;

/*
 * List of shared objects. Note that this always includes the program
 * executable as the first element.
 */
extern mod_info_t	modules;
extern size_t		n_modules;

/*
 * The symbol table.
 */
struct nl {
	char		*name;		/* name of the symbol */
	GElf_Addr	value;		/* value of the symbol */
	unsigned char	info;		/* symbol's bind/type info */
	GElf_Xword	size;		/* size of the symbol */
	size_t		ncalls;		/* number of calls to this func */
	size_t		nticks;		/* number of ticks spent here */
};
typedef struct nl	nltype;

/*
 * The profile output record. There is some duplication of fields from
 * the namelist, but the profsym contains just the symbols we're going
 * to print, and that makes a lot of things easier.
 */
struct profrec {
	GElf_Addr	addr;			/* symbol value */
	double		percent_time;		/* percentage time spent here */
	double		seconds;		/* time spent here in seconds */
	size_t		ncalls;			/* calls to this function */
	double		msecs_per_call;		/* milliseconds per call */
	char		*demangled_name;	/* demangled name if C++ */
	bool		print_mid;		/* print module id ? */
	char		*name;			/* bookkeeping, not printed */
	mod_info_t	*module;		/* bookkeeping, not printed */
};
typedef struct profrec	profrec_t;
extern profrec_t	*profsym;

/*
 * Names in profile output need to be sorted to figure out if there'll
 * be any duplicate names in the output.
 */
struct profnames {
	char		*name;
	profrec_t	*pfrec;
};
typedef struct profnames	profnames_t;

/*
 * File status.
 */
extern struct stat	aout_stat, monout_stat;

/*
 * Timing related externs.
 */
extern bool	time_in_ticks;
extern size_t	n_pcsamples, n_accounted_ticks, n_zeros, total_funcs;
extern double	total_time;

/*
 * Other declarations
 */
extern void	profver(void);
extern nltype	*nllookup(mod_info_t *, Address, Address *);
extern Address	*locate(Address *, size_t, Address);
extern void	get_syms(char *, mod_info_t *);
extern int	cmp_by_address(const void *arg1, const void *arg2);
extern bool	is_shared_obj(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SGS_PROFV_H */
