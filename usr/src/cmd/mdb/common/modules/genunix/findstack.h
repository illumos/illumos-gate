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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_MDB_FINDSTACK_H
#define	_MDB_FINDSTACK_H

#include <mdb/mdb_modapi.h>
#include <sys/param.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct findstack_info {
	uintptr_t	*fsi_stack;	/* place to record frames */
	uintptr_t	fsi_sp;		/* stack pointer */
	uintptr_t	fsi_pc;		/* pc */
	uintptr_t	fsi_sobj_ops;	/* sobj_ops */
	uint_t		fsi_tstate;	/* t_state */
	uchar_t		fsi_depth;	/* stack depth */
	uchar_t		fsi_failed;	/* search failed */
	uchar_t		fsi_overflow;	/* stack was deeper than max_depth */
	uchar_t		fsi_panic;	/* thread called panic() */
	uchar_t		fsi_max_depth;	/* stack frames available */
} findstack_info_t;

#define	FSI_FAIL_BADTHREAD	1
#define	FSI_FAIL_NOTINMEMORY	2
#define	FSI_FAIL_THREADCORRUPT	3
#define	FSI_FAIL_STACKNOTFOUND	4

typedef struct stacks_module {
	char		sm_name[MAXPATHLEN]; /* name of module */
	uintptr_t	sm_text;	/* base address of text in module */
	size_t		sm_size;	/* size of text in module */
} stacks_module_t;

extern int findstack(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int findstack_debug(uintptr_t, uint_t, int, const mdb_arg_t *);

/*
 * The following routines are implemented in findstack.c, shared across both
 * genunix and libc.
 */
extern int stacks(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void stacks_cleanup(int);

/*
 * The following routines are specific to their context (kernel vs. user-land)
 * and are therefore implemented in findstack_subr.c (of which each of genunix
 * and libc have their own copy).
 */
extern void stacks_help(void);
extern int stacks_findstack(uintptr_t, findstack_info_t *, uint_t);
extern void stacks_findstack_cleanup();
extern int stacks_module(stacks_module_t *);

extern int findstack_debug_on;

#define	fs_dprintf(x)					\
	if (findstack_debug_on) {			\
		mdb_printf("findstack debug: ");	\
		/*CSTYLED*/				\
		mdb_printf x ;				\
	}

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_FINDSTACK_H */
