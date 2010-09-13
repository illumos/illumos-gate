/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MDB_CALLB_H
#define	_MDB_CALLB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_list.h>
#include <mdb/mdb_module.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Callback facility designed to allow interested parties (dmods, targets, or
 * even the core debugger framework) to register for notification when certain
 * "interesting" events occur.
 */

/*
 * Callback classes:
 * (MDB_CALLBACK_* definitions in the module API need to be in sync with these)
 */
#define	MDB_CALLB_STCHG		1	/* System execution state change */
#define	MDB_CALLB_PROMPT	2	/* Before printing the prompt */

typedef void (*mdb_callb_f)(void *);

typedef struct mdb_callb {
	mdb_list_t	cb_list;	/* List of callbacks */
	mdb_module_t	*cb_mod;	/* Requesting module (if any) */
	int		cb_class;	/* When to notify */
	mdb_callb_f	cb_func;	/* Function to invoke */
	void		*cb_arg;	/* Argument for cb_func */
} mdb_callb_t;

extern mdb_callb_t *mdb_callb_add(mdb_module_t *, int, mdb_callb_f, void *);
extern void mdb_callb_remove(mdb_callb_t *);
extern void mdb_callb_remove_by_mod(mdb_module_t *);
extern void mdb_callb_remove_all(void);
extern void mdb_callb_fire(int);

#ifdef __cplusplus
}
#endif

#endif /* _MDB_CALLB_H */
