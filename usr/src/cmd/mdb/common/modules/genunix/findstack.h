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

#ifndef	_MDB_FINDSTACK_H
#define	_MDB_FINDSTACK_H

#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int findstack(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int findstack_debug(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int stacks(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void stacks_help(void);
extern void stacks_cleanup(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_FINDSTACK_H */
