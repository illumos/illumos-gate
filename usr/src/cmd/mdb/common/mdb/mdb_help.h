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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 */

#ifndef	_MDB_HELP_H
#define	_MDB_HELP_H

#include <mdb/mdb_tab.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

extern int cmd_dmods(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_dcmds(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_walkers(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_formats(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_help(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_help_tab(mdb_tab_cookie_t *, uint_t, int, const mdb_arg_t *);
extern int cmd_which(uintptr_t, uint_t, int, const mdb_arg_t *);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_HELP_H */
