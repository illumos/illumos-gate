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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

#ifndef	_MDB_PRINT_H
#define	_MDB_PRINT_H

#include <mdb/mdb_tab.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_MDB

extern int cmd_enum(uintptr_t, uint_t, int, const mdb_arg_t *);
extern void enum_help(void);
extern int cmd_sizeof(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_sizeof_tab(mdb_tab_cookie_t *, uint_t, int, const mdb_arg_t *);
extern int cmd_offsetof(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_list(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_array(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_print(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_print_tab(mdb_tab_cookie_t *, uint_t, int, const mdb_arg_t *);
extern void print_help(void);
extern int cmd_printf(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_printf_tab(mdb_tab_cookie_t *, uint_t, int, const mdb_arg_t *);
extern void printf_help(void);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_PRINT_H */
