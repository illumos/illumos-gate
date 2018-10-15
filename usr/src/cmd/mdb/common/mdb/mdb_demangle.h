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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Jason King.
 */

#ifndef	_MDB_DEMANGLE_H
#define	_MDB_DEMANGLE_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_MDB

#include <sys/types.h>
#include <sys/param.h>
#include <mdb/mdb_modapi.h>
#include <demangle-sys.h>

typedef struct mdb_demangler {
	sysdem_lang_t dm_lang;		/* language to demangle */
	char *dm_buf;			/* demangling buffer */
	size_t dm_len;			/* size of dm_buf in bytes */
	char *dm_dem;			/* start of demangled string (in buf) */
	uint_t dm_flags;		/* convert flags (see below) */
} mdb_demangler_t;

#define	MDB_DM_QUAL	0x1		/* show static/const/volatile */
#define	MDB_DM_SCOPE	0x2		/* show function scope specifiers */
#define	MDB_DM_FUNCARG	0x4		/* show function arguments */
#define	MDB_DM_MANGLED	0x8		/* show mangled name */
#define	MDB_DM_ALL	0xf		/* mask of all valid flags */

extern mdb_demangler_t *mdb_dem_load(void);
extern void mdb_dem_unload(mdb_demangler_t *);
extern const char *mdb_dem_convert(mdb_demangler_t *, const char *);

extern int cmd_demangle(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_demflags(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int cmd_demstr(uintptr_t, uint_t, int, const mdb_arg_t *);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_DEMANGLE_H */
