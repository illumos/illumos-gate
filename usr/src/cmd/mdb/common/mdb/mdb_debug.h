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

#ifndef	_MDB_DEBUG_H
#define	_MDB_DEBUG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdarg.h>

#define	MDB_DBG_CMDBUF	0x00000001
#define	MDB_DBG_PARSER	0x00000002
#define	MDB_DBG_HELP	0x00000004
#define	MDB_DBG_MODULE	0x00000008
#define	MDB_DBG_DCMD	0x00000010
#define	MDB_DBG_ELF	0x00000020
#define	MDB_DBG_MACH	0x00000040
#define	MDB_DBG_SHELL	0x00000080
#define	MDB_DBG_KMOD	0x00000100
#define	MDB_DBG_WALK	0x00000200
#define	MDB_DBG_UMEM	0x00000400
#define	MDB_DBG_DSTK	0x00000800
#define	MDB_DBG_TGT	0x00001000
#define	MDB_DBG_PSVC	0x00002000
#define	MDB_DBG_PROC	0x00004000
#define	MDB_DBG_CTF	0x00008000
#define	MDB_DBG_DPI	0x00010000
#define	MDB_DBG_KDI	0x00020000
#define	MDB_DBG_CALLB	0x00040000

#ifdef _MDB

extern void mdb_dprintf(uint_t, const char *, ...);
extern void mdb_dvprintf(uint_t, const char *, va_list);

extern uint_t mdb_dstr2mode(const char *);
extern void mdb_dmode(uint_t);

extern const char *mdb_err2str(int);

extern int mdb_dassert(const char *, const char *, int);
#ifdef DEBUG
#define	ASSERT(x)	((void)((x) || mdb_dassert(#x, __FILE__, __LINE__)))
#else
#define	ASSERT(x)
#endif

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_DEBUG_H */
