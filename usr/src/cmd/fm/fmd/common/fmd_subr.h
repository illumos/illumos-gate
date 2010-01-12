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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_SUBR_H
#define	_FMD_SUBR_H

#include <pthread.h>
#include <synch.h>
#include <stdarg.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef DEBUG
extern int fmd_assert(const char *, const char *, int);
#define	ASSERT(x)	((void)((x) || fmd_assert(#x, __FILE__, __LINE__)))
#else
#define	ASSERT(x)
#endif

extern void fmd_vpanic(const char *, va_list);
extern void fmd_panic(const char *, ...);

extern void fmd_verror(int, const char *, va_list);
extern void fmd_error(int, const char *, ...);

#define	FMD_DBG_HELP	0x0001	/* display list of debugging modes and exit */
#define	FMD_DBG_ERR	0x0002	/* enable error handling debug messages */
#define	FMD_DBG_MOD	0x0004	/* enable module subsystem debug messages */
#define	FMD_DBG_DISP	0x0008	/* enable dispq subsystem debug messages */
#define	FMD_DBG_XPRT	0x0010	/* enable transport subsystem debug messages */
#define	FMD_DBG_EVT	0x0020	/* enable event subsystem debug messages */
#define	FMD_DBG_LOG	0x0040	/* enable log subsystem debug messages */
#define	FMD_DBG_TMR	0x0080	/* enable timer subsystem debug messages */
#define	FMD_DBG_FMRI	0x0100	/* enable fmri subsystem debug messages */
#define	FMD_DBG_ASRU	0x0200	/* enable asru subsystem debug messages */
#define	FMD_DBG_CASE	0x0400	/* enable case subsystem debug messages */
#define	FMD_DBG_CKPT	0x0800	/* enable checkpoint debug messages */
#define	FMD_DBG_RPC	0x1000	/* enable rpc service debug messages */
#define	FMD_DBG_TRACE	0x2000	/* display matching TRACE() calls */
#define	FMD_DBG_ALL	0x1ffe	/* enable all modes except for HELP, TRACE */

extern void fmd_vdprintf(int, const char *, va_list);
extern void fmd_dprintf(int, const char *, ...);

extern void fmd_trace_cpp(void *, const char *, int);
extern void *fmd_trace(uint_t, const char *, ...);

#ifdef DEBUG
#define	TRACE(args)	{ fmd_trace_cpp(fmd_trace args, __FILE__, __LINE__); }
#else
#define	TRACE(args)
#endif

extern const char *fmd_ea_strerror(int);
extern uint64_t fmd_ena(void);
extern uint32_t fmd_ntz32(uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_SUBR_H */
