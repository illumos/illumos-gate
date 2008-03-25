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
 *
 * out.h -- public definitions for output module
 *
 * general output & error handling routines.  the routine out() is
 * the most commonly used routine in this module -- called by virtually
 * all other modules.
 */

#ifndef	_ESC_COMMON_OUT_H
#define	_ESC_COMMON_OUT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/ccompile.h>
#include <inttypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

void out_init(const char *myname);
void out_fini(void);
void out(int flags, const char *fmt, ...);
void outfl(int flags, const char *fname, int line, const char *fmt, ...);
void out_exit(int code) __NORETURN;
void out_altfp(FILE *fp);
int out_errcount(void);
int out_warncount(void);

/* flags for out() */
#define	O_OK	0x0000	/* simple output pseudo-flag */
#define	O_DIE	0x0001	/* O_PROG, stderr, bump exit code, call out_exit() */
#define	O_ERR	0x0002	/* O_PROG, stderr, bump exit code */
#define	O_WARN	0x0004	/* O_PROG, stderr, do nothing unless Warn is set */
#define	O_SYS	0x0008	/* append errno text to message */
#define	O_STAMP	0x0010	/* append a timestamp */
#define	O_ALTFP	0x0020	/* write output to alternate file pointer */
#define	O_PROG	0x0040	/* prepend program name to message */
#define	O_NONL	0x0080	/* don't append a newline to message */
#define	O_DEBUG	0x0100	/* do nothing unless Debug is set */
#define	O_VERB	0x0200	/* do nothing unless Verbose is set */
#define	O_VERB2	0x0400	/* do nothing unless Verbose >= 2 */
#define	O_VERB3	0x2000	/* do nothing unless Verbose >= 3 */
#define	O_USAGE	0x0800	/* stderr, usage message */
#define	O_ABORT	0x1000	/* call abort() after issuing any output */

#ifdef DEBUG

#define	ASSERT(cnd) \
	((void)((cnd) || (outfl(O_ABORT, __FILE__, __LINE__, \
	    "assertion failure: %s", #cnd), 0)))

#define	ASSERTinfo(cnd, info) \
	((void)((cnd) || (outfl(O_ABORT, __FILE__, __LINE__, \
	    "assertion failure: %s (%s = %s)", #cnd, #info, info), 0)))

#define	ASSERTeq(lhs, rhs, tostring) \
	((void)(((lhs) == (rhs)) || (outfl(O_ABORT, __FILE__, __LINE__, \
	    "assertion failure: %s (%s) == %s (%s)", #lhs, \
	    tostring(lhs), #rhs, tostring(rhs)), 0)))

#define	ASSERTne(lhs, rhs, tostring) \
	((void)(((lhs) != (rhs)) || (outfl(O_ABORT, __FILE__, __LINE__, \
	    "assertion failure: %s (%s) != %s (%s)", #lhs, \
	    tostring(lhs), #rhs, tostring(rhs)), 0)))

#else

#define	ASSERT(cnd) ((void)0)
#define	ASSERTinfo(cnd, info) ((void)0)
#define	ASSERTeq(lhs, rhs, tostring) ((void)0)
#define	ASSERTne(lhs, rhs, tostring) ((void)0)

#endif

extern int Debug;
extern int Verbose;
extern int Warn;

/*
 * so you can say things like:
 *	printf("\t%10d fault statement%s\n", OUTS(Faultcount));
 */
#define	OUTS(i) (i), ((i) == 1) ? "" : "s"

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_OUT_H */
