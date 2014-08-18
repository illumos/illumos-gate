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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_EXECINFO_H
#define	_EXECINFO_H

/*
 * These functions provide glibc-compatible backtrace functionality.
 * Improved functionality is available using Solaris-specific APIs;
 * see man page for walkcontext(), printstack() and addtosymstr().
 */
#ifdef	__cplusplus
extern "C" {
#endif

extern int backtrace(void **, int);
extern char **backtrace_symbols(void *const *, int);
extern void backtrace_symbols_fd(void *const *, int, int);

#ifdef	__cplusplus
}
#endif

#endif /* _EXECINFO_H */
