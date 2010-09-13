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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _UTIL_H
#define	_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interfaces for libdhcpsvc public module utility functions; these are for
 * internal use only.  See util.c for information about how to use the
 * exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdio.h>

extern int		copy_range(int, off_t, int, off_t, uint64_t);
extern unsigned int	field_split(char *, uint_t, char **, const char *);
extern void		nhconvert(void *, const void *, size_t);
extern int		open_file(const char *, unsigned int, int *);
extern char		*read_entry(FILE *);
extern int		syserr_to_dsvcerr(int);
extern int		pnread(int, void *, size_t, off_t);
extern int		pnwrite(int, const void *, size_t, off_t);
extern void		escape(char, const char *, char *, size_t);
extern void		unescape(char, const char *, char *, size_t);
extern uint64_t		gensig(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTIL_H */
