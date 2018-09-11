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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2009 Chad Mynhier
 */

#ifndef	_PRUTIL_H
#define	_PRUTIL_H

#include <sys/processor.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern void Die(char *, ...);
extern void Warn(char *, ...);
extern void Progname(char *);
extern void Usage();
extern int Atoi(char *);
extern void Format_size(char *, size_t, int);
extern void Format_pct(char *, float, int);
extern void Format_num(char *, int, int);
extern void Format_time(char *, ulong_t, int);
extern void Format_state(char *, char, processorid_t, int);
extern void *Realloc(void *, size_t);
extern void *Malloc(size_t);
extern void *Zalloc(size_t);
extern int Setrlimit();
extern void Priocntl(char *);
extern void getprojname(projid_t, char *, size_t, int, int, size_t);
extern void getzonename(projid_t, char *, size_t, int, size_t);
extern void stripfname(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PRUTIL_H */
