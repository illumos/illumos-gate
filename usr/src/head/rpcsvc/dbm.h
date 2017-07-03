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
 * Copyright 2014, 2016 PALO, Richard.
 *
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef	_RPCSVC_DBM_H
#define	_RPCSVC_DBM_H

#include <sys/isa_defs.h>
#include <sys/null.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PBLKSIZ	1024
#define	DBLKSIZ	4096
#define	BYTESIZ	8

long	bitno;
long	maxbno;
long	blkno;
long	hmask;

char	pagbuf[PBLKSIZ];
char	dirbuf[DBLKSIZ];

int	dirf;
int	pagf;
int	dbrdonly;

typedef	struct
{
	char	*dptr;
	int	dsize;
} datum;

datum	fetch(datum);
datum	makdatum(char *, int);
datum	firstkey(void);
datum	nextkey(datum);
datum	firsthash(long);
long	calchash(datum);
long	hashinc(long);

#ifdef	__cplusplus
}
#endif

#endif	/* _RPCSVC_DBM_H */
