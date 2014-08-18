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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Hashed key data base library.
 */

#ifndef _NDBM_H
#define	_NDBM_H

#include <sys/feature_tests.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * flags to dbm_store()
 */
#define	DBM_INSERT	0
#define	DBM_REPLACE	1

#define	_PBLKSIZ 1024
#define	_DBLKSIZ 4096

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	PBLKSIZ _PBLKSIZ
#define	DBLKSIZ _DBLKSIZ
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

typedef struct {
	int	dbm_dirf;		/* open directory file */
	int	dbm_pagf;		/* open page file */
	int	dbm_flags;		/* flags, see below */
	long	dbm_maxbno;		/* last ``bit'' in dir file */
	long	dbm_bitno;		/* current bit number */
	long	dbm_hmask;		/* hash mask */
	long	dbm_blkptr;		/* current block for dbm_nextkey */
	int	dbm_keyptr;		/* current key for dbm_nextkey */
	long	dbm_blkno;		/* current page to read/write */
	long	dbm_pagbno;		/* current page in pagbuf */
	char	dbm_pagbuf[_PBLKSIZ];	/* page file block buffer */
	long	dbm_dirbno;		/* current block in dirbuf */
	char	dbm_dirbuf[_DBLKSIZ];	/* directory file block buffer */
} DBM;

#if defined(_XPG4_2)
typedef struct {
	void	*dptr;
	size_t	dsize;
} datum;
#else
typedef struct {
	char	*dptr;
	long	dsize;
} datum;
#endif

DBM	*dbm_open(const char *, int, mode_t);
void	dbm_close(DBM *);
datum	dbm_fetch(DBM *, datum);
datum	dbm_firstkey(DBM *);
datum	dbm_nextkey(DBM *);
int	dbm_delete(DBM *, datum);
int	dbm_store(DBM *, datum, datum, int);
int	dbm_clearerr(DBM *);
int	dbm_error(DBM *);

#define	_DBM_RDONLY	0x1	/* data base open read-only */
#define	_DBM_IOERR	0x2	/* data base I/O error */

#define	dbm_rdonly(__db)	((__db)->dbm_flags & _DBM_RDONLY)
#define	dbm_error(__db)		((__db)->dbm_flags & _DBM_IOERR)
/* use this one at your own risk! */
#define	dbm_clearerr(__db)	((__db)->dbm_flags &= ~_DBM_IOERR)
/* for fstat(2) */
#define	dbm_dirfno(__db)	((__db)->dbm_dirf)
#define	dbm_pagfno(__db)	((__db)->dbm_pagf)

#ifdef	__cplusplus
}
#endif

#endif	/* _NDBM_H */
