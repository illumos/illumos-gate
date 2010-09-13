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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1989 AT&T					*/
/*	  All Rights Reserved  					*/

/*
 *	Based on @(#)lnstuff.h 1.5 02/06/05 from lint
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	LNSTUFF_H
#define	LNSTUFF_H

#include <sys/types.h>

#define	LDI 01		/* defined and initialized: storage set aside	*/
#define	LIB 02		/* defined on a library				*/
#define	LDC 04		/* defined as a common region on UNIX		*/
#define	LDX 010		/* defined by an extern: if ! pflag, same as LDI */
#define	LRV 020		/* function returns a value			*/
#define	LUV 040		/* function used in a value context		*/
#define	LUE 0100	/* function used in effects context		*/
#define	LUM 0200	/* mentioned somewhere other than at the declaration */
#define	LDS 0400	/* defined static object (like LDI)		*/
#define	LFN 01000	/* filename record				*/
#define	LSU 02000	/* struct/union def				*/
#define	LPR 04000	/* prototype declaration			*/
#define	LND 010000	/* end module marker				*/
#define	LPF 020000	/* printf like					*/
#define	LSF 040000	/* scanf like					*/

#define	LNQUAL		00037		/* type w/o qualifiers		*/
#define	LNUNQUAL	0174000		/* remove type, keep other info */
#define	LCON		(1<<15)		/* type qualified by const	*/
#define	LVOL		(1<<14)		/* type qualified by volatile	*/
#define	LNOAL		(1<<13)		/* not used */
#define	LCONV		(1<<12)		/* type is an integer constant	*/
#define	LPTR		(1<<11)		/* last modifier is a pointer	*/
#define	LINTVER		4

typedef unsigned long T1WORD;
typedef long FILEPOS;
typedef short TY;

typedef struct flens {
	long		f1, f2, f3, f4;
	unsigned short	ver, mno;
} FLENS;

typedef struct {
	TY		aty;		/* base type			*/
	unsigned long	dcl_mod;	/* ptr/ftn/ary modifiers	*/
	unsigned short	dcl_con;	/* const qualifiers		*/
	unsigned short	dcl_vol;	/* volatile qualifiers		*/
	union {
		T1WORD	ty;
		FILEPOS	pos;
	} extra;
} ATYPE;

typedef struct {
	short		decflag;	/* what type of record is this	*/
	short		nargs;		/* # of args (or members)	*/
	int		fline;		/* line defined/used in		*/
	ATYPE		type;		/* type information		*/
} LINE;

union rec {
	LINE l;
	struct {
		short decflag;
		char *fn;
	} f;
};

/* type modifiers */
#define	LN_TMASK 3
#define	LN_ISPTR(x)	(((x)&LN_TMASK) == 1)  /* is x a pointer type */
#define	LN_ISFTN(x)	(((x)&LN_TMASK) == 2)  /* is x a function type */
#define	LN_ISARY(x)	(((x)&LN_TMASK) == 3)  /* is x an array type */

/* type numbers for pass2 */
#define	LN_STRUCT	21	/* generic struct */
#define	LN_UNION	22	/* generic union */

#endif	/* LNSTUFF_H */
