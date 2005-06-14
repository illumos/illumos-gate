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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */
/*	saghdr.h 1.4 of 5/13/85	*/
#include <stdio.h>
#define	NPTS	100
#define NFLD	9
#define	FLDCH	10
#ifndef	DEBUG
#define	DEBUG	0
#endif

struct	entry	{
	char	tm[9];
	float	hr;
	float	val;
	char	qfld[8];
	};

struct	array	{
	char	hname[56];
	struct	entry	ent[NPTS];
	};


struct	c	{
	char	name[60];
	char	op;
	struct	array	*dptr;
	};

struct	p	{
	char	spec[60];
	struct	c	c[5];
	char	mn[10], mx[10];
	float	min, max;
	int	jitems;
	int	mode;
	};
