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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"


extern struct huff {
	long xn;
	int xw;
	long xc;
	long xcq;	/* (c,0) */
	long xcs;	/* c left justified */
	long xqcs;	/* (q-1,c,q) left justified */
	long xv0;
} huffcode;
#define	n huffcode.xn
#define	w huffcode.xw
#define	c huffcode.xc
#define	cq huffcode.xcq
#define	cs huffcode.xcs
#define	qcs huffcode.xqcs
#define	v0 huffcode.xv0

double	huff(float);
int	rhuff(FILE *);
void	whuff(void);
