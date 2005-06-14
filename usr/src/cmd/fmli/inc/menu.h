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


/*
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 *
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

struct menu {
	struct menu_line	(*disp)();
	char	*arg;
	vt_id	vid;
	int	flags;
	int	index;			/* current item */
	int	hcols;			/* # of chars highlighted */
	int	topline;		/* top line displayed */
	int	number;			/* number of items */
	/* max length of highlight and description parts */
	int	hwidth;
	int	dwidth;
	/* multi-column parameters */
	int	ncols;
};

#define MENU_DIRTY	1
#define MENU_USED	2
#define MENU_CENTER	4
#define MENU_NONUMBER	8
#define MENU_MSELECT	16
#define MENU_TRUNC	32	/* no room for description; show elipses */
#define ALL_MNU_FLAGS	63
#define MENU_ALL	1000	/* max number of chars to highlight on line */

extern struct menu	*MNU_array;
extern menu_id	MNU_curid;
