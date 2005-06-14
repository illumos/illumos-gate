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
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 *
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.9 */

struct vt {
	char	*title;
	WINDOW	*win;
	WINDOW  *subwin;
	vt_id	next;
	vt_id	prev;
	int	number;
	int	flags;
};
/* les */
#define	WORK_LEN	7
#define	DATE_LEN	48

#define VT_USED		 01
#define VT_DIRTY	 02	/* contents of window changed */
#define VT_BDIRTY	 04	/* border of window changed */
#define VT_TDIRTY	010	/* title of window changed */
#define VT_SADIRTY	020	/* scroll "arrows" for window changed */
#define VT_PADIRTY	040	/* page "arrows" for window changed */ 

#define VT_ANYDIRTY	(VT_DIRTY | VT_BDIRTY | VT_TDIRTY | VT_PADIRTY | VT_SADIRTY)

extern vt_id		VT_front;
extern vt_id		VT_back;
extern vt_id		VT_curid;
extern struct vt	*VT_array;

/* attribute array                   abs: indirection removed.
extern chtype		Attr_list[];
#define highlights(x)	((chtype) Attr_list[x])
*/
