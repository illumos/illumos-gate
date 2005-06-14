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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

/* see vt.h for previous "VT_" defines !!! */
#define VT_UPSARROW	 0100	
#define VT_DNSARROW	 0200	
#define VT_UPPARROW	 0400	
#define VT_DNPARROW	01000	
#define VT_NONUMBER	16384
#define VT_NOBORDER	32768

#define VT_UNDEFINED	((vt_id) -1)

/* indicates cost function to use when creating a new vt */
#define VT_NOOVERLAP	0
#define VT_CENTER	1
#define VT_COVERCUR	2
#define VT_NOCOVERCUR	3
#define NUMCOSTS	4
#define VT_COSTS	3	/* AND off the COST part of the flags */

#define STATUS_WIN	0
#define CMD_WIN		1
#define MESS_WIN	2

/* "funny" characters */
#define MENU_MARKER	'\1'	/* RIGHT ARROW */
