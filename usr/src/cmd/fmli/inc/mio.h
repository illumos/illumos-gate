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
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

#ifndef	CONT
/* compatibility w/ getok */
union tok
{
	char	*s;
	int	b;
};
#endif


#define	CONT	-1
#define	BACK	-2
#define	BPAINT	-3

#define	CBUT	0	/* for wcntrl only */
#define	STR	1
#define	ABUT	2	/* button reports */
#define	VBUT	4
#define	SBUT	6
#define CMD_KEY	8	/* only for objhandler */
#define	SCREPAINT	15

/* flags (to be or'ed with window) */
#define	CCP	01000 /* current cursor position */
#define	INV	02000 /* inverse video */

/* windows for wprintf */
#define	FBUT	0
#define	LBUT	13
#define	TTL	15
/* NOTE: MAIL and NEWS are BUTTON numbers, MAIL_WIN and NEWS_WIN are WINDOW
	numbers - if they are ever changed to not coincide, some poor soul had
	better go through all the code and change all the MAIL and NEWS's to
	MAIL_WIN and NEWS_WIN as appropriate */
#define	MAIL_WIN	17
#define	MAIL	17
#define	NEWS_WIN	16
#define	NEWS	16
#define	DWH	18
#define	MWH	19
#define	CLBUT	20
#define	CRBUT	21
#define	DWC	(DWH | CCP)
#define	MWC	(MWH | CCP)

#define	BBUT0	16
#define	BBUT1	17
/* modes for enhancement of display */
#define	BONW	7
#define	WONB	0
#define MESS_PGLAB	0
#define MESS_LAB	1
#define MESS_WAIT	2
