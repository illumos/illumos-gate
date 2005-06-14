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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.8 */

extern chtype getattr();
extern chtype acswreadchar();

/* defines for Substreams */
#define SINGLE	0
#define MULTI	1

/* Miscellaneous defines and macros */
#define Fieldrows	(Cfld->rows)
#define Fieldcols	(Cfld->cols)
#define Flags		(Cfld->flags)
#define Fieldattr	(Cfld->fieldattr)
#define Lastattr	(Cfld->lastattr)
#define Currtype	(Cfld->currtype)
#define Scrollbuf	(Cfld->scrollbuf)
#define Buffoffset	(Cfld->buffoffset)
#define Buffsize	(Cfld->buffsize)
#define Bufflast	(Cfld->bufflast)
#define Value		(Cfld->value)
#define Valptr		(Cfld->valptr)

/* computational macros */
#define LASTCOL		(Cfld->cols - 1)
#define LASTROW		(Cfld->rows - 1)
#define LINEBYTES	(Cfld->cols + 1)
#define FIELDBYTES	(Cfld->rows * (Cfld->cols + 1))


/* field character operation macros */
#define	freadchar(r,c)	wreadchar(r+Cfld->frow,c+Cfld->fcol)
#define	acsreadchar(r,c) acswreadchar(r+Cfld->frow,c+Cfld->fcol)
#define fputchar(x)	wputchar(x, Fieldattr, NULL);

#define UP	0
#define DOWN	1
#define LEFT	2
#define RIGHT	3
