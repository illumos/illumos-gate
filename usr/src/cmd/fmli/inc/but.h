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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

#include	"mio.h"

#define ANY	99	/* same as in io.h, but don't want to include it all */

#define RESTART	(LBUT)
#define DONE	(LBUT-1)
#define MORE	(LBUT-2)
#define PRE	(LBUT-3)
#define BUT1	(FBUT)
#define BUT2	(FBUT+1)
#define BUT3	(FBUT+2)
#define BUT4	(FBUT+3)
#define BUT5	(FBUT+4)
#define BUT6	(FBUT+5)
#define BUT7	(FBUT+6)
#define BUT1R	(LBUT-6)
#define BUT2R	(LBUT-5)
#define BUT3R	(LBUT-4)
#define BUT4R	(LBUT-3)
#define BUT5R	(LBUT-2)
#define BUT6R	(LBUT-1)
#define BUT7R	(LBUT)

#define LABLEN_1	(11)
#define LABLEN_2	(14)
