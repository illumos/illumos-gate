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

#define ON	1
#define OFF	0
/* the following are the defines for the hard-coded columns of the OOT */
#define OF_VI	0	/* view init function */
#define OF_SH	1	/* selection handler function */
#define OF_EX	2	/* exit function */
#define	OF_MV	3	/* make viewable function */
#define OF_OPEN	4	/* default action (open) */

#define PROMPT	(-4)
#define REINIT	(-5)
#define BACKUP	3
#define REPAINT	4
#define OBJECT	5
#define REREAD	6
#define NOPAINT	7
#define NOOBJECT	8

#define MAX_LABELS	12

#define SAME_OBJECT	1
#define DIFF_OBJECT	2
#define FILE_PARENT	3
#define DIR_PARENT	4

/* flags for make_object */
#define NOFORCE	(0x1)
#define FORCE	(0x2)
#define PARENT	(0x4)

struct label {
	struct operation	*oper;
	int	number;
};
