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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.8 */

extern	char *fld_eval();

#define	sing_eval(a,b)		fld_eval(&(a)->single, b, (a)->seqno)
#define	multi_eval(a,b,c)	fld_eval((a)->multi + b, c, (a)->seqno)

#define KEYWORDSIZE	14

#define VAL_CALC	-1
#define CMD		32

/* Possible return types for attribute. */

#define RET_INT		0x1
#define RET_STR		0x2
#define RET_BOOL	0x3
#define RET_LIST	0x4
#define RET_ARGS	0x5
#define RET_PATH	0x40
#define EVAL_ONCE	0x80
#define EVAL_ALWAYS	0x100
#define EVAL_SOMETIMES	0x200
#define FREEIT		0x400
#define MAKE_COPY	0x800
#define MENU_MARKED	0x1000
#define MENU_CHECKED	0x2000
#define ATTR_TOUCHED	0x4000
#ifndef EV_SQUIG                 /* must match EV_SQUIG in inc/eval.h       */
#define EV_SQUIG	0x8000	 /* set when {} are special in a descriptor */
#endif                           /* careful.. flag is flipped in eval()     */
#define RETS		7

#define INLINE		1

/* parse table indexes for items that must have the same index
   in more than one parse table
 */

	
#define  PAR_INTR   0
#define  PAR_ONINTR 1
#define  PAR_DONE   2
#define  PAR_ACTION 2
#define  PAR_NAME   3	


struct attribute {
	char *testring;
	int flags;
	char *def;
	char *cur;
	unsigned int seqno;
};

struct fld {
	struct attribute **attrs;
};

struct fm_mn {
	unsigned int seqno;
	struct fld single;
	struct fld *multi;
};
