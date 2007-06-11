/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * eval.h -- public definitions for eval module
 *
 */

#ifndef	_EFT_EVAL_H
#define	_EFT_EVAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct evalue {
	enum datatype {
		UNDEFINED = 0,
		UINT64,		/* use for Boolean as well */
		STRING,		/* usually pointer from stable() */
		NODEPTR		/* (struct node *) */
	} t;
	/*
	 * using v to handle all values eliminates the need for switch()
	 * blocks during assignments, comparisons and other operations
	 */
	unsigned long long v;
};

int eval_potential(struct node *np, struct lut *ex, struct node *events[],
    struct node **newc, struct config *croot);
int eval_expr(struct node *np, struct lut *ex, struct node *events[],
	struct lut **globals, struct config *croot, struct arrow *arrowp,
	int try, struct evalue *valuep);

#ifdef	__cplusplus
}
#endif

#endif	/* _EFT_EVAL_H */
