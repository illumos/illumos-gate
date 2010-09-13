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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * check.h -- public definitions for check module
 *
 * the checking functions are called by the tree_X() functions
 * in tree.c.  this header file exports the checking functions
 * from check.c so that tree.c can see them.  nobody else uses them.
 */

#ifndef	_ESC_COMMON_CHECK_H
#define	_ESC_COMMON_CHECK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

void check_init(void);
void check_fini(void);
void check_report_combination(struct node *np);
void check_arrow(struct node *np);
void check_stmt_required_properties(struct node *stmtnp);
void check_stmt_allowed_properties(enum nodetype t,
    struct node *nvpairnp, struct lut *lutp);
void check_propnames(enum nodetype t, struct node *np, int from, int to);
void check_propscope(struct node *np);
void check_proplists(enum nodetype t, struct node *np);
void check_upset_engine(struct node *lhs, struct node *rhs, void *arg);
void check_refcount(struct node *lhs, struct node *rhs, void *arg);
int check_cycle_level(long long val);
void check_cycle(struct node *lhs, struct node *rhs, void *arg);
void check_type_iterator(struct node *np);
void check_name_iterator(struct node *np);
void check_func(struct node *np);
void check_expr(struct node *np);
void check_event(struct node *np);
void check_required_props(struct node *lhs, struct node *rhs, void *arg);

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_CHECK_H */
