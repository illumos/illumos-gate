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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _EXPR_H
#define	_EXPR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <stdio.h>

#include "queue.h"
#include "spec.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Typedefs
 */

typedef struct expr {
	queue_node_t	qn;
	spec_t		 *left_p;
	spec_t		 *right_p;

} expr_t;


/*
 * Declarations
 */

expr_t * expr(spec_t * left_p, spec_t * right_p);
void expr_destroy(expr_t * list_p);
expr_t * expr_list(expr_t * list_p, expr_t * item_p);
void expr_print(FILE * stream, expr_t * list_p);
boolean_t expr_match(expr_t * expr_p, const char *attrs);
expr_t * expr_dup(expr_t * list_p);

#ifdef __cplusplus
}
#endif

#endif /* _EXPR_H */
