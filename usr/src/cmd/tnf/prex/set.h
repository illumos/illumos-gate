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

#ifndef _SET_H
#define	_SET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <stdio.h>
#include <sys/types.h>

#include "queue.h"
#include "expr.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Typedefs
 */

typedef struct set {
	queue_node_t	qn;
	char		   *setname_p;
	expr_t		 *exprlist_p;

}			   set_t;


/*
 * Declarations
 */

set_t		  *set(char *name, expr_t * exprlist_p);
void			set_list(void);
set_t		  *set_find(char *setname_p);
boolean_t	   set_match(set_t * set_p, const char *name, const char *keys);

#ifdef __cplusplus
}
#endif

#endif /* _SET_H */
