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

#ifndef _FCN_H
#define	_FCN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include "queue.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Typedefs
 */

typedef struct fcn {
	queue_node_t	qn;
	char		*name_p;
	char		*entry_name_p;
} fcn_t;


/*
 * Declarations
 */

void fcn(char *name_p, char *func_entry_p);
void fcn_list(void);
fcn_t *fcn_find(char *name_p);
char *fcn_findname(const char * const entry_p);

#ifdef __cplusplus
}
#endif

#endif /* _FCN_H */
