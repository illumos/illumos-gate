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

#ifndef _QUEUE_H
#define	_QUEUE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Typedefs
 */

typedef struct queue_node queue_node_t;
struct queue_node {
	queue_node_t   *next_p;
	queue_node_t   *prev_p;
};


/*
 * Declarations
 */

boolean_t	   queue_isempty(queue_node_t * q);
queue_node_t   *queue_prepend(queue_node_t * h, queue_node_t * q);
queue_node_t   *queue_append(queue_node_t * h, queue_node_t * q);
void			queue_init(queue_node_t * q);
queue_node_t   *queue_next(queue_node_t * h, queue_node_t * q);
queue_node_t   *queue_remove(queue_node_t * q);

#ifdef __cplusplus
}
#endif

#endif	/* _QUEUE_H */
