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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * insque() and remque() insert or remove an element from a queue.
 * The queue is built from a doubly linked list whose elements are
 * defined by a structure where the first member of the structure
 * points to the next element in the queue and the second member
 * of the structure points to the previous element in the queue.
 */

#pragma weak _insque = insque
#pragma weak _remque = remque

#include "lint.h"
#include <sys/types.h>
#include <stdlib.h>
#include <search.h>

void
insque(void *elem, void *pred)
{
	if (pred == NULL) {    /* This is the first element being inserted. */
		((struct qelem *)elem)->q_forw = NULL;
		((struct qelem *)elem)->q_back = NULL;
	} else if (((struct qelem *)pred)->q_forw == NULL) {
					/* The element is inserted at */
					/* the end of the queue. */
		((struct qelem *)elem)->q_forw = NULL;
		((struct qelem *)elem)->q_back = pred;
		((struct qelem *)pred)->q_forw = elem;
	} else {		/* The element is inserted in the middle of */
				/* the queue. */
		((struct qelem *)elem)->q_forw = ((struct qelem *)pred)->q_forw;
		((struct qelem *)elem)->q_back = pred;
		((struct qelem *)pred)->q_forw->q_back = elem;
		((struct qelem *)pred)->q_forw = elem;
	}
}

void
remque(void *elem)
{
	if (((struct qelem *)elem)->q_back == NULL) {
					/* The first element is removed. */
		if (((struct qelem *)elem)->q_forw == NULL)
					/* The only element is removed. */
			return;
		((struct qelem *)elem)->q_forw->q_back = NULL;
	} else if (((struct qelem *)elem)->q_forw == NULL) {
					/* The last element is removed */
		((struct qelem *)elem)->q_back->q_forw = NULL;
	} else {	/* The middle element is removed. */
		((struct qelem *)elem)->q_back->q_forw =
		    ((struct qelem *)elem)->q_forw;
		((struct qelem *)elem)->q_forw->q_back =
		    ((struct qelem *)elem)->q_back;
	}
}
