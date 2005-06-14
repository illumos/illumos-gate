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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DATAQ_H
#define	_DATAQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "llt.h"

typedef struct dataq_data {
	ll_t list;
	void *data;
} dataq_data_t;

typedef struct dataq_waiter {
	ll_t list;
	pthread_cond_t cv;
	int wakeup;
} dataq_waiter_t;

typedef struct dataq {
	pthread_mutex_t lock;
	int num_data;
	int num_waiters;
	llh_t data;
	llh_t waiters;
} dataq_t;

int dataq_init(dataq_t *ptr);
int dataq_enqueue(dataq_t *dataq, void *in);
int dataq_dequeue(dataq_t *dataq, void **outptr, int);
int dataq_destroy(dataq_t *dataq);

#endif	/* _DATAQ_H */
