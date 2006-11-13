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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nscd_db.h"

static nscd_seq_num_t		acc_seq = 1;
static mutex_t			seq_mutex = DEFAULTMUTEX;
static nscd_cookie_num_t	cookie_num = 1234;
static mutex_t			cookie_mutex = DEFAULTMUTEX;

nscd_seq_num_t
_nscd_get_seq_num()
{
	nscd_seq_num_t	seq_num;

	(void) mutex_lock(&seq_mutex);
	seq_num = acc_seq;
	acc_seq++;
	(void) mutex_unlock(&seq_mutex);

	return (seq_num);
}

nscd_cookie_num_t
_nscd_get_cookie_num()
{
	nscd_cookie_num_t	ret;

	(void) mutex_lock(&cookie_mutex);
	ret = cookie_num;
	cookie_num++;
	(void) mutex_unlock(&cookie_mutex);

	return (ret);
}
