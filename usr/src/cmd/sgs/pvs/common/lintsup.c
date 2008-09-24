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
/* LINTLIBRARY */
/* PROTOLIB1 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Supplimental Pseudo-code to get lint to consider
 * these symbols used.
 */

#include <debug.h>
#include "msg.h"

void
foo()
{
	dbg_print(0, _pvs_msg((Msg)&__pvs_msg[0]));

	alist_delete_by_offset(NULL, NULL);
	(void) alist_insert_by_offset(NULL, NULL, 0, 0, 0);
	alist_reset(NULL);

	(void) aplist_delete_value(NULL, NULL);
	aplist_reset(NULL);
	(void) aplist_test(NULL, NULL, 0);
}
