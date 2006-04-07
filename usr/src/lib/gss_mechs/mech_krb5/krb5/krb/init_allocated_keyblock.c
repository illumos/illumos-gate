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

#include "k5-int.h"

krb5_error_code KRB5_CALLCONV
krb5_init_allocated_keyblock(
	krb5_context context,
	krb5_enctype enctype,
	unsigned int length,
	krb5_keyblock *kb)
{

	if (!kb)
		return (EINVAL);

	(void) memset(kb, 0, sizeof (*kb));
	kb->enctype = enctype;
	kb->length = length;

	if (length) {
		kb->contents = malloc(length);
		if (!kb->contents) {
			return (ENOMEM);
		}
		(void) memset(kb->contents, 0, length);
	} else {
		kb->contents = NULL;
	}

	kb->dk_list = NULL;

#ifdef _KERNEL
	kb->kef_key = NULL;
#else
	kb->hKey = CK_INVALID_HANDLE;
#endif

	return (0);
}
