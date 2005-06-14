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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/types.h>

void
zero(caddr_t addr, size_t len)
{
	int _len = (int)len;

	while (_len-- > 0) {
		/* Align and go faster */
		if (((intptr_t)addr & ((sizeof (int) - 1))) == 0) {
			/* LINTED */
			int *w = (int *)addr;
			/* LINTED */
			while (_len > 0) {
				*w++ = 0;
				_len -= sizeof (int);
			}
			return;
		}
		*addr++ = 0;
	}
}
