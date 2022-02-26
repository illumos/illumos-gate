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

#include <sys/promif_impl.h>

/*
 * Secure WAN boot requires firmware support for storing and
 * retrieving security keys. The user command to set these
 * keys in firmware storage is ickey(8). Currently, sun4v
 * platforms do not support this functionality. However, there
 * is an external interface to these prom interfaces from the
 * openprom(4D) driver. They are not documented in the man page,
 * but they should still be handled just well enough so that
 * the user gets a sensible error back.
 */

int
promif_set_security_key(void *p)
{
	_NOTE(ARGUNUSED(p))

	return (-1);
}

int
promif_get_security_key(void *p)
{
	cell_t	*ci = (cell_t *)p;

	ci[6] = p1275_int2cell(-1);

	return (-1);
}
