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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* SVr4.0 1.4 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include "utility.h"

int
set_field_buffer(FIELD *f, int n, char *v)
{
	char *p;
	char *x;
	size_t s;
	int err = 0;
	int	len;
	int	size;

	if (!f || !v || n < 0 || n > f->nbuf)
		return (E_BAD_ARGUMENT);

	len = (int)  strlen(v);
	size = BufSize(f);

	if (Status(f, GROWABLE) && len > size)
		if (!_grow_field(f, (len - size - 1)/GrowSize(f) + 1))
			return (E_SYSTEM_ERROR);

	x = Buffer(f, n);
	s = BufSize(f);
	p = memccpy(x, v, '\0', s);

	if (p)
		(void) memset(p - 1, ' ', (size_t) (s - (p - x) + 1));

	if (n == 0) {
		if (_sync_field(f) != E_OK)
			++err;
		if (_sync_linked(f) != E_OK)
			++err;
	}
	return (err ? E_SYSTEM_ERROR : E_OK);
}

char *
field_buffer(FIELD *f, int n)
{
/*
 * field_buffer may not be accurate on the current field unless
 * called from within the check validation function or the
 * form/field init/term functions.
 * field_buffer is always accurate on validated fields.
 */

	if (f && n >= 0 && n <= f -> nbuf)
		return (Buffer(f, n));
	else
		return ((char *) 0);
}
