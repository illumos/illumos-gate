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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Stuff for mucking about with properties
 */

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/prom_emul.h>

int
prom_getproplen(pnode_t nodeid, caddr_t name)
{
	return (promif_getproplen(nodeid, name));
}

int
prom_getprop(pnode_t nodeid, caddr_t name, caddr_t value)
{
	return (promif_getprop(nodeid, name, value));
}

caddr_t
prom_nextprop(pnode_t nodeid, caddr_t previous, caddr_t next)
{
	return (promif_nextprop(nodeid, previous, next));
}

/* obsolete entries, not needed */
char *
prom_decode_composite_string(void *buf, size_t buflen, char *prev)
{
	if ((buf == 0) || (buflen == 0) || ((int)buflen == -1))
		return ((char *)0);

	if (prev == 0)
		return ((char *)buf);

	prev += strlen(prev) + 1;
	if (prev >= ((char *)buf + buflen))
		return ((char *)0);
	return (prev);
}

/*ARGSUSED*/
int
prom_bounded_getprop(pnode_t nodeid, caddr_t name, caddr_t value, int len)
{
	return (-1);
}
