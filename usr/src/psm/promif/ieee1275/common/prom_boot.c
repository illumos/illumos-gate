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

#include <sys/promif.h>
#include <sys/promimpl.h>

char *
prom_bootargs(void)
{
	int length;
	pnode_t node;
	static char *name = "bootargs";
	static char bootargs[OBP_MAXPATHLEN];

	if (bootargs[0] != (char)0)
		return (bootargs);

	node = prom_chosennode();
	if ((node == OBP_NONODE) || (node == OBP_BADNODE))
		node = prom_rootnode();
	length = prom_getproplen(node, name);
	if ((length == -1) || (length == 0))
		return (NULL);
	if (length > OBP_MAXPATHLEN)
		length = OBP_MAXPATHLEN - 1;	/* Null terminator */
	(void) prom_bounded_getprop(node, name, bootargs, length);
	return (bootargs);
}


struct bootparam *
prom_bootparam(void)
{
	PROMIF_DPRINTF(("prom_bootparam on P1275?\n"));
	return ((struct bootparam *)0);
}

char *
prom_bootpath(void)
{
	static char bootpath[OBP_MAXPATHLEN];
	int length;
	pnode_t node;
	static char *name = "bootpath";

	if (bootpath[0] != (char)0)
		return (bootpath);

	node = prom_chosennode();
	if ((node == OBP_NONODE) || (node == OBP_BADNODE))
		node = prom_rootnode();
	length = prom_getproplen(node, name);
	if ((length == -1) || (length == 0))
		return (NULL);
	if (length > OBP_MAXPATHLEN)
		length = OBP_MAXPATHLEN - 1;	/* Null terminator */
	(void) prom_bounded_getprop(node, name, bootpath, length);
	return (bootpath);
}
