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

int
prom_devicetype(pnode_t id, char *type)
{
	register int len;
	char buf[OBP_MAXDRVNAME];

	len = prom_getproplen(id, OBP_DEVICETYPE);
	if (len <= 0 || len >= OBP_MAXDRVNAME)
		return (0);

	(void) prom_getprop(id, OBP_DEVICETYPE, (caddr_t)buf);

	if (prom_strcmp(type, buf) == 0)
		return (1);

	return (0);
}

int
prom_getnode_byname(pnode_t id, char *name)
{
	int len;
	char buf[OBP_MAXDRVNAME];

	len = prom_getproplen(id, OBP_NAME);
	if (len <= 0 || len >= OBP_MAXDRVNAME)
		return (0);

	(void) prom_getprop(id, OBP_NAME, (caddr_t)buf);

	if (prom_strcmp(name, buf) == 0)
		return (1);

	return (0);
}
