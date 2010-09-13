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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * If the stdin device exports the "keyboard" property and
 * the length of the property is 0, return true.  Otherwise,
 * check the name of the stdin device node.  If the name is
 * "keyboard" return true, else return false.
 * XXX: The "keyboard" property is not part of the IEEE 1275 standard.
 * XXX: Perhaps this belongs in platform dependent directories?
 */
int
prom_stdin_is_keyboard(void)
{
	char dev_name[OBP_MAXDRVNAME];

	/*
	 * NB: A keyboard property with a value might be an alias
	 * or something else so we distinguish it by length.
	 */
	if (prom_getproplen(prom_stdin_node(), "keyboard") == 0)
		return (1);

	if (prom_stdin_devname(dev_name) == -1)
		return (0);

	return (prom_strcmp(dev_name, "keyboard") == 0);
}
