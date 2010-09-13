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

/*
 * Return ihandle of stdout
 */
ihandle_t
prom_stdout_ihandle(void)
{
	static ihandle_t istdout;
	static char *name = "stdout";

	if (istdout)
		return (istdout);

	if (prom_getproplen(prom_chosennode(), name) !=
	    sizeof (ihandle_t))  {
		return (istdout = (ihandle_t)-1);
	}
	(void) prom_getprop(prom_chosennode(), name,
	    (caddr_t)(&istdout));
	istdout = prom_decode_int(istdout);
	return (istdout);

}

/*
 * Return phandle of stdout
 */
pnode_t
prom_stdout_node(void)
{
	static phandle_t pstdout;
	ihandle_t istdout;

	if (pstdout)
		return (pstdout);

	if ((istdout = prom_stdout_ihandle()) == (ihandle_t)-1)
		return (pstdout = (pnode_t)OBP_BADNODE);

	return (pstdout = prom_getphandle(istdout));
}
