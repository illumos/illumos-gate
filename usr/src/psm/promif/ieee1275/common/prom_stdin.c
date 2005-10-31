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
 * Return ihandle of stdin
 */
ihandle_t
prom_stdin_ihandle(void)
{
	static ihandle_t istdin;
	static char *name = "stdin";

	if (istdin)
		return (istdin);

	if (prom_getproplen(prom_chosennode(), name) !=
	    sizeof (ihandle_t))  {
#if defined(PROMIF_DEBUG) || defined(lint)
		prom_fatal_error("No stdout ihandle?");
#endif
		return (istdin = (ihandle_t)-1);
	}
	(void) prom_getprop(prom_chosennode(), name,
	    (caddr_t)(&istdin));
	istdin = prom_decode_int(istdin);
	return (istdin);
}

/*
 * Return phandle of stdin
 */
pnode_t
prom_stdin_node(void)
{
	static phandle_t pstdin;
	ihandle_t istdin;

	if (pstdin)
		return (pstdin);

	if ((istdin = prom_stdin_ihandle()) == (ihandle_t)-1)
		return (pstdin = (pnode_t)OBP_BADNODE);

	return (pstdin = prom_getphandle(istdin));
}
