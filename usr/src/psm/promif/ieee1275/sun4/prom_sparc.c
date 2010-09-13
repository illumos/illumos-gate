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
 * Copyright 1991-1993,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * P1275 Client Interface Functions defined for SPARC.
 * This file belongs in a platform dependent area.
 */

/*
 * This function returns NULL or a a verified client interface structure
 * pointer to the caller.
 */

int (*cif_handler)(void *);

void *
p1275_sparc_cif_init(void *cookie)
{
	cif_handler = (int (*)(void *))cookie;
	return ((void *)cookie);
}

int
p1275_sparc_cif_handler(void *p)
{
	int rv;

	if (cif_handler == NULL)
		return (-1);

	rv = client_handler((void *)cif_handler, p);
	return (rv);
}
