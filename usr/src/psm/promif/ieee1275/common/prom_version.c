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
 * Copyright (c) 1991-1994, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

int
prom_getversion(void)
{

	/*
	 * For compatibility with older client programs, if there is no
	 * ROMVEC, we simply return a very large number here.
	 */
	return (obp_romvec_version);
}

int
prom_is_openprom(void)
{
	/*
	 * Returns true, if openboot or open firmware interface exists.
	 */
	return (1);
}

int
prom_is_p1275(void)
{
	/*
	 * Returns true, if IEEE 1275 interface exists.
	 */
	return (1);
}

/*
 * Certain standalones need to get the revision of a certain
 * version of the firmware to be able to figure out how to
 * correct for certain errors in certain versions of the PROM.
 *
 * The caller has to know what to do with the cookie returned
 * from prom_mon_id(). c.f. uts/sun4c/io/autoconf.c:impl_fix_props().
 */

void *
prom_mon_id(void)
{
	return (NULL);		/* For compatibilty, none exists in 1275 */
}
