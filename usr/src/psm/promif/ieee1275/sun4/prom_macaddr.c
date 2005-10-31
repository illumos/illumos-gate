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
 * Return our machine address in the single argument.
 */

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/idprom.h>

/*ARGSUSED*/
int
prom_getmacaddr(ihandle_t hd, caddr_t ea)
{
	idprom_t idprom;
	pnode_t macnodeid;

	/*
	 * Look for the 'mac-address' property in the device node
	 * associated with the ihandle 'hd'. This handles the
	 * cases when we booted from the network device, using either
	 * the platform mac address or a local mac address. This
	 * code will always return whichever mac-address was used by the
	 * firmware (local or platform, depending on nvram settings).
	 */
	macnodeid = prom_getphandle(hd);
	if (macnodeid != OBP_BADNODE) {
		if (prom_getproplen(macnodeid, OBP_MAC_ADDR) != -1) {
			(void) prom_getprop(macnodeid, OBP_MAC_ADDR, ea);
			return (0);
		}
	}

	/*
	 * The code above, should have taken care of the case
	 * when we booted from the device ... otherwise, as a fallback
	 * case, return the system mac address from the idprom.
	 * This code (idprom) is SMCC (and compatibles) platform-centric.
	 * This code always returns the platform mac address.
	 */
	if (prom_getidprom((caddr_t)&idprom, sizeof (idprom)) == 0) {
		char *f = (char *)idprom.id_ether;
		char *t = ea;
		int i;

		for (i = 0; i < sizeof (idprom.id_ether); ++i)
			*t++ = *f++;

		return (0);
	} else
		return (-1); /* our world must be starting to explode */
}
