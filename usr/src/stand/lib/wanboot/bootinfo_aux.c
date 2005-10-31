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

#include <sys/types.h>
#include <dhcp_impl.h>
#include <sys/promif.h>
#include <strings.h>
#include <sys/salib.h>
#include <dhcpv4.h>
#include <bootinfo.h>
#include <bootinfo_aux.h>

/*
 * Functions dealing with bootinfo initialization/cleanup.
 * Both no-ops in the standalone.
 */
boolean_t
bi_init_bootinfo(void)
{
	return (B_TRUE);
}

void
bi_end_bootinfo(void)
{
}

/*
 * Functions dealing with /chosen data.
 */
boolean_t
bi_get_chosen_prop(const char *name, void *valbuf, size_t *vallenp)
{
	static pnode_t	chosen;
	int		len;

	/*
	 * The standalone helpfully provides a function for getting a
	 * handle on /chosen; it prom_panic()'s if /chosen doesn't exist.
	 */
	if (chosen == OBP_NONODE) {
		chosen = prom_chosennode();
	}

	/*
	 * Check for the existence/size of a property with name 'name';
	 * if found, and the receiving buffer is big enough, copy its value.
	 * If not, return the length of the buffer that would be needed
	 * to fullfill the request.
	 */
	if ((len = prom_getproplen(chosen, (char *)name)) == -1) {
		return (B_FALSE);
	}
	if (len <= *vallenp) {
		if (prom_getprop(chosen, (char *)name, (caddr_t)valbuf) == -1) {
			return (B_FALSE);
		}
	}
	*vallenp = len;

	return (B_TRUE);
}

boolean_t
bi_put_chosen_prop(const char *name, const void *valbuf, size_t vallen,
    boolean_t bytes)
{
	/*
	 * Add this property to /chosen.
	 */
	prom_create_encoded_prop((char *)name, (void *)valbuf, vallen,
	    (bytes ? ENCODE_BYTES : ENCODE_STRING));

	return (B_TRUE);
}

/*
 * Function dealing with DHCP data.
 */
boolean_t
bi_get_dhcp_info(uchar_t optcat, uint16_t optcode, uint16_t optsize,
    void *valbuf, size_t *vallenp)
{
	return (dhcp_getinfo_pl(state_pl, optcat, optcode, optsize, valbuf,
	    vallenp));
}
