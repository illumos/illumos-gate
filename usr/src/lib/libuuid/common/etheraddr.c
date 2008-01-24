/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <stropts.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <sys/sockio.h>
#include <libdlpi.h>
#include <sys/utsname.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "etheraddr.h"

static boolean_t get_etheraddr(const char *linkname, void *arg);

/*
 * get an individual arp entry
 */
int
arp_get(uuid_node_t *node)
{
	struct utsname name;
	struct arpreq ar;
	struct hostent *hp;
	struct sockaddr_in *sin;
	int s;

	if (uname(&name) == -1) {
		return (-1);
	}
	(void) memset(&ar, 0, sizeof (ar));
	ar.arp_pa.sa_family = AF_INET;
	/* LINTED pointer */
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr(name.nodename);
	if (sin->sin_addr.s_addr == (in_addr_t)-1) {
		hp = gethostbyname(name.nodename);
		if (hp == NULL) {
			return (-1);
		}
		(void) memcpy(&sin->sin_addr, hp->h_addr,
		    sizeof (sin->sin_addr));
	}
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		return (-1);
	}
	if (ioctl(s, SIOCGARP, (caddr_t)&ar) < 0) {
		(void) close(s);
		return (-1);
	}
	(void) close(s);
	if (ar.arp_flags & ATF_COM) {
		bcopy(&ar.arp_ha.sa_data, node, 6);
	} else
		return (-1);
	return (0);
}

/*
 * Name:	get_ethernet_address
 *
 * Description:	Obtains the system ethernet address.
 *
 * Returns:	0 on success, non-zero otherwise.  The system ethernet
 *		address is copied into the passed-in variable.
 */
int
get_ethernet_address(uuid_node_t *node)
{
	walker_arg_t	state;

	if (arp_get(node) == 0)
		return (0);

	/*
	 * Try to get physical (ethernet) address from network interfaces.
	 */
	state.wa_addrvalid = B_FALSE;
	dlpi_walk(get_etheraddr, &state, 0);
	if (state.wa_addrvalid)
		bcopy(state.wa_etheraddr, node, state.wa_etheraddrlen);

	return (state.wa_addrvalid ? 0 : -1);
}

/*
 * Get the physical address via DLPI and update the flag to true upon success.
 */
static boolean_t
get_etheraddr(const char *linkname, void *arg)
{
	int		retval;
	dlpi_handle_t	dh;
	walker_arg_t	*statep = arg;

	if (dlpi_open(linkname, &dh, 0) != DLPI_SUCCESS)
		return (B_FALSE);

	statep->wa_etheraddrlen = DLPI_PHYSADDR_MAX;
	retval = dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR,
	    statep->wa_etheraddr, &(statep->wa_etheraddrlen));

	dlpi_close(dh);

	if (retval == DLPI_SUCCESS) {
		statep->wa_addrvalid = B_TRUE;
		return (B_TRUE);
	}
	return (B_FALSE);
}
