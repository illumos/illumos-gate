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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libfcoe.h>
#include <locale.h>

int
main()
{
	FCOE_STATUS	status;
	PFCOE_SMF_PORT_LIST portlist = NULL;
	PFCOE_SMF_PORT_INSTANCE port = NULL;
	int i;
	int ret;

	(void) setlocale(LC_ALL, "");

	status = FCOE_LoadConfig(FCOE_PORTTYPE_INITIATOR, &portlist);

	if (status != FCOE_STATUS_OK) {
		ret = 1;
	} else if (portlist == NULL) {
		return (0);
	} else {
		for (i = 0; i < portlist->port_num; i++) {
			port = &portlist->ports[i];
			if (port->port_type == FCOE_PORTTYPE_INITIATOR) {
				(void) FCOE_CreatePort(port->mac_link_name,
				    port->port_type,
				    port->port_pwwn,
				    port->port_nwwn,
				    port->mac_promisc);
			}
		}
		ret = 0;
	}

	if (portlist != NULL) {
		free(portlist);
	}
	return (ret);
} /* end main */
