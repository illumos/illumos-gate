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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libipmi.h>
#include <string.h>

#include "ipmi_impl.h"

ipmi_deviceid_t *
ipmi_get_deviceid(ipmi_handle_t *ihp)
{
	ipmi_cmd_t cmd, *resp;

	if (ihp->ih_deviceid_valid)
		return (&ihp->ih_deviceid);

	cmd.ic_netfn = IPMI_NETFN_APP;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_DEVICEID;
	cmd.ic_data = NULL;
	cmd.ic_dlen = 0;

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (NULL);

	if (resp->ic_dlen < sizeof (ipmi_deviceid_t)) {
		(void) ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL);
		return (NULL);
	}

	(void) memcpy(&ihp->ih_deviceid, resp->ic_data,
	    sizeof (ipmi_deviceid_t));
	ihp->ih_deviceid.id_product = LE_16(ihp->ih_deviceid.id_product);
	ihp->ih_deviceid_valid = B_TRUE;

	return (&ihp->ih_deviceid);
}
