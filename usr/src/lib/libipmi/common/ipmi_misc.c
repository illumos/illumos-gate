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

#include <libipmi.h>
#include <stdio.h>
#include <string.h>

#include "ipmi_impl.h"

ipmi_deviceid_t *
ipmi_get_deviceid(ipmi_handle_t *ihp)
{
	ipmi_cmd_t cmd, *resp;
	uint16_t id_prod;

	if (ihp->ih_deviceid != NULL)
		return (ihp->ih_deviceid);

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

	/*
	 * The devid response data may include additional data beyond the end of
	 * the normal structure, so we copy the entire response.
	 */
	if ((ihp->ih_deviceid = ipmi_alloc(ihp, resp->ic_dlen)) == NULL)
		return (NULL);

	(void) memcpy(ihp->ih_deviceid, resp->ic_data, resp->ic_dlen);
	id_prod = LE_IN16(&ihp->ih_deviceid->id_product);
	(void) memcpy(&id_prod, &ihp->ih_deviceid->id_product,
	    sizeof (id_prod));
	ihp->ih_deviceid_len = resp->ic_dlen;

	return (ihp->ih_deviceid);
}

/*
 * Returns the firmware revision as a string.  This does the work of converting
 * the deviceid data into a human readable string (decoding the BCD values).
 * It also encodes the fact that Sun ILOM includes the additional micro revision
 * at the end of the deviceid information.
 */
const char *
ipmi_firmware_version(ipmi_handle_t *ihp)
{
	ipmi_deviceid_t *dp;
	uint8_t *auxrev;
	size_t len;
	char rev[128];
	int i;

	if (ihp->ih_firmware_rev != NULL)
		return (ihp->ih_firmware_rev);

	if ((dp = ipmi_get_deviceid(ihp)) == NULL)
		return (NULL);

	/*
	 * Start with the major an minor revision numbers
	 */
	(void) snprintf(rev, sizeof (rev), "%d.%d", dp->id_firm_major,
	    ipmi_convert_bcd(dp->id_firm_minor));

	if (ipmi_is_sun_ilom(dp) &&
	    ihp->ih_deviceid_len >= sizeof (ipmi_deviceid_t) + 4) {
		/*
		 * With Sun ILOM we have the micro revision at the end of the
		 * deviceid.  The first two bytes of the aux revision field are
		 * the platform version and release version.
		 */
		auxrev = (uint8_t *)dp + sizeof (ipmi_deviceid_t);
		for (i = 0; i < 2; i++) {
			if (auxrev[i] == 0)
				continue;

			len = strlen(rev);
			(void) snprintf(rev + len, sizeof (rev) - len, ".%u",
			    auxrev[i]);
		}
	}

	if ((ihp->ih_firmware_rev = ipmi_strdup(ihp, rev)) == NULL)
		return (NULL);

	return (ihp->ih_firmware_rev);
}
