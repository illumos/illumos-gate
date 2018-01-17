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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2017, Joyent, Inc.
 */
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
	(void) memcpy(&ihp->ih_deviceid->id_product, &id_prod,
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

/*
 * IPMI Get Channel Authentication Capabilities Command
 * See Section 22.13
 *
 * Caller is responsible for free'ing returned ipmi_channel_auth_caps_t
 */
ipmi_channel_auth_caps_t *
ipmi_get_channel_auth_caps(ipmi_handle_t *ihp, uint8_t channel, uint8_t priv)
{
	ipmi_cmd_t cmd, *resp;
	uint8_t msg_data[2];
	ipmi_channel_auth_caps_t *caps;

	if (channel > 0xF) {
		(void) ipmi_set_error(ihp, EIPMI_INVALID_REQUEST, NULL);
		return (NULL);
	}

	msg_data[0] = channel;
	msg_data[1] = priv;

	cmd.ic_netfn = IPMI_NETFN_APP;
	cmd.ic_cmd = IPMI_CMD_GET_CHANNEL_AUTH_CAPS;
	cmd.ic_data = msg_data;
	cmd.ic_dlen = sizeof (msg_data);
	cmd.ic_lun = 0;

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (NULL);

	if (resp->ic_dlen < sizeof (ipmi_channel_auth_caps_t)) {
		(void) ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL);
		return (NULL);
	}

	if ((caps = ipmi_alloc(ihp, sizeof (ipmi_channel_auth_caps_t)))
	    == NULL)
		/* ipmi errno set */
		return (NULL);

	(void) memcpy(caps, resp->ic_data, sizeof (ipmi_channel_auth_caps_t));

	return (caps);
}

ipmi_channel_info_t *
ipmi_get_channel_info(ipmi_handle_t *ihp, int number)
{
	ipmi_cmd_t cmd, *rsp;
	uint8_t channel;

	if (number > 0xF) {
		(void) ipmi_set_error(ihp, EIPMI_INVALID_REQUEST, NULL);
		return (NULL);
	}

	channel = (uint8_t)number;

	cmd.ic_netfn = IPMI_NETFN_APP;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_CHANNEL_INFO;
	cmd.ic_data = &channel;
	cmd.ic_dlen = sizeof (channel);

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL)
		return (NULL);

	if (rsp->ic_dlen < sizeof (ipmi_channel_info_t)) {
		(void) ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL);
		return (NULL);
	}

	return (rsp->ic_data);
}

/*
 * IPMI Chassis Identify Command
 * See Section 28.5
 */
int
ipmi_chassis_identify(ipmi_handle_t *ihp, boolean_t enable)
{
	ipmi_cmd_t cmd;
	uint8_t msg_data[2];

	if (enable) {
		msg_data[0] = 0;
		msg_data[1] = 1;
	} else {
		msg_data[0] = 0;
		msg_data[1] = 0;
	}

	cmd.ic_netfn = IPMI_NETFN_CHASSIS;
	cmd.ic_cmd = IPMI_CMD_CHASSIS_IDENTIFY;
	cmd.ic_data = msg_data;
	cmd.ic_dlen = sizeof (msg_data);
	cmd.ic_lun = 0;

	if (ipmi_send(ihp, &cmd) == NULL)
		return (-1);

	return (0);
}

/*
 * caller is responsible for free'ing returned structure
 */
ipmi_chassis_status_t *
ipmi_chassis_status(ipmi_handle_t *ihp)
{
	ipmi_cmd_t cmd, *rsp;
	ipmi_chassis_status_t *chs;

	cmd.ic_netfn = IPMI_NETFN_CHASSIS;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_CHASSIS_STATUS;
	cmd.ic_data = NULL;
	cmd.ic_dlen = 0;

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL)
		return (NULL);

	if (rsp->ic_dlen < sizeof (ipmi_chassis_status_t)) {
		(void) ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL);
		return (NULL);
	}

	if ((chs = ipmi_alloc(ihp, sizeof (ipmi_chassis_status_t))) == NULL) {
		/* ipmi errno set */
		return (NULL);
	}

	(void) memcpy(chs, rsp->ic_data, sizeof (ipmi_chassis_status_t));
	return (chs);
}
