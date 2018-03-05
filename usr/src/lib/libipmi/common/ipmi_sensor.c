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
/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <libipmi.h>
#include <string.h>

#include "ipmi_impl.h"

ipmi_sensor_reading_t *
ipmi_get_sensor_reading(ipmi_handle_t *ihp, uint8_t id)
{
	ipmi_cmd_t cmd, *resp;
	ipmi_sensor_reading_t *srp;

	cmd.ic_netfn = IPMI_NETFN_SE;
	cmd.ic_cmd = IPMI_CMD_GET_SENSOR_READING;
	cmd.ic_lun = 0;
	cmd.ic_data = &id;
	cmd.ic_dlen = sizeof (id);

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (NULL);

	/*
	 * The upper half of the state field is optional, so if it's not
	 * present, then set it to zero.  We also need to convert to the
	 * native endianness.
	 */
	if (resp->ic_dlen < sizeof (ipmi_sensor_reading_t) - sizeof (uint8_t)) {
		(void) ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL);
		return (NULL);
	}
	srp = resp->ic_data;

	if (resp->ic_dlen < sizeof (ipmi_sensor_reading_t))
		(void) memset((char *)srp + resp->ic_dlen, '\0',
		    sizeof (ipmi_sensor_reading_t) - resp->ic_dlen);

	srp->isr_state = LE_IN16(&srp->isr_state);
	return (srp);
}

int
ipmi_set_sensor_reading(ipmi_handle_t *ihp, ipmi_set_sensor_reading_t *req)
{
	ipmi_set_sensor_reading_t realreq;
	ipmi_cmd_t cmd, *resp;
	uint16_t tmp;

	/*
	 * Convert states to little endian.
	 */
	(void) memcpy(&realreq, req, sizeof (realreq));

	tmp = LE_IN16(&realreq.iss_assert_state);
	(void) memcpy(&realreq.iss_assert_state, &tmp, sizeof (tmp));
	tmp = LE_IN16(&realreq.iss_deassert_state);
	(void) memcpy(&realreq.iss_deassert_state, &tmp, sizeof (tmp));

	cmd.ic_netfn = IPMI_NETFN_SE;
	cmd.ic_cmd = IPMI_CMD_SET_SENSOR_READING;
	cmd.ic_lun = 0;
	cmd.ic_data = &realreq;
	cmd.ic_dlen = sizeof (realreq);

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	if (resp->ic_dlen != 0)
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));

	return (0);
}

int
ipmi_get_sensor_thresholds(ipmi_handle_t *ihp, ipmi_sensor_thresholds_t *thresh,
    uint8_t id)
{
	ipmi_cmd_t cmd, *resp;

	cmd.ic_netfn = IPMI_NETFN_SE;
	cmd.ic_cmd = IPMI_CMD_GET_SENSOR_THRESHOLDS;
	cmd.ic_lun = 0;
	cmd.ic_data = &id;
	cmd.ic_dlen = sizeof (id);

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	if (resp->ic_dlen < sizeof (ipmi_sensor_thresholds_t)) {
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));
	}

	(void) memcpy(thresh, resp->ic_data, sizeof (ipmi_sensor_thresholds_t));

	return (0);
}
