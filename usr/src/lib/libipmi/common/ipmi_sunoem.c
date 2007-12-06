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
#include <stddef.h>

#include "ipmi_impl.h"

#define	IPMI_CMD_SUNOEM_LED_GET		0x21
#define	IPMI_CMD_SUNOEM_LED_SET		0x22

typedef struct ipmi_cmd_sunoem_led_set {
	DECL_BITFIELD2(
	    ic_sls_channel_msb		:1,	/* device slave address */
	    ic_sls_slaveaddr		:7);	/* (from SDR record) */
	uint8_t		ic_sls_type;		/* led type */
	DECL_BITFIELD2(
	    __reserved			:1,	/* device access address */
	    ic_sls_accessaddr		:7);	/* (from SDR record */
	uint8_t		ic_sls_hwinfo;		/* OEM hardware info */
	uint8_t		ic_sls_mode;		/* LED mode */
	uint8_t		ic_sls_force;		/* force direct access */
	uint8_t		ic_sls_role;		/* BMC authorization */
} ipmi_cmd_sunoem_led_set_t;

typedef struct ipmi_cmd_sunoem_led_get {
	DECL_BITFIELD2(
	    ic_slg_channel_msb		:1,	/* device slave address */
	    ic_slg_slaveaddr		:7);	/* (from SDR record) */
	uint8_t		ic_slg_type;		/* led type */
	DECL_BITFIELD2(
	    __reserved			:1,	/* device access address */
	    ic_slg_accessaddr		:7);	/* (from SDR record */
	uint8_t		ic_slg_hwinfo;		/* OEM hardware info */
	uint8_t		ic_slg_force;		/* force direct access */
} ipmi_cmd_sunoem_led_get_t;

#define	IPMI_SUNOEM_LED_TYPE_OK2RM	0
#define	IPMI_SUNOEM_LED_TYPE_SERVICE	1
#define	IPMI_SUNOEM_LED_TYPE_ACT	2
#define	IPMI_SUNOEM_LED_TYPE_LOCATE	3
#define	IPMI_SUNOEM_LED_TYPE_ANY	0xFF

static int
check_sunoem(ipmi_handle_t *ihp)
{
	ipmi_deviceid_t *devid;

	if ((devid = ipmi_get_deviceid(ihp)) == NULL)
		return (-1);

	if (ipmi_devid_manufacturer(devid) != IPMI_OEM_SUN)
		return (ipmi_set_error(ihp, EIPMI_INVALID_COMMAND, NULL));

	return (0);
}

static int
ipmi_send_sunoem_led_set(ipmi_handle_t *ihp, ipmi_cmd_sunoem_led_set_t *req)
{
	ipmi_cmd_t cmd, *resp;

	cmd.ic_netfn = IPMI_NETFN_OEM;
	cmd.ic_cmd = IPMI_CMD_SUNOEM_LED_SET;
	cmd.ic_lun = 0;
	cmd.ic_data = req;
	cmd.ic_dlen = sizeof (*req);

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	if (resp->ic_dlen != 0)
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));

	return (0);
}

static int
ipmi_send_sunoem_led_get(ipmi_handle_t *ihp, ipmi_cmd_sunoem_led_get_t *req,
    uint8_t *result)
{
	ipmi_cmd_t cmd, *resp;

	cmd.ic_netfn = IPMI_NETFN_OEM;
	cmd.ic_cmd = IPMI_CMD_SUNOEM_LED_GET;
	cmd.ic_lun = 0;
	cmd.ic_data = req;
	cmd.ic_dlen = sizeof (*req);

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	if (resp->ic_dlen != 1)
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));

	*result = *((uint8_t *)resp->ic_data);
	return (0);
}

int
ipmi_sunoem_led_set(ipmi_handle_t *ihp, ipmi_sdr_generic_locator_t *dev,
    uint8_t mode)
{
	ipmi_cmd_sunoem_led_set_t cmd = { 0 };

	if (check_sunoem(ihp) != 0)
		return (-1);

	cmd.ic_sls_slaveaddr = dev->is_gl_slaveaddr;
	cmd.ic_sls_channel_msb = dev->is_gl_channel_msb;
	cmd.ic_sls_type = dev->is_gl_oem;
	cmd.ic_sls_accessaddr = dev->is_gl_accessaddr;
	cmd.ic_sls_hwinfo = dev->is_gl_oem;
	cmd.ic_sls_mode = mode;

	return (ipmi_send_sunoem_led_set(ihp, &cmd));
}

int
ipmi_sunoem_led_get(ipmi_handle_t *ihp, ipmi_sdr_generic_locator_t *dev,
    uint8_t *mode)
{
	ipmi_cmd_sunoem_led_get_t cmd = { 0 };

	if (check_sunoem(ihp) != 0)
		return (-1);

	cmd.ic_slg_slaveaddr = dev->is_gl_slaveaddr;
	cmd.ic_slg_channel_msb = dev->is_gl_channel_msb;
	cmd.ic_slg_type = dev->is_gl_oem;
	cmd.ic_slg_accessaddr = dev->is_gl_accessaddr;
	cmd.ic_slg_hwinfo = dev->is_gl_oem;

	return (ipmi_send_sunoem_led_get(ihp, &cmd, mode));
}

int
ipmi_sunoem_uptime(ipmi_handle_t *ihp, uint32_t *uptime, uint32_t *gen)
{
	ipmi_cmd_t cmd, *resp;
	uint8_t unused;

	if (check_sunoem(ihp) != 0)
		return (-1);

	cmd.ic_netfn = IPMI_NETFN_OEM;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_SUNOEM_UPTIME;
	cmd.ic_dlen = sizeof (unused);
	cmd.ic_data = &unused;

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	if (resp->ic_dlen != 2 * sizeof (uint32_t))
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));

	if (uptime)
		*uptime = BE_32(((uint32_t *)resp->ic_data)[0]);
	if (gen)
		*gen = BE_32(((uint32_t *)resp->ic_data)[1]);

	return (0);
}

int
ipmi_sunoem_update_fru(ipmi_handle_t *ihp, ipmi_sunoem_fru_t *req)
{
	ipmi_cmd_t cmd, *resp;

	if (check_sunoem(ihp) != 0)
		return (-1);

	switch (req->isf_type) {
	case IPMI_SUNOEM_FRU_DIMM:
		req->isf_datalen = sizeof (req->isf_data.dimm);
		break;

	case IPMI_SUNOEM_FRU_CPU:
		req->isf_datalen = sizeof (req->isf_data.cpu);
		break;

	case IPMI_SUNOEM_FRU_BIOS:
		req->isf_datalen = sizeof (req->isf_data.bios);
		break;

	case IPMI_SUNOEM_FRU_DISK:
		req->isf_datalen = sizeof (req->isf_data.disk);
		break;
	}

	cmd.ic_netfn = IPMI_NETFN_OEM;
	cmd.ic_cmd = IPMI_CMD_SUNOEM_FRU_UPDATE;
	cmd.ic_lun = 0;
	cmd.ic_dlen = offsetof(ipmi_sunoem_fru_t, isf_data) +
	    req->isf_datalen;
	cmd.ic_data = req;

	if ((resp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	if (resp->ic_dlen != 0)
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));

	return (0);
}
