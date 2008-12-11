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
 * Query and configure LAN interfaces over IPMI.  This is done through the
 * complicated get/set LAN Configuration Parameters command.  This queries or
 * sets the parameters one per command in series.  We hide this implementation
 * detail and instead export a single structure to consumers.
 */

#include <stddef.h>
#include <strings.h>

#include <libipmi.h>

#include "ipmi_impl.h"

typedef struct ipmi_cmd_lan_get_config {
	DECL_BITFIELD3(
	    ilgc_number		:4,
	    __reserved		:3,
	    ilgc_revonly	:1);
	uint8_t		ilgc_param;
	uint8_t		ilgc_set;
	uint8_t		ilgc_block;
} ipmi_cmd_lan_get_config_t;

typedef struct ipmi_cmd_lan_set_config {
	DECL_BITFIELD2(
	    ilsc_number		:4,
	    __reserved		:4);
	uint8_t		ilsc_param;
	uint8_t		ilsc_data[18];
} ipmi_cmd_lan_set_config_t;

#define	IPMI_LAN_SET_LEN(dlen)	\
	(offsetof(ipmi_cmd_lan_set_config_t, ilsc_data) + (dlen))

#define	IPMI_LAN_PARAM_SET_IN_PROGRESS		0
#define	IPMI_LAN_PARAM_IP_ADDR			3
#define	IPMI_LAN_PARAM_IP_SOURCE		4
#define	IPMI_LAN_PARAM_MAC_ADDR			5
#define	IPMI_LAN_PARAM_SUBNET_MASK		6
#define	IPMI_LAN_PARAM_GATEWAY_ADDR		12

#define	IPMI_LAN_SET_COMPLETE			0x0
#define	IPMI_LAN_SET_INPROGRESS			0x1
#define	IPMI_LAN_SET_COMMIT			0x2

typedef struct ipmi_lan_entry {
	int	ile_param;
	int	ile_mask;
	int	ile_set;
	int	ile_block;
	size_t	ile_offset;
	size_t	ile_len;
} ipmi_lan_entry_t;

static ipmi_lan_entry_t ipmi_lan_table[] = {
	{ IPMI_LAN_PARAM_IP_ADDR, IPMI_LAN_SET_IPADDR, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_ipaddr), sizeof (uint32_t) },
	{ IPMI_LAN_PARAM_IP_SOURCE, IPMI_LAN_SET_IPADDR_SOURCE, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_ipaddr_source), sizeof (uint8_t) },
	{ IPMI_LAN_PARAM_MAC_ADDR, IPMI_LAN_SET_MACADDR, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_macaddr), 6 * sizeof (uint8_t) },
	{ IPMI_LAN_PARAM_SUBNET_MASK, IPMI_LAN_SET_SUBNET, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_subnet), sizeof (uint32_t) },
	{ IPMI_LAN_PARAM_GATEWAY_ADDR, IPMI_LAN_SET_GATEWAY_ADDR, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_gateway_addr), sizeof (uint32_t) }
};

#define	IPMI_LAN_NENTRIES	\
	(sizeof (ipmi_lan_table) / sizeof (ipmi_lan_table[0]))

static int
ipmi_lan_get_param(ipmi_handle_t *ihp, int channel, int param, int set,
    int block, void *data, size_t len)
{
	ipmi_cmd_t cmd, *rsp;
	ipmi_cmd_lan_get_config_t lcmd = { 0 };

	lcmd.ilgc_number = channel;
	lcmd.ilgc_param = param;
	lcmd.ilgc_set = set;
	lcmd.ilgc_block = block;

	cmd.ic_netfn = IPMI_NETFN_TRANSPORT;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_LAN_CONFIG;
	cmd.ic_data = &lcmd;
	cmd.ic_dlen = sizeof (lcmd);

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL) {
		switch (ihp->ih_completion) {
		case 0x80:
			(void) ipmi_set_error(ihp, EIPMI_BADPARAM, NULL);
			break;
		}
		return (-1);
	}

	if (rsp->ic_dlen < len + 1)
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));

	bcopy((uint8_t *)rsp->ic_data + 1, data, len);

	return (0);
}

int
ipmi_lan_get_config(ipmi_handle_t *ihp, int channel, ipmi_lan_config_t *cfgp)
{
	uint8_t set;
	int i;
	ipmi_lan_entry_t *lep;

	if (ipmi_lan_get_param(ihp, channel, IPMI_LAN_PARAM_SET_IN_PROGRESS, 0,
	    0, &set, sizeof (set)) != 0)
		return (-1);

	if (set & IPMI_LAN_SET_INPROGRESS)
		cfgp->ilc_set_in_progress = B_TRUE;
	else
		cfgp->ilc_set_in_progress = B_FALSE;

	for (i = 0; i < IPMI_LAN_NENTRIES; i++) {
		lep = &ipmi_lan_table[i];
		if (ipmi_lan_get_param(ihp, channel, lep->ile_param,
		    lep->ile_set, lep->ile_block,
		    (char *)cfgp + lep->ile_offset, lep->ile_len) != 0)
			return (-1);
	}

	return (0);
}

static int
ipmi_lan_set_param(ipmi_handle_t *ihp, int channel, int param, void *data,
    size_t len)
{
	ipmi_cmd_t cmd;
	ipmi_cmd_lan_set_config_t lcmd = { 0 };

	lcmd.ilsc_number = channel;
	lcmd.ilsc_param = param;
	bcopy(data, lcmd.ilsc_data, len);

	cmd.ic_netfn = IPMI_NETFN_TRANSPORT;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_SET_LAN_CONFIG;
	cmd.ic_data = &lcmd;
	cmd.ic_dlen = IPMI_LAN_SET_LEN(len);

	if (ipmi_send(ihp, &cmd) == NULL) {
		switch (ihp->ih_completion) {
		case 0x80:
			(void) ipmi_set_error(ihp, EIPMI_BADPARAM, NULL);
			break;

		case 0x81:
			(void) ipmi_set_error(ihp, EIPMI_BUSY, NULL);
			break;

		case 0x82:
			(void) ipmi_set_error(ihp, EIPMI_READONLY, NULL);
			break;

		case 0x83:
			(void) ipmi_set_error(ihp, EIPMI_WRITEONLY, NULL);
			break;
		}
		return (-1);
	}

	return (0);
}

int
ipmi_lan_set_config(ipmi_handle_t *ihp, int channel, ipmi_lan_config_t *cfgp,
    int mask)
{
	uint8_t set;
	int i;
	ipmi_lan_entry_t *lep;

	/*
	 * Cancel any pending transaction, then open a new transaction.
	 */
	set = IPMI_LAN_SET_COMPLETE;
	if (ipmi_lan_set_param(ihp, channel, IPMI_LAN_PARAM_SET_IN_PROGRESS,
	    &set, sizeof (set)) != 0)
		return (-1);
	set = IPMI_LAN_SET_INPROGRESS;
	if (ipmi_lan_set_param(ihp, channel, IPMI_LAN_PARAM_SET_IN_PROGRESS,
	    &set, sizeof (set)) != 0)
		return (-1);

	/*
	 * Iterate over all parameters and set them.
	 */
	for (i = 0; i < IPMI_LAN_NENTRIES; i++) {
		lep = &ipmi_lan_table[i];
		if (!(lep->ile_mask & mask))
			continue;

		if (ipmi_lan_set_param(ihp, channel, lep->ile_param,
		    (char *)cfgp + lep->ile_offset, lep->ile_len) != 0) {
			/*
			 * On some systems, setting the mode to DHCP may cause
			 * the command to timeout, presumably because it is
			 * waiting for the setting to take effect.  If we see
			 * completion code 0xc3 (command timeout) while setting
			 * the DHCP value, just ignore it.
			 */
			if (mask != IPMI_LAN_SET_IPADDR_SOURCE ||
			    cfgp->ilc_ipaddr_source != IPMI_LAN_SRC_DHCP ||
			    ihp->ih_completion != 0xC3)
				return (-1);
		}
	}

	/*
	 * Commit the transaction.
	 */
	set = IPMI_LAN_SET_COMPLETE;
	if (ipmi_lan_set_param(ihp, channel, IPMI_LAN_PARAM_SET_IN_PROGRESS,
	    &set, sizeof (set)) != 0)
		return (-1);

	return (0);
}
