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
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "ipmi_impl.h"

/*
 * 31.2 Get SEL Info Command.
 */
ipmi_sel_info_t *
ipmi_sel_get_info(ipmi_handle_t *ihp)
{
	ipmi_cmd_t cmd, *rsp;
	ipmi_sel_info_t *ip;

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_SEL_INFO;
	cmd.ic_dlen = 0;
	cmd.ic_data = NULL;

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL)
		return (NULL);

	ip = (ipmi_sel_info_t *)rsp->ic_data;

	ip->isel_entries = LE_IN16(&ip->isel_entries);
	ip->isel_free = LE_IN16(&ip->isel_free);
	ip->isel_add_ts = LE_IN32(&ip->isel_add_ts);
	ip->isel_erase_ts = LE_IN32(&ip->isel_erase_ts);

	return (ip);
}

typedef struct ipmi_cmd_get_sel_entry {
	uint16_t	ic_sel_ent_resid;
	uint16_t	ic_sel_ent_recid;
	uint8_t		ic_sel_ent_offset;
	uint8_t		ic_sel_ent_bytes;
} ipmi_cmd_get_sel_entry_t;

ipmi_sel_event_t *
ipmi_sel_get_entry(ipmi_handle_t *ihp, uint16_t id)
{
	ipmi_cmd_t cmd, *rsp;
	ipmi_sel_event_t *evp;
	ipmi_cmd_get_sel_entry_t data;

	data.ic_sel_ent_resid = 0;
	data.ic_sel_ent_recid = LE_16(id);
	data.ic_sel_ent_offset = 0;
	data.ic_sel_ent_bytes = 0xFF;

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_SEL_ENTRY;
	cmd.ic_dlen = sizeof (data);
	cmd.ic_data = &data;

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL)
		return (NULL);

	if (rsp->ic_dlen < sizeof (ipmi_sel_event_t)) {
		(void) ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL);
		return (NULL);
	}

	evp = (ipmi_sel_event_t *)rsp->ic_data;

	evp->isel_ev_next = LE_IN16(&evp->isel_ev_next);
	evp->isel_ev_recid = LE_IN16(&evp->isel_ev_recid);
	if (evp->isel_ev_rectype == IPMI_SEL_SYSTEM ||
	    evp->isel_ev_rectype >= IPMI_SEL_OEM_LO)
		evp->isel_ev_ts = LE_IN32(&evp->isel_ev_ts);

	return (evp);
}

/*
 * SEL time management.  For the purposes of libipmi we assume that the SDR
 * repository and SEL share the same timebase, even though the spec allows for
 * separate time sources.  Hence no function to set the SDR repository time.
 */
int
ipmi_sel_get_time(ipmi_handle_t *ihp, uint32_t *tp)
{
	ipmi_cmd_t cmd, *rsp;

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_SEL_TIME;
	cmd.ic_dlen = 0;
	cmd.ic_data = NULL;

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	if (rsp->ic_dlen < sizeof (uint32_t))
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));

	*tp = LE_IN32(rsp->ic_data);

	return (0);
}

int
ipmi_sel_set_time(ipmi_handle_t *ihp, uint32_t t)
{
	ipmi_cmd_t cmd;

	t = LE_32(t);

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_SET_SEL_TIME;
	cmd.ic_dlen = sizeof (t);
	cmd.ic_data = &t;

	if (ipmi_send(ihp, &cmd) == NULL)
		return (-1);

	return (0);
}

int
ipmi_sel_get_utc_offset(ipmi_handle_t *ihp, int *offp)
{
	ipmi_cmd_t cmd, *rsp;
	int16_t off16;

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_SEL_UTC_OFFSET;
	cmd.ic_dlen = 0;
	cmd.ic_data = NULL;

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	if (rsp->ic_dlen < sizeof (uint16_t))
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));

	off16 = LE_IN16(rsp->ic_data);
	*offp = off16;

	return (0);
}

int
ipmi_sel_set_utc_offset(ipmi_handle_t *ihp, int off)
{
	ipmi_cmd_t cmd;
	int16_t off16 = off;

	off16 = LE_16(off16);

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_SET_SEL_UTC_OFFSET;
	cmd.ic_dlen = sizeof (off16);
	cmd.ic_data = &off16;

	if (ipmi_send(ihp, &cmd) == NULL)
		return (-1);

	return (0);
}
