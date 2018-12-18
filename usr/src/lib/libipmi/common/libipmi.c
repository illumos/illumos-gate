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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <libipmi.h>
#include <string.h>

#include "ipmi_impl.h"

ipmi_handle_t *
ipmi_open(int *errp, char **msg, uint_t xport_type, nvlist_t *params)
{
	ipmi_handle_t *ihp;
	static char errmsg[48];

	if (msg)
		*msg = NULL;

	if ((ihp = calloc(1, sizeof (ipmi_handle_t))) == NULL) {
		*errp = EIPMI_NOMEM;
		if (msg)
			*msg = "memory allocation failure";
		return (NULL);
	}

	switch (xport_type) {
	case IPMI_TRANSPORT_BMC:
		ihp->ih_transport = &ipmi_transport_bmc;
		break;
	case IPMI_TRANSPORT_LAN:
		ihp->ih_transport = &ipmi_transport_lan;
		break;
	default:
		*msg = "invalid transport type specified";
		return (NULL);
	}

	ihp->ih_retries = 3;

	if ((ihp->ih_tdata = ihp->ih_transport->it_open(ihp, params)) == NULL ||
	    ipmi_sdr_init(ihp) != 0 || ipmi_entity_init(ihp) != 0) {
		*errp = ihp->ih_errno;
		if (msg) {
			(void) strncpy(errmsg, ipmi_errmsg(ihp), 47);
			errmsg[47] = '\0';
			*msg = errmsg;
		}
		ipmi_close(ihp);
		return (NULL);
	}

	return (ihp);
}

void
ipmi_close(ipmi_handle_t *ihp)
{
	if (ihp->ih_transport && ihp->ih_tdata)
		ihp->ih_transport->it_close(ihp->ih_tdata);
	ipmi_free(ihp, ihp->ih_deviceid);
	ipmi_free(ihp, ihp->ih_firmware_rev);
	ipmi_user_clear(ihp);
	ipmi_sdr_fini(ihp);
	ipmi_entity_fini(ihp);
	free(ihp);
}

/*
 * See section 5.2 for a description of the completion codes.
 */
static struct ipmi_err_conv {
	int	bmc_err;
	int	ipmi_err;
} ipmi_errtable[] = {
	{ 0xC0,			EIPMI_BUSY },
	{ 0xC1,			EIPMI_INVALID_COMMAND },
	{ 0xC2,			EIPMI_INVALID_COMMAND },
	{ 0xC3,			EIPMI_COMMAND_TIMEOUT },
	{ 0xC4,			EIPMI_NOSPACE },
	{ 0xC5,			EIPMI_INVALID_RESERVATION },
	{ 0xC6,			EIPMI_INVALID_REQUEST },
	{ 0xC7,			EIPMI_INVALID_REQUEST },
	{ 0xC8,			EIPMI_INVALID_REQUEST },
	{ 0xC9,			EIPMI_INVALID_REQUEST },
	{ 0xCA,			EIPMI_DATA_LENGTH_EXCEEDED },
	{ 0xCB,			EIPMI_NOT_PRESENT },
	{ 0xCC,			EIPMI_INVALID_REQUEST },
	{ 0xCD,			EIPMI_INVALID_COMMAND },
	{ 0xCE,			EIPMI_UNAVAILABLE },
	{ 0xCF,			EIPMI_UNAVAILABLE },
	{ 0xD0,			EIPMI_BUSY },
	{ 0xD1,			EIPMI_BUSY },
	{ 0xD2,			EIPMI_BUSY },
	{ 0xD3,			EIPMI_NOT_PRESENT },
	{ 0xD4,			EIPMI_ACCESS },
	{ 0xD5,			EIPMI_UNAVAILABLE },
	{ 0xD6,			EIPMI_UNAVAILABLE },
	{ 0xFF,			EIPMI_UNSPECIFIED },
};

#define	IPMI_ERROR_COUNT \
	(sizeof (ipmi_errtable) / sizeof (ipmi_errtable[0]))

ipmi_cmd_t *
ipmi_send(ipmi_handle_t *ihp, ipmi_cmd_t *cmd)
{
	int i;

	if (ihp->ih_transport->it_send(ihp->ih_tdata, cmd, &ihp->ih_response,
	    &ihp->ih_completion) != 0)
		return (NULL);

	if (ihp->ih_completion != 0) {
		for (i = 0; i < IPMI_ERROR_COUNT; i++) {
			if (ihp->ih_completion == ipmi_errtable[i].bmc_err) {
				(void) ipmi_set_error(ihp,
				    ipmi_errtable[i].ipmi_err,
				    "IPMI completion code 0x%x",
				    ihp->ih_completion);
				return (NULL);
			}
		}

		(void) ipmi_set_error(ihp, EIPMI_UNKNOWN,
		    "IPMI completion code 0x%x", ihp->ih_completion);
		return (NULL);
	}

	return (&ihp->ih_response);
}
