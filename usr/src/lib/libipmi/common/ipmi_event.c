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

#include <libipmi.h>

int
ipmi_event_platform_message(ipmi_handle_t *ihp,
    ipmi_platform_event_message_t *pem)
{
	ipmi_cmd_t cmd = { 0 };

	cmd.ic_netfn = IPMI_NETFN_SE;
	cmd.ic_cmd = IPMI_CMD_PLATFORM_EVENT_MESSAGE;
	cmd.ic_dlen = sizeof (ipmi_platform_event_message_t);
	cmd.ic_data = pem;

	if (ipmi_send(ihp, &cmd) == NULL)
		return (-1);
	else
		return (0);
}
