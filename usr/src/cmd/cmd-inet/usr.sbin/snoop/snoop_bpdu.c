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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ethernet.h>

#include <snoop.h>

struct conf_bpdu {
	uchar_t cb_protid[2];		/* Protocol Identifier */
	uchar_t cb_protvers;		/* Protocol Version Identifier */
	uchar_t cb_type;		/* BPDU Type */
	uchar_t cb_flags;		/* BPDU Flags */
	uchar_t cb_rootid[8];		/* Root Identifier */
	uchar_t cb_rootcost[4];		/* Root Path Cost */
	uchar_t cb_bridgeid[8];		/* Bridge Identifier */
	uchar_t cb_portid[2];		/* Port Identifier */
	uchar_t cb_messageage[2];	/* Message Age */
	uchar_t cb_maxage[2];		/* Max Age */
	uchar_t cb_hello[2];		/* Hello Time */
	uchar_t cb_fwddelay[2];		/* Forward Delay */
};

#define	BPDU_TYPE_CONF		0
#define	BPDU_TYPE_RCONF		2
#define	BPDU_TYPE_TCNOTIF	0x80

int
interpret_bpdu(int flags, char *data, int dlen)
{
	struct conf_bpdu *cb;
	const char *pdutype;

	if (dlen < 4) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "BPDU (short packet)");
		return (0);
	}

	cb = (struct conf_bpdu *)data;

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "Bridge PDU T:%d L:%d", cb->cb_type, dlen);
	}

	if (flags & F_DTAIL) {
		show_header("Bridge-PDU: ",
		    "Bridge PDU Frame", dlen);
		show_space();
		switch (cb->cb_type) {
		case BPDU_TYPE_CONF:
			pdutype = "Configuration";
			break;
		case BPDU_TYPE_RCONF:
			pdutype = "Rapid Configuration";
			break;
		case BPDU_TYPE_TCNOTIF:
			pdutype = "TC Notification";
			break;
		default:
			pdutype = "?";
			break;
		}
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "PDU type = %d (%s)", cb->cb_type, pdutype);
		show_trailer();
	}
	return (0);
}
