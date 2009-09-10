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
#include <sys/vlan.h>
#include <net/trill.h>

#include <snoop.h>

#define	PDUTYPE_OFFSET 4
#define	PDUTYPE_HELLO1 15
#define	PDUTYPE_HELLO2 16
#define	PDUTYPE_HELLOP2P 17
#define	PDUTYPE_LSP1 18
#define	PDUTYPE_LSP2 20
#define	PDUTYPE_CSN1 24
#define	PDUTYPE_CSN2 25
#define	PDUTYPE_PSN1 26
#define	PDUTYPE_PSN2 27

int
interpret_isis(int flags, char *data, int dlen, boolean_t istrill)
{
	uint8_t pdutypenum;
	char *pdutype;

	pdutypenum = *(data+ PDUTYPE_OFFSET);
	switch (pdutypenum) {
	case PDUTYPE_HELLO1:
	case PDUTYPE_HELLO2:
		pdutype = "Hello";
		break;
	case PDUTYPE_HELLOP2P:
		pdutype = "P2P Hello";
		break;
	case PDUTYPE_LSP1:
	case PDUTYPE_LSP2:
		pdutype = "Link State";
		break;
	case PDUTYPE_CSN1:
	case PDUTYPE_CSN2:
		pdutype = "CSN";
		break;
	case PDUTYPE_PSN1:
	case PDUTYPE_PSN2:
		pdutype = "PSN";
		break;
	default:
		pdutype = "Unknown";
		break;
	}

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "%s %s L:%d", istrill ? "Core TRILL IS-IS" : "IS-IS",
		    pdutype, dlen);
	}

	if (flags & F_DTAIL) {
		if (istrill) {
			show_header("TRILL-IS-IS: ",
			    "Core TRILL IS-IS Frame", dlen);
		} else {
			show_header("IS-IS: ",
			    "IS-IS Frame", dlen);
		}
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Frame type = %02X (%s)", pdutypenum, pdutype);
		show_trailer();
	}
	return (0);
}
