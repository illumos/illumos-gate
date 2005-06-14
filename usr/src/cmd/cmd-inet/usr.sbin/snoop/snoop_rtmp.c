/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>

#include <at.h>
#include <snoop.h>

static void show_rtmp_tuples(uint8_t *, int);

static char *
rtmp_func_long(uint8_t fun)
{
	switch (fun) {
	case RTMP_REQ:
		return ("Request");
	case RTMP_RDR_SH:
		return ("Route Data Request, split horizon");
	case RTMP_RDR_NSH:
		return ("Route Data Request, no split horizon");
	default:
		return ("unknown");
	}
}

static char *
rtmp_func_short(uint8_t fun)
{
	switch (fun) {
	case RTMP_REQ:
		return ("Req");
	case RTMP_RDR_SH:
		return ("RDR, sh");
	case RTMP_RDR_NSH:
		return ("RDR, no sh");
	default:
		return ("unknown");
	}
}

void
interpret_rtmp(int flags, struct ddp_hdr *ddp, int len)
{
	uint8_t *data;
	uint16_t snet;
	uint8_t node;
	int tuples;
	int runt;
	char extended;

	len -= DDPHDR_SIZE;
	if (len < 0)
		goto out;

	data = (uint8_t *)ddp + DDPHDR_SIZE;

	switch (ddp->ddp_type) {
	case DDP_TYPE_RTMPRQ:		/* simple rtmp */
		if (len < 1)
			goto out;

		if (flags & F_SUM) {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "RTMP F=%s",
			    rtmp_func_short(data[0]));
		}

		if (flags & F_DTAIL) {
			show_header("RTMP: ", "RTMP Header", len);
			show_space();

			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Func = %d (%s)",
			    data[0], rtmp_func_long(data[0]));
		}
		break;
	case DDP_TYPE_RTMPRESP:		/* RTMP data */
		if (len < 3)
			goto out;

		snet = get_short(data);
		if (data[2] != 8)	/* ID length is always 8 */
			return;
		node = data[3];		/* assume id_len == 8 */
		extended = (data[6] != RTMP_FILLER) &&
		    (get_short(&data[4]) != 0);

		tuples = (len - 4) / 3;
		runt = (len - 4) % 3; /* integral length? */

		if (flags & F_SUM) {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "RTMP Data Snet=%d, Snode=%d%s",
			    snet, node, runt != 0 ? " (short)" : "");
		}

		if (flags & F_DTAIL) {
			show_header("RTMP: ", "RTMP Header", len);
			show_space();

			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "RTMP Data, Length = %d%s",
			    len, runt != 0 ? " (short packet)" : "");
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Senders Net = %d, Sender Node %d",
			    snet, node);
			if (extended)
				show_rtmp_tuples(&data[4], tuples);
			else
				show_rtmp_tuples(&data[7], tuples-1);
		}

		break;
	}
	return;
out:
	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "RTMP (short packet)");
	}

	if (flags & F_DTAIL) {
		show_header("RTMP: ", "RTMP Header", len);
		show_space();

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "(short packet)");
	}
}

static void
show_rtmp_tuples(uint8_t *p, int tuples)
{
	while (tuples > 0) {

		if (p[2] & RTMP_EXTEND) { /* extended tuple? */

			(void) snprintf(get_line(0, 0),
			    get_line_remain(),
			    "Network = %d-%d, Distance = %d",
			    get_short(p), get_short(&p[3]),
			    p[2] & RTMP_DIST_MASK);
			p += 6;
			tuples -= 2;
		} else {

			(void) snprintf(get_line(0, 0),
			    get_line_remain(),
			    "Network = %d, Distance = %d",
			    get_short(p), p[2]);
			p += 3;
			tuples--;
		}
	}
}
