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

static char *atp_ci(uint8_t);

static char *atp_trel[8] = {
	"30s",
	"1m",
	"2m",
	"4m",
	"8m",
	"(undef 5)",
	"(undef 6)",
	"(undef 7)"
};

void
interpret_atp(int flags, struct ddp_hdr *ddp, int len)
{
	struct atp_hdr *atp = (struct atp_hdr *)ddp;
	int atplen = len - (DDPHDR_SIZE + ATPHDR_SIZE);

	if (flags & F_SUM) {
		if (atplen < 0) {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "ATP (short packet)");
			return;
		}
		(void) snprintf(get_sum_line(), MAXLINE,
		    "ATP (%s), TID=%d, L=%d",
		    atp_ci(atp->atp_ctrl),
		    get_short((uint8_t *)&atp->atp_tid),
		    len);
	}

	if (flags & F_DTAIL) {
		show_header("ATP:  ", "ATP Header", 8);
		show_space();

		if (atplen < 0) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "ATP (short packet)");
			return;
		}
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Length = %d", len);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Ctrl = 0x%x (%s), bitmap/seq = 0x%x",
		    atp->atp_ctrl,
		    atp_ci(atp->atp_ctrl),
		    atp->atp_seq);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "TID = %d, user bytes 0x%x 0x%x 0x%x 0x%x",
		    get_short((uint8_t *)&atp->atp_tid),
		    atp->atp_user[0], atp->atp_user[1],
		    atp->atp_user[2], atp->atp_user[3]);
		show_space();
	}

	if (ddp->ddp_dest_sock == DDP_TYPE_ZIP ||
	    ddp->ddp_src_sock == DDP_TYPE_ZIP)
		interpret_atp_zip(flags, atp, atplen);
}

static char *
atp_ci(uint8_t ci)
{
	static char buf[50];
	char *p = buf;
	char *to = NULL;
	char *tail = &buf[sizeof (buf)];

	switch (atp_fun(ci)) {
	case ATP_TREQ:
		p += snprintf(p, tail-p, "TReq");
		to = atp_trel[atp_tmo(ci)];
		break;
	case ATP_TRESP:
		p += snprintf(p, tail-p, "TResp");
		break;
	case ATP_TREL:
		p += snprintf(p, tail-p, "TRel");
		break;
	}

	p += snprintf(p, tail-p, ci & ATP_FLG_XO ? " XO" : " ALO");

	if (ci & ATP_FLG_EOM)
		p += snprintf(p, tail-p, " EOM");

	if (ci & ATP_FLG_STS)
		p += snprintf(p, tail-p, " STS");

	if (to != NULL)
		(void) snprintf(p, tail-p, " %s", to);
	return (buf);
}
