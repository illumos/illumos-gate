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
 * Copyright (c) 1991-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>

#include <at.h>
#include <snoop.h>

static char *adsp_ctrl(uint8_t);

void
interpret_adsp(int flags, struct ddp_adsphdr *adp, int len)
{
	struct ddp_adsp_open *apo;

	if (flags & F_SUM) {
		if (len < sizeof (struct ddp_adsphdr)) {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "ADSP (short packet)");
			return;
		}
		(void) snprintf(get_sum_line(), MAXLINE,
		    "ADSP ConnID=%u (%s)",
		    get_short(adp->ad_connid),
		    adsp_ctrl(adp->ad_desc));
	}

	if (flags & F_DTAIL) {
		show_header("ADSP: ", "ADSP Header",
		    len - sizeof (struct ddp_adsphdr));
		show_space();

		if (len < sizeof (struct ddp_adsphdr)) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "(short packet)");
			return;
		}

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "ConnID = %u, ByteSeq = %u, RecvSeq = %u",
		    get_short(adp->ad_connid),
		    get_long(adp->ad_fbseq),
		    get_long(adp->ad_nrseq));

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "RcvWin = %u, Ctrl = 0x%x (%s)",
		    get_short(adp->ad_rcvwin),
		    adp->ad_desc,
		    adsp_ctrl(adp->ad_desc));

		switch (adp->ad_desc) {
		case AD_CREQ:		/* open requests */
		case AD_CACK:
		case AD_CREQ_ACK:
		case AD_CDENY:
			apo = (struct ddp_adsp_open *)adp;
			if (len < sizeof (struct ddp_adsp_open)) {
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "(short packet)");
				return;
			}
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Dest ConnID = %u, AttRcvSeq = %u",
			    get_short(apo->ad_dconnid),
			    get_long(apo->ad_attseq));
			break;
		}

		if (adp->ad_desc & AD_ATT) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "AttCode = 0x%x",
			    get_short(((struct ddp_adsp_att *)adp)->
				ad_att_code));
		}
	}
}

static char *adsp_ctrl_msg[] = {
	"Probe/Ack",
	"OpenConnReq",
	"OpenConnAck",
	"OpenConnReq+Ack",
	"OpenConnDeny",
	"CloseConnAdv",
	"ForwReset",
	"ForwReset Ack",
	"RetransAdv",
	"9", "10", "11", "12", "13", "14", "15",
};

static char *
adsp_ctrl(uint8_t ctrl)
{
	static char buf[50];
	char *p = buf;
	char *tail = &buf[sizeof (buf)];

	if (ctrl & AD_ACKREQ)
		p += snprintf(p, tail-p, "AckReq");

	if (ctrl & AD_EOM) {
		p += snprintf(p, tail-p, p == buf ? "EOM" : " EOM");
	}

	if (ctrl & AD_ATT) {
		p += snprintf(p, tail-p, p == buf ? "Att" : " Att");
	}

	if (ctrl & AD_CTRL) {
		(void) snprintf(p, tail-p, "%s%s", p == buf ? "" : " ",
		    adsp_ctrl_msg[ctrl & AD_CTRL_MASK]);
	}

	return (buf);
}
