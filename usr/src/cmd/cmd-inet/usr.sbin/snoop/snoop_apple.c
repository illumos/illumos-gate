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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <at.h>
#include <snoop.h>

extern char *src_name, *dst_name;

struct socktable {
	int	pt_num;
	char	*pt_short;
};

static struct socktable pt_ddp[] = {
	{1,	"RTMP"},
	{2,	"NIS"},
	{4,	"Echoer"},
	{6,	"ZIS"},
	{0,	NULL},
};

static struct socktable pt_ddp_types[] = {
	{1,	"RTMP Resp"},
	{2,	"NBP"},
	{3,	"ATP"},
	{4,	"AEP"},
	{5,	"RTMP Req"},
	{6,	"ZIP"},
	{7,	"ADSP"},
	{0,	NULL},
};

static char *
apple_ddp_type(struct socktable *p, uint16_t port)
{
	for (; p->pt_num != 0; p++) {
		if (port == p->pt_num)
			return (p->pt_short);
	}
	return (NULL);
}

/*
 * return the short at p, regardless of alignment
 */

uint16_t
get_short(uint8_t *p)
{
	return (p[0] << 8 | p[1]);
}

/*
 * return the long at p, regardless of alignment
 */
uint32_t
get_long(uint8_t *p)
{
	return (p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);
}

/*
 * format a MAC address
 */

char *
print_macaddr(uint8_t *ha, int len)
{
	static char buf[128];
	char *p = buf;

	while (len-- != 0) {
		p += snprintf(p, sizeof (buf) - (p - buf),
		    len > 0 ? "%x:" : "%x", *ha++);
	}
	return (buf);
}

/* ARGSUSED */
void
interpret_at(int flags, struct ddp_hdr *ddp, int len)
{
	int ddplen;
	char *pname;
	char buff [32];
	static char src_buf[16];
	static char dst_buf[16];

	if (ddp_pad(ddp) != 0)
		return;			/* unknown AppleTalk proto */

	ddplen = ddp_len(ddp);

	(void) snprintf(src_buf, sizeof (src_buf),
	    "%u.%u", ntohs(ddp->ddp_src_net), ddp->ddp_src_id);
	src_name = src_buf;

	(void) snprintf(dst_buf, sizeof (dst_buf),
	    "%u.%u", ntohs(ddp->ddp_dest_net), ddp->ddp_dest_id);
	if (ddp->ddp_dest_id == NODE_ID_BROADCAST)
		dst_name = "(broadcast)";
	else
		dst_name = dst_buf;

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "DDP S=%u.%u:%u D=%u.%u:%u LEN=%d",
		    ntohs(ddp->ddp_src_net),
		    ddp->ddp_src_id,
		    ddp->ddp_src_sock,
		    ntohs(ddp->ddp_dest_net),
		    ddp->ddp_dest_id,
		    ddp->ddp_dest_sock,
		    ddp_len(ddp));
	}

	if (flags & F_DTAIL) {
		show_header("DDP:  ", "DDP Header", ddplen - DDPHDR_SIZE);
		show_space();
		pname = apple_ddp_type(pt_ddp, ddp->ddp_src_sock);
		if (pname == NULL) {
			pname = "";
		} else {
			(void) snprintf(buff, sizeof (buff), "(%s)", pname);
			pname = buff;
		}

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Source = %s, Socket = %u %s",
		    src_name, ddp->ddp_src_sock, pname);
		pname = apple_ddp_type(pt_ddp, ddp->ddp_dest_sock);
		if (pname == NULL) {
			pname = "";
		} else {
			(void) snprintf(buff, sizeof (buff), "(%s)", pname);
			pname = buff;
		}
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Destination = %s, Socket = %u %s",
		    dst_name, ddp->ddp_dest_sock, pname);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Hop count = %d",
		    ddp_hop(ddp));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Length = %d",
		    ddp_len(ddp));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Checksum = %04x %s",
		    ntohs(ddp->ddp_cksum),
		    ddp->ddp_cksum == 0 ? "(no checksum)" : "");
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "DDP type = %d (%s)",
		    ddp->ddp_type,
		    apple_ddp_type(pt_ddp_types, ddp->ddp_type));
		show_space();
	}


	/* go to the next protocol layer */

	switch (ddp->ddp_type) {
	case DDP_TYPE_NBP:
		interpret_nbp(flags, (struct nbp_hdr *)ddp, ddplen);
		break;
	case DDP_TYPE_AEP:
		interpret_aecho(flags, ddp, ddplen);
		break;
	case DDP_TYPE_ATP:
		interpret_atp(flags, ddp, ddplen);
		break;
	case DDP_TYPE_ZIP:
		interpret_ddp_zip(flags, (struct zip_hdr *)ddp, ddplen);
		break;
	case DDP_TYPE_ADSP:
		interpret_adsp(flags, (struct ddp_adsphdr *)ddp, ddplen);
		break;
	case DDP_TYPE_RTMPRQ:
	case DDP_TYPE_RTMPRESP:
		interpret_rtmp(flags, ddp, ddplen);
		break;
	}
}
