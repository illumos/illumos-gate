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

char *print_macaddr(uint8_t *, int);

static char *zip_flags(char);
static char *zip_flags_long(char);

void
interpret_ddp_zip(int flags, struct zip_hdr *zip, int len)
{
	int cnt;
	uint16_t net;
	uint16_t range;
	uint8_t *p;
	char zone[33];
	char defzone[60] = "";
	char mcast[50] = "";
	uint8_t gniflags;
	uint8_t *tail = (uint8_t *)zip + len;

	if (flags & F_SUM) {
		if (len < sizeof (struct zip_hdr))
			goto out;

		switch (zip->zip_func) {
		case ZIP_QUERY:
			cnt = zip->zip_netcnt;
			(void) snprintf(get_sum_line(), MAXLINE,
			    "ZIP Query CNT = %d", cnt);
			break;
		case ZIP_REPLY:
		case ZIP_EXT_REPLY:
			cnt = zip->zip_netcnt;
			(void) snprintf(get_sum_line(), MAXLINE,
			    "ZIP Reply CNT = %d", cnt);
			break;
		case ZIP_GET_NET_INFO:
			p = &zip->zip_func;

			if ((p+6 > tail) || (p+7+p[6] > tail))
				goto out;

			(void) snprintf(get_sum_line(), MAXLINE,
			    "ZIP GNI Zone = \"%.*s\"", p[6], &p[7]);
			break;
		case ZIP_GET_NET_INFO_REPLY:
			p = &zip->zip_func;

			gniflags = p[1];
			(void) snprintf(get_sum_line(), MAXLINE,
			    "ZIP GNI Rep Flags 0x%x (%s)",
			    gniflags, zip_flags(gniflags));
			break;
		default:
			(void) snprintf(get_sum_line(), MAXLINE,
			    "ZIP CMD = %d", zip->zip_func);
			break;
		}
	}

	if (flags & F_DTAIL) {
		show_header("ZIP:  ", "ZIP Header", len);
		show_space();

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Length = %d", len);

		if (len < sizeof (struct zip_hdr))
			goto out;

		switch (zip->zip_func) {
		case ZIP_QUERY:
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Query, Network count = %d", zip->zip_netcnt);
			cnt = zip->zip_netcnt;
			p = (uint8_t *)(zip + 1);
			while (cnt--) {
				if (p+2 > tail)
					goto out;
				net = get_short(p);
				p += 2;
				(void) snprintf(get_line(0, 0),
				    get_line_remain(), "Net = %d", net);
			}
			break;
		case ZIP_REPLY:
		case ZIP_EXT_REPLY:
			cnt = zip->zip_netcnt;
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Reply, Network count = %d", cnt);

			p = (uint8_t *)(zip + 1);
			while (cnt--) {
				if (p+2 > tail)
					goto out;
				net = get_short(p);
				p += 2;
				if (p+1 > tail || (&p[1] + p[0]) > tail)
					goto out;
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "Network = %d, Zone = \"%.*s\"",
				    net, p[0], &p[1]);
				p += p[0] + 1;
			}
			break;
		case ZIP_GET_NET_INFO:
			p = &zip->zip_func;
			if (p+1 > tail || (&p[1] + p[0]) > tail)
				goto out;
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "GetNetInfo Zone = \"%.*s\"", p[0], &p[1]);
			break;
		case ZIP_GET_NET_INFO_REPLY:
			p = &zip->zip_func;
			if (p+5 > tail)
				goto out;
			gniflags = p[1];
			net = get_short(&p[2]);
			range = get_short(&p[4]);

			if (p+7 > tail || (&p[7] + p[6]) > tail)
				goto out;
			(void) snprintf(zone, sizeof (zone),
			    "%.*s", p[6], &p[7]);
			p = &p[7] + p[6];

			if ((gniflags & ZIP_FLG_USEBRC) == 0) {
				if (p+1 > tail || (&p[1] + p[0]) > tail)
					goto out;
				(void) snprintf(mcast, sizeof (mcast),
				    "Multicast address = %s",
				    print_macaddr(&p[1], p[0]));
			}

			if (gniflags & ZIP_FLG_ZINV) {
				p = &p[1] + p[0];
				if (p+1 > tail || (&p[1] + p[0]) > tail)
					goto out;
				(void) snprintf(defzone, sizeof (defzone),
				    "Default Zone = \"%.*s\"",
				    p[0], &p[1]);
			}
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "GetNetInfo Reply, Flags 0x%x (%s)",
			    gniflags, zip_flags_long(gniflags));

			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Network number = %d-%d", net, range);

			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Zone = \"%s\"", zone);

			if (mcast[0])
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "%s", mcast);

			if (defzone[0])
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "%s", defzone);

			break;
		case ZIP_NOTIFY:
			p = &zip->zip_func;
			if (p+5 > tail)
				goto out;

			gniflags = p[1];
			net = get_short(&p[2]);
			range = get_short(&p[4]);

			if (p+7 > tail || (&p[7] + p[6]) > tail)
				goto out;
			(void) snprintf(zone, sizeof (zone),
			    "%.*s", p[6], &p[7]);
			p = &p[7] + p[6];

			if ((gniflags & ZIP_FLG_USEBRC) == 0) {
				if (p+1 > tail || (&p[1] + p[0]) > tail)
					goto out;
				(void) snprintf(mcast, sizeof (mcast),
				    "New Multicast address = %s",
				    print_macaddr(&p[1], p[0]));
			}

			if (p+1 > tail || (&p[1] + p[0]) > tail)
				goto out;

			p = &p[1] + p[0];

			if (p+1 > tail || (&p[1] + p[0]) > tail)
				goto out;

			(void) snprintf(defzone, sizeof (defzone),
			    "New Default Zone = \"%.*s\"",
			    p[0], &p[1]);

			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Notify, Flags 0x%x (%s)",
			    gniflags, zip_flags_long(gniflags));

			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Old Zone = \"%s\"", zone);

			if (mcast[0])
				(void) snprintf(get_line(0, 0),
				    get_line_remain(), "%s", mcast);

			if (defzone[0])
				(void) snprintf(get_line(0, 0),
				    get_line_remain(), "%s", defzone);

			break;
		default:
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Op = %d", zip->zip_func);
			break;
		}
	}
	return;
out:
	if (flags & F_SUM)
		(void) snprintf(get_sum_line(), MAXLINE,
		    "ZIP (short packet)");
	if (flags & F_DTAIL)
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "ZIP (short packet)");
}

static char *
zip_flags(char flags)
{
	static char buf[50];
	char *p = buf;
	char *tail = &buf[sizeof (buf)];

	buf[0] = '\0';

	if (flags & ZIP_FLG_ZINV)
		p += snprintf(p, tail-p, "IZ");

	if (flags & ZIP_FLG_USEBRC)
		p += snprintf(p, tail-p, p == buf ? "UB" : " UB");

	if (flags & ZIP_FLG_ONEZ)
		(void) snprintf(p, tail-p, p == buf ? "OOZ" : " OOZ");

	return (buf);
}

static char *
zip_flags_long(char flags)
{
	static char buf[50];
	char *p = buf;
	char *tail = &buf[sizeof (buf)];

	buf[0] = '\0';

	if (flags & ZIP_FLG_ZINV)
		p += snprintf(p, tail-p, "ZoneInvalid");

	if (flags & ZIP_FLG_USEBRC)
		p += snprintf(p, tail-p,
		    p == buf ? "UseBroadcast" : " UseBroadcast");

	if (flags & ZIP_FLG_ONEZ)
		(void) snprintf(p, tail-p,
		    p == buf ? "OnlyOneZone" : " OnlyOneZone");

	return (buf);
}

void
interpret_atp_zip(int flags, struct atp_hdr *atp, int len)
{
	int cnt;
	uint8_t *data;
	uint8_t *tail = (uint8_t *)(atp+1) + len;

	if (flags & F_SUM) {
		if (len < 0) {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "ZIP (short packet)");
			return;
		}

		switch (atp_fun(atp->atp_ctrl)) {
		case ATP_TREQ:
			switch (atp->atp_user[0]) {
			case ZIP_ATP_GETMYZONE:
				(void) snprintf(get_sum_line(), MAXLINE,
				    "ZIP GetMyZone");
				break;

			case ZIP_ATP_GETZONELIST:
				(void) snprintf(get_sum_line(), MAXLINE,
				    "ZIP GetZoneList");
				break;

			case ZIP_ATP_GETLOCALZONES:
				(void) snprintf(get_sum_line(), MAXLINE,
				    "ZIP GetLocalZones");
				break;
			}
			break;
		case ATP_TRESP:
			cnt = get_short(&atp->atp_user[2]);
			(void) snprintf(get_sum_line(), MAXLINE,
			    "ZIP ZoneReply, Cnt = %d", cnt);

			break;
		}
	}

	if (flags & F_DTAIL) {
		show_header("ZIP:  ", "ZIP Header", len);
		show_space();

		if (len < 0) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "ZIP (short packet)");
			return;
		}

		switch (atp_fun(atp->atp_ctrl)) {
		case ATP_TREQ:
			switch (atp->atp_user[0]) {
			case ZIP_ATP_GETMYZONE:
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "GetMyZone, Start Index = %d",
				    get_short(&atp->atp_user[2]));
				break;
			case ZIP_ATP_GETZONELIST:
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "GetZoneList, Start Index = %d",
				    get_short(&atp->atp_user[2]));
				break;
			case ZIP_ATP_GETLOCALZONES:
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "GetLocalZones, Start Index = %d",
				    get_short(&atp->atp_user[2]));
				break;
			}
			break;
		case ATP_TRESP:
			cnt = get_short(&atp->atp_user[2]);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "ZoneReply, Number of Zones = %d, Length = %d",
			    cnt, len);

			data = (uint8_t *)atp + DDPHDR_SIZE + ATPHDR_SIZE;

			while (cnt--) {
				if (data > tail ||
				    (&data[1] + data[0]) > tail) {
					(void) snprintf(get_line(0, 0),
					    get_line_remain(),
					    "ZoneReply (short packet)");
					return;
				}
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "Zone = \"%.*s\"", data[0], &data[1]);
				data += data[0] + 1;
			}
			break;
		}
	}
}
