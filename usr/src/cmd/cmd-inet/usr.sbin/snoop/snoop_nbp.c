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

static void show_nbp_tuples(uint8_t *, int, uint8_t *);

static char *nbp_short[] = {
	"0",				/* 0 */
	"BRRQ   ",			/* 1 */
	"LKUP C ",			/* 2 */
	"LKUP R ",			/* 3 */
	"FWD    ",			/* 4 */
	"5      ",
	"6      ",
	"7      ",
	"8      ",
	"9      ",
	"10     ",
	"11     ",
	"RGSTR  ",			/* 12 */
	"UNRGSTR",			/* 13 */
	"OK     ",			/* 14 */
	"ERROR  ",			/* 15 */
};

void
interpret_nbp(int flags, struct nbp_hdr *nbp, int len)
{
	uint8_t *data;
	int nbp_cnt = nbp->nbp_fun_cnt & 0xf; /* lower four bits */
	int nbp_op = (nbp->nbp_fun_cnt >> 4) & 0xf; /* upper four bits */

	data = (uint8_t *)(nbp + 1);

	if (flags & F_SUM) {
		if (len < sizeof (struct nbp_hdr)) {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "NBP (short packet)");
			return;
		}
		(void) snprintf(get_sum_line(), MAXLINE,
		    "NBP F=%s CNT=%d ID=%d", nbp_short[nbp_op],
		    nbp_cnt, nbp->nbp_id);
	}

	if (flags & F_DTAIL) {
		show_header("NBP:  ", "NBP Header", len);
		show_space();

		if (len < sizeof (struct nbp_hdr)) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "NBP (short packet)");
			return;
		}
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Length = %d", len);

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Func = %d (%s)", nbp_op, nbp_short[nbp_op]);

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Tuple count = %d", nbp_cnt);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Id = %d", nbp->nbp_id);
		show_nbp_tuples(data, nbp_cnt, ((uint8_t *)nbp) + len);
	}
}

static void
show_nbp_tuples(uint8_t *p, int tuples, uint8_t *tail)
{
	uint16_t net;
	uint8_t node;
	uint8_t sock;
	uint8_t enumer;
	char obj[100];
	char *op;
	char *otail = &obj[sizeof (obj)];

	while (tuples--) {
		op = obj;
		if ((p + 5) > tail)
			goto out;
		net = get_short(p);
		p += 2;
		node = *p++;
		sock = *p++;
		enumer = *p++;

		if (p > tail || &p[1]+p[0] > tail)
			goto out;
		op += snprintf(op, otail-op, "%.*s", p[0], &p[1]);

		p = &p[1]+p[0];
		if (p > tail || &p[1]+p[0] > tail)
			goto out;
		op += snprintf(op, otail-op, ":%.*s", p[0], &p[1]);

		p = &p[1]+p[0];
		if (p > tail || &p[1]+p[0] > tail)
			goto out;
		(void) snprintf(op, otail-op, "@%.*s", p[0], &p[1]);
		p = &p[1]+p[0];

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Name = \"%s\"", obj);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Net = %d, node = %d, sock = %d, enum = %d",
		    net, node, sock, enumer);
	}
	return;
out:
	(void) snprintf(get_line(0, 0), get_line_remain(),
	    "NBP (short tuple)");
}
