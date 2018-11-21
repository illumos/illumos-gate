/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include "../common_defs.h"

int
main(int ac, char **av)
{
	to_utf8_table_component_t tbl[256];
	register int i, j;
	char buf[BUFSIZ], num[100];
	unsigned int l, k;
	char ascii_only = 0;

	if (ac > 1 && strcmp(av[1], "-ascii") == 0)
		ascii_only = 1;

	for (i = 0; i < 256; i++) {
		if (i <= 0x1f || i == 0x7f || (ascii_only && i <= 0x7f)) {
			tbl[i].size = 1;
			tbl[i].u8 = (unsigned int)i;
		} else if (!ascii_only && (i >= 0x80 && i <= 0x9f)) {
			tbl[i].size = 2;
			tbl[i].u8 = (unsigned int)i;
		} else {
			tbl[i].size = ICV_TYPE_ILLEGAL_CHAR;
			tbl[i].u8 = 0;
		}
	}


	while (fgets(buf, BUFSIZ, stdin)) {
		i = 0;
		while (buf[i] && isspace(buf[i]))
			i++;
		if (buf[i] == '#' || buf[i] == '\0')
			continue;

		for (j = 0; !isspace(buf[i]); i++, j++)
			num[j] = buf[i];
		num[j] = '\0';

		k = strtol(num, (char **)NULL, 0);

		while (isspace(buf[i]))
			i++;

		/* Take care of UNDEFINED cases. */
		if (buf[i] == '#' || buf[i] == '\0') {
			tbl[k].size = ICV_TYPE_ILLEGAL_CHAR;
			tbl[k].u8 = 0;
			continue;
		}

		for (j = 0; !isspace(buf[i]); i++, j++)
			num[j] = buf[i];
		num[j] = '\0';

		l = strtol(num, (char **)NULL, 0);

		tbl[k].u8 = l;
		if (l < 0x80)
			tbl[k].size = 1;
		else if (l < 0x800)
			tbl[k].size = 2;
		else if (l < 0x10000)
			tbl[k].size = 3;
		else if (l < 0x200000)
			tbl[k].size = 4;
		else if (l < 0x4000000)
			tbl[k].size = 5;
		else
			tbl[k].size = 6;
	}

	for (i = 0; i < 256; i++) {
		if (tbl[i].u8 < 0x80)
			l = tbl[i].u8;
		else if (tbl[i].u8 < 0x800) {
			l = 0xc080 |
				(((tbl[i].u8 >> 6) & 0x1f) << 8) |
				(tbl[i].u8 & 0x3f);
		} else if (tbl[i].u8 < 0x10000) {
			l = 0xe08080 |
				(((tbl[i].u8 >> 12) & 0x0f) << 16) |
				(((tbl[i].u8 >> 6) & 0x3f) << 8) |
				(tbl[i].u8 & 0x3f);
		} else if (tbl[i].u8 < 0x200000) {
			l = 0xf0808080 |
				(((tbl[i].u8 >> 18) & 0x07) << 24) |
				(((tbl[i].u8 >> 12) & 0x3f) << 16) |
				(((tbl[i].u8 >> 6) & 0x3f) << 8) |
				(tbl[i].u8 & 0x3f);
		} /* We only support characters in range of UTF-16
		else if (tbl[i].u8 < 0x4000000) {
			l = 0xf880808080 |
				(((tbl[i].u8 >> 24) & 0x03) << 32) |
				(((tbl[i].u8 >> 18) & 0x3f) << 24) |
				(((tbl[i].u8 >> 12) & 0x3f) << 16) |
				(((tbl[i].u8 >> 6) & 0x3f) << 8) |
				(tbl[i].u8 & 0x3f);
		} else {
			l = 0xfc8080808080 |
				(((tbl[i].u8 >> 30) & 0x01) << 40) |
				(((tbl[i].u8 >> 24) & 0x3f) << 32) |
				(((tbl[i].u8 >> 18) & 0x3f) << 24) |
				(((tbl[i].u8 >> 12) & 0x3f) << 16) |
				(((tbl[i].u8 >> 6) & 0x3f) << 8) |
				(tbl[i].u8 & 0x3f);
		}
		*/

		printf("/* 0x%02X */  {  0x%08X, %-3d},\n", i, l, tbl[i].size);
	}
}
