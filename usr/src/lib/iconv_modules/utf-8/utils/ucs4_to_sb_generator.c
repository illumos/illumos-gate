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
 *
 * This program will generate UTF-8 to whatever single byte codeset mapping
 * table in the single byte codeset code values' ascending order. You need to
 * use sort(1) to sort out and make it ready for binary search that will
 * do the search on the UTF-8 values.
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
			tbl[i].size = (signed char)1;
			tbl[i].u8 = (unsigned int)i;
		} else if (!ascii_only && (i >= 0x80 && i <= 0x9f)) {
			tbl[i].size = (signed char)2;
			tbl[i].u8 = (unsigned int)i;
		} else {
			tbl[i].size = (signed char)ICV_TYPE_ILLEGAL_CHAR;
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

		if (buf[i] == '#' || buf[i] == '\0') {
			tbl[k].size = (signed char)ICV_TYPE_ILLEGAL_CHAR;
			tbl[k].u8 = 0;
			continue;
		}

		for (j = 0; !isspace(buf[i]); i++, j++)
			num[j] = buf[i];
		num[j] = '\0';

		l = strtol(num, (char **)NULL, 0);

		tbl[k].u8 = l;
		if (l < 0x80)
			tbl[k].size = (signed char)1;
		else if (l < 0x800)
			tbl[k].size = (signed char)2;
		else if (l < 0x10000)
			tbl[k].size = (signed char)3;
		else if (l < 0x200000)
			tbl[k].size = (signed char)4;
		else if (l < 0x4000000)
			tbl[k].size = (signed char)5;
		else
			tbl[k].size = (signed char)6;
	}

	for (i = 0; i < 256; i++) {
		l = tbl[i].u8;
		if (i > 0x7f && l != 0)
			printf("\t{  0x%08X, 0x%02X  },\n", l, i);
	}

	if (ascii_only)
		printf("\t{  0x%08X, 0x%02X  },\n", 0, 0);

	fprintf(stderr, "%s: make sure you sort the result by using\n\n\
\tsort -k 1 -t ',' result_file\n\n\
since iconv module that will include the result table uses binary search.\n",
av[0]);
}
