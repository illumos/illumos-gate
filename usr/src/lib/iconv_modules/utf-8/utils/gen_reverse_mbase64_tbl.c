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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * This program generates reverse Modified Base 64 values.
 */


#include <stdio.h>

main() {
	unsigned int c;
	int i;
	int j;

	for (c = 0, i = j = 0; c < 0x100; c++) {
		if (j % 16 == 0)
			printf("\n/*%02x*/\t", j);
		j++;
		if (c >= 'A' && c <= 'Z') {
			printf("%2d, ", c - 'A');
		} else if (c >= 'a' && c <= 'z') {
			printf("%2d, ", c - 'a' + 26);
		} else if (c >= '0' && c <= '9') {
			printf("%2d, ", c - '0' + 52);
		} else if (c == '+') {
			printf("%2d, ", 62);
		} else if (c == '/') {
			printf("%2d, ", 63);
		} else if (c > 127)
			printf("%d, ", -2);
		else
			printf("%d, ", -1);
	}
	printf("\n");
}
