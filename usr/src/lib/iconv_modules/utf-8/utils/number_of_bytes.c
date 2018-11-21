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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * This particular program generates a table that contains the number of
 * bytes in a UTF-8 character by only examining the leading byte of a UTF-8
 * character.
 */



#include <stdio.h>
#include "../common_defs.h"

main()
{
	int i;
	int k, l;

	for (i = 0; i <= 0xff; i++) {
		if (i <= 0x7f)
			k = 1;
		else if (i >= 0xc0 && i <= 0xdf)
			k = 2;
		else if (i >= 0xe0 && i <= 0xef)
			k = 3;
		else if (i >= 0xf0 && i <= 0xf7)
			k = 4;
		else if (i >= 0xf8 && i <= 0xfb)
			k = 5;
		else if (i >= 0xfc && i <= 0xfd)
			k = 6;
		else
			k = ICV_TYPE_ILLEGAL_CHAR; /* illegal char */

		if (i == 0 || (i % 16 == 0)) {
			if (i < 0x80)
				printf("\n\t");
			else {
				printf("\n\n    /*  ");
				for (l = i; l < (i + 16); l++)
					printf("%02X  ", l);
				printf("*/\n\t");
			}
		}
		if (k < 0)
			printf("%d, ", k);
		else
			printf(" %d, ", k);
	}

	printf("\n");
}
