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
#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1991 Sun Microsystems, Inc.
 *
 * Produce a big hunk o' data from an Fcode input file.
 * Usage: process <infile.fcode >outfile
 */

#include <stdio.h>

main()
{
	int c, count = 0;

	(void) printf("const unsigned char forthblock[] = {\n");
	while ((c = getchar()) != EOF)
		(void) printf("0x%02x,%c", c & 0xff,
		    (count = ++count % 8) ? ' ' : '\n');
	(void) printf("\n};\n");
	return (0);
}
