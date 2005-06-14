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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Post-process adb script.
 * All we do is collapse repeated formats into number*format.
 * E.g. XXX is collapsed to 3X.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int
main()
{
	int c, quote, paren, savec, count, dispcmd;

	savec = count = 0;
	quote = 0;	/* not in quoted string */
	paren = 0;	/* not in parenthesized string */
	dispcmd = 0;	/* not in display command */
	while ((c = getchar()) != EOF) {
		if (c == '"') {
			quote = !quote;
		} else if (c == '(') {
			paren++;
		} else if (c == ')') {
			paren--;
		} else if (c == '/' || c == '?') {
			dispcmd = 1;
		} else if (c == '\n') {
			dispcmd = 0;
		}
		if (c == savec) {
			count++;
			continue;
		}
		if (savec) {
			if (count > 1) {
				printf("%d", count);
			}
			putchar(savec);
			savec = 0;
		}
		if (quote == 0 && paren == 0 && dispcmd &&
		    strchr("KJFXOQDUfYpPxoqdubcC+IaAtrn-", c)) {
			savec = c;
			count = 1;
		} else {
			putchar(c);
		}
	}
	if (savec)
		putchar(savec);
	return (0);
}
