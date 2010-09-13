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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>

/*
 * More generic than get_u_long. Supports byte, short, long, longlong.
 * Returns 0 for success, -1 for failure.
 */
int
get_number(char **src, void *dest, int len)
{
	register unsigned	base;
	register char	c;

	if (len != 1 && (len % 2) != 0 || len > 8)
		return (-1);	/* not valid */
	/*
	 * Collect number up to first illegal character.  Values are specified
	 * as for C:  0x=hex, 0=octal, other=decimal.
	 */
	base = 10;
	if (**src == '0') {
		base = 8;
		(*src)++;
	}
	if (**src == 'x' || **src == 'X') {
		base = 16,
		(*src)++;
	}

	while (c = **src) {
		if (isdigit(c)) {
			switch (len) {
			case 1:
				*(u_char *) dest =
				    (*(u_char *) dest) * base + (c - '0');
				break;
			case 2:
				*(u_short *) dest = (*(u_short *) dest) *
				    base + (c - '0');
				break;
			case 4:
				*(u_long *) dest = (*(u_long *) dest) *
				    base + (c - '0');
				break;
			case 8:
				*(u_longlong_t *) dest =
				    (*(u_longlong_t *) dest) * base +
				    (c - '0');
				break;
			}
			(*src)++;
			continue;
		}
		if (base == 16 && isxdigit(c)) {
			switch (len) {
			case 1:
				*(u_char *) dest =
				    ((*(u_char *) dest) << 4) + ((c & ~32) +
				    10 - 'A');
				break;
			case 2:
				*(u_short *) dest =
				    ((*(u_short *) dest) << 4) + ((c & ~32) +
				    10 - 'A');
				break;
			case 4:
				*(u_long *) dest =
				    ((*(u_long *) dest) << 4) + ((c & ~32) +
				    10 - 'A');
				break;
			case 8:
				*(u_longlong_t *) dest =
				    ((*(u_longlong_t *) dest) << 4) +
				    ((c & ~32) + 10 - 'A');
				break;
			}
		    (*src)++;
		    continue;
		}
		break;
	}
	return (0);
}
main()
{
	char *src;
	u_char one;
	u_short two;
	u_long four;
	u_longlong_t eight;

	/*
	 * Try single octet (dec)
	 */
	src = "a56";
	one = 0;
	if (get_number(&src, (void *) &one, 1) != 0)
		printf("byte failed.\n");
	else
		printf("byte: %d\n", one);

	src = "65535";
	two = 0;
	if (get_number(&src, (void *) &two, 2) != 0)
		printf("short failed.\n");
	else
		printf("short: %d\n", two);

	src = "4294967296";
	four = 0;
	if (get_number(&src, (void *) &four, 4) != 0)
		printf("long failed.\n");
	else
		printf("long: %d\n", four);

	src = "4289672944289672944";
	eight = 0;
	if (get_number(&src, (void *) &eight, 8) != 0)
		printf("longlong failed.\n");
	else
		printf("longlong: %d\n", eight);



	/*
	 * Try single octet (hex)
	 */
	src = "0xff";
	one = 0;
	if (get_number(&src, (void *) &one, 1) != 0)
		printf("byte failed.\n");
	else
		printf("byte: 0x%x\n", one);

	src = "0xffff";
	two = 0;
	if (get_number(&src, (void *) &two, 2) != 0)
		printf("short failed.\n");
	else
		printf("short: 0x%x\n", two);

	src = "0xffffffff";
	four = 0;
	if (get_number(&src, (void *) &four, 4) != 0)
		printf("long failed.\n");
	else
		printf("long: 0x%x\n", four);

	src = "0xffffffffffffffff";
	eight = 0;
	if (get_number(&src, (void *) &eight, 8) != 0)
		printf("longlong failed.\n");
	else
		printf("longlong: 0x%x\n", eight);

	/*
	 * Try single octet (Oct)
	 */
	src = "0376";
	one = 0;
	if (get_number(&src, (void *) &one, 1) != 0)
		printf("byte failed.\n");
	else
		printf("byte: 0x%x\n", one);

	src = "0177776";
	two = 0;
	if (get_number(&src, (void *) &two, 2) != 0)
		printf("short failed.\n");
	else
		printf("short: 0x%x\n", two);

	src = "037777777776";
	four = 0;
	if (get_number(&src, (void *) &four, 4) != 0)
		printf("long failed.\n");
	else
		printf("long: 0x%x\n", four);

	src = "01777777777777777777776";
	eight = 0;
	if (get_number(&src, (void *) &eight, 8) != 0)
		printf("longlong failed.\n");
	else
		printf("longlong: 0x%x\n", eight);
	return (0);
}
