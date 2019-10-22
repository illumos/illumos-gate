/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdio.h>
#include <err.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <libcustr.h>
#include "cron.h"

#ifdef PARSETEST
#define	xstrdup(x) strdup((x))
#endif

#define	MAX_ELEMENTS 60

#define	READNUMBER(x) \
	do { \
		(x) = (x) * 10 + (line[cursor] - '0'); \
		if ((x) > MAX_ELEMENTS) { \
			err = CFOUTOFBOUND; \
			goto out; \
		} \
	} while (isdigit(line[++cursor]))

#define	ADDELEMENT(x)  \
	do { \
		if (eindex >= MAX_ELEMENTS) { \
			err = CFEOVERFLOW; \
			goto out; \
		} \
		elements[eindex++] = (x); \
	} while (0)

/* A more restrictive version of isspace(3C) that only looks for space/tab */
#define	ISSPACE(x) \
	((x) == ' ' || (x) == '\t')

cferror_t
next_field(uint_t lower, uint_t upper, char *line, int *cursorp, char **ret)
{
	uint_t elements[MAX_ELEMENTS];
	uint_t eindex = 0, i;
	int cursor = *cursorp;
	cferror_t err = CFOK;

	assert(upper - lower <= MAX_ELEMENTS);

	if (ret != NULL)
		*ret = NULL;

	while (ISSPACE(line[cursor]))
		cursor++;

	if (line[cursor] == '\0') {
		err = CFEOLN;
		goto out;
	}

	for (;;) {
		uint_t num = 0, num2 = 0, step = 0;

		if (line[cursor] == '*') {
			cursor++;

			/* Short circuit for plain '*' */
			if (ISSPACE(line[cursor])) {
				if (ret != NULL)
					*ret = xstrdup("*");
				goto out;
			}

			/*
			 * '*' is only permitted alongside other elements if
			 * it has an associated step.
			 */

			if (line[cursor] != '/') {
				err = CFUNEXPECT;
				goto out;
			}

			/* Treat it as a range covering all values */
			num = lower;
			num2 = upper;
		} else {
			if (!isdigit(line[cursor])) {
				err = CFUNEXPECT;
				goto out;
			}

			READNUMBER(num);

			if (num < lower || num > upper) {
				err = CFOUTOFBOUND;
				goto out;
			}

			if (line[cursor] == '-') {
				cursor++;
				if (!isdigit(line[cursor])) {
					err = CFUNEXPECT;
					goto out;
				}

				READNUMBER(num2);

				if (num2 < lower || num2 > upper) {
					err = CFOUTOFBOUND;
					goto out;
				}
			} else {
				ADDELEMENT(num);
				goto next;
			}
		}

		/* Look for a step definition */
		if (line[cursor] == '/') {
			cursor++;
			if (!isdigit(line[cursor])) {
				err = CFUNEXPECT;
				goto out;
			}

			READNUMBER(step);

			if (step == 0) {
				err = CFOUTOFBOUND;
				goto out;
			}
		} else {
			step = 1;
		}

		if (num <= num2) {
			for (i = num; i <= num2; i += step) {
				ADDELEMENT(i);
			}
		} else {
			/* Wrap-around range */
			for (i = num; i <= upper; i += step) {
				ADDELEMENT(i);
			}

			i -= (upper - lower + 1);
			for (; i <= num2; i += step) {
				ADDELEMENT(i);
			}
		}

next:

		if (line[cursor] != ',')
			break;

		cursor++;
	}

	if (line[cursor] == '\0') {
		err = CFEOLN;
		goto out;
	}

	if (!ISSPACE(line[cursor])) {
		err = CFUNEXPECT;
		goto out;
	}

	if (ret != NULL) {
		custr_t *cs = NULL;

		if (custr_alloc(&cs) != 0) {
			err = CFENOMEM;
			goto out;
		}

		for (i = 0; i < eindex; i++) {
			if (custr_len(cs) > 0) {
				if (custr_appendc(cs, ',') != 0) {
					custr_free(cs);
					err = CFENOMEM;
					goto out;
				}
			}
			if (custr_append_printf(cs, "%u", elements[i]) != 0) {
				custr_free(cs);
				err = CFENOMEM;
				goto out;
			}
		}

		if (custr_len(cs) != 0)
			*ret = xstrdup(custr_cstr(cs));
		custr_free(cs);
	}

out:

	*cursorp = cursor;

	return (err);
}

#ifdef PARSETEST
int
main(int argc, char **argv)
{
	int lower, upper, cursor = 0;
	char *ret;

	if (argc != 4)
		errx(1, "<lower> <upper> <string>");

	lower = atoi(argv[1]);
	upper = atoi(argv[2]);

	switch (next_field(lower, upper, argv[3], &cursor, &ret)) {
	case CFOK:
		(void) printf("%s\n", ret);
		break;
	case CFEOLN:
		(void) printf("UnexpectedEOL\n");
		break;
	case CFUNEXPECT:
		(void) printf("UnexpectedChar\n");
		break;
	case CFOUTOFBOUND:
		(void) printf("OutOfBounds\n");
		break;
	case CFEOVERFLOW:
		(void) printf("Overflow\n");
		break;
	case CFENOMEM:
		(void) printf("OutOfMemory\n");
		break;
	default:
		(void) printf("UnknownError\n");
		break;
	}

	return (0);
}
#endif
