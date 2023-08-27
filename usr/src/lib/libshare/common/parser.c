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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdio.h>
#include <ctype.h>

#define	TK_INIT		0
#define	TK_TOKEN	1
#define	TK_SKIPWHITE	2
#define	TK_QUOTED	3

/*
 * assumes quoted strings are delimited by white space (i.e sp
 * "string" sp). Backslash can be used to quote a quote mark.
 * quoted strings will have the quotes stripped.
 */

char *
_sa_get_token(char *string)
{
	static char *orig = NULL;
	static char *curp;
	char *ret;
	int state = TK_INIT;
	int c;
	int quotechar = 0;

	if (string != orig || string == NULL) {
		orig = string;
		curp = string;
		if (string == NULL) {
			return (NULL);
		}
	}
	ret = curp;
	while ((c = *curp) != '\0') {
		switch (state) {
		case TK_SKIPWHITE:
		case TK_INIT:
			if (isspace(c)) {
				while (*curp && isspace(*curp))
					curp++;
				ret = curp;
			}
			if (c == '"' || c == '\'') {
				state = TK_QUOTED;
				curp++;
				ret = curp;
				quotechar = c; /* want to match for close */
			} else {
				state = TK_TOKEN;
			}
			break;
		case TK_TOKEN:
			switch (c) {
			case '\\':
				curp++;
				if (*curp) {
					curp++;
					break;
				}
				return (ret);
			default:
				if (*curp == '\0' || isspace(c)) {
					*curp++ = '\0';
					return (ret);
				}
				curp++;
				break;
			}
			break;
		case TK_QUOTED:
			switch (c) {
			case '\\':
				curp++;
				if (*curp) {
					curp++;
					break;
				}
				curp++;
				break;
			default:
				if (c == '\0' || c == quotechar) {
					*curp++ = '\0';
					return (ret);
				}
				curp++;
				break;
			}
			break;
		}
	}
	return (NULL);
}
