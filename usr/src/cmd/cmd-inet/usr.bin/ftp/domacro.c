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
 *	Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved  	*/

/*
 *	University Copyright- Copyright (c) 1982, 1986, 1988
 *	The Regents of the University of California
 *	All Rights Reserved
 *
 *	University Acknowledgment- Portions of this document are derived from
 *	software developed by the University of California, Berkeley, and its
 *	contributors.
 */

#include <libintl.h>
#include <stdlib.h>

#include "ftp_var.h"

#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

void
domacro(int argc, char *argv[])
{
	register int i, j;
	register char *cp1, *cp2;
	int count = 2, loopflg = 0;
	char line2[200];
	struct cmd *c;
	int	len;

	if (argc < 2) {
		stop_timer();
		(void) strcat(line, " ");
		printf("(macro name) ");
		(void) gets(&line[strlen(line)]);
		reset_timer();
		makeargv();
		argc = margc;
		argv = margv;
	}
	if (argc < 2) {
		printf("Usage: %s macro_name.\n", argv[0]);
		code = -1;
		return;
	}
	for (i = 0; i < macnum; ++i) {
		if (strncmp(argv[1], macros[i].mac_name, 9) == 0) {
			break;
		}
	}
	if (i == macnum) {
		printf("'%s' macro not found.\n", argv[1]);
		code = -1;
		return;
	}
	(void) strcpy(line2, line);
TOP:
	cp1 = macros[i].mac_start;
	while (cp1 != macros[i].mac_end) {
		while (isspace(*cp1)) {
			cp1++;
		}
		cp2 = line;
		while (*cp1 != '\0') {
			switch (*cp1) {
			case '\\':
				cp1++;
				if ((len = mblen(cp1, MB_CUR_MAX)) <= 0)
					len = 1;
				memcpy(cp2, cp1, len);
				cp2 += len;
				cp1 += len;
				break;

			case '$':
				if (isdigit(*(cp1+1))) {
					j = 0;
					while (isdigit(*++cp1))
						j = 10 * j +  *cp1 - '0';
					if (argc - 2 >= j) {
						(void) strcpy(cp2, argv[j+1]);
						cp2 += strlen(argv[j+1]);
					}
					break;
				}
				if (*(cp1+1) == 'i') {
					loopflg = 1;
					cp1 += 2;
					if (count < argc) {
						(void) strcpy(cp2, argv[count]);
						cp2 += strlen(argv[count]);
					}
					break;
				}
				/* FALLTHROUGH */
			default:
				if ((len = mblen(cp1, MB_CUR_MAX)) <= 0)
					len = 1;
				memcpy(cp2, cp1, len);
				cp2 += len;
				cp1 += len;
				break;
			}
		}
		*cp2 = '\0';
		makeargv();
		if (margv[0] == NULL) {
			code = -1;
			return;
		} else {
			c = getcmd(margv[0]);
		}
		if (c == (struct cmd *)-1) {
			printf("?Ambiguous command\n");
			code = -1;
		} else if (c == 0) {
			printf("?Invalid command\n");
			code = -1;
		} else if (c->c_conn && !connected) {
			printf("Not connected.\n");
			code = -1;
		} else {
			if (verbose) {
				printf("%s\n", line);
			}
			(*c->c_handler)(margc, margv);
#define	CTRL(c) ((c)&037)
			if (bell && c->c_bell) {
				(void) putchar(CTRL('g'));
			}
			(void) strcpy(line, line2);
			makeargv();
			argc = margc;
			argv = margv;
		}
		if (cp1 != macros[i].mac_end) {
			cp1++;
		}
	}
	if (loopflg && ++count < argc) {
		goto TOP;
	}
}
