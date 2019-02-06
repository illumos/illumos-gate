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

#include <sys/salib.h>

#define	EOF	(-1)

int opterr = 1, optind = 1, optopt = 0;
char *optarg = NULL;
int _sp = 1;

extern void warn(const char *, ...);

void
getopt_reset(void)
{
	opterr = 1;
	optind = 1;
	optopt = 0;
	optarg = NULL;
	_sp = 1;
}

int
getopt(int argc, char *const *argv, const char *opts)
{
	char c;
	char *cp;

	if (_sp == 1) {
		if (optind >= argc || argv[optind][0] != '-' ||
		    argv[optind] == NULL || argv[optind][1] == '\0')
			return (EOF);
		else if (strcmp(argv[optind], "--") == 0) {
			optind++;
			return (EOF);
		}
	}
	optopt = c = (unsigned char)argv[optind][_sp];
	if (c == ':' || (cp = strchr(opts, c)) == NULL) {
		if (opts[0] != ':')
			warn("%s: illegal option -- %c\n", argv[0], c);
		if (argv[optind][++_sp] == '\0') {
			optind++;
			_sp = 1;
		}
		return ('?');
	}

	if (*(cp + 1) == ':') {
		if (argv[optind][_sp+1] != '\0')
			optarg = &argv[optind++][_sp+1];
		else if (++optind >= argc) {
			if (opts[0] != ':') {
				warn("%s: option requires an argument"
				    " -- %c\n", argv[0], c);
			}
			_sp = 1;
			optarg = NULL;
			return (opts[0] == ':' ? ':' : '?');
		} else
			optarg = argv[optind++];
		_sp = 1;
	} else {
		if (argv[optind][++_sp] == '\0') {
			_sp = 1;
			optind++;
		}
		optarg = NULL;
	}
	return (c);
}
