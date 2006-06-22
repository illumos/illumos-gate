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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ulimit builtin
 */

#include <sys/resource.h>
#include <stdlib.h>
#include "defs.h"

/*
 * order is important in this table! it is indexed by resource ID.
 */

static struct rlimtab {
	char	*name;
	char	*scale;
	rlim_t	divisor;
} rlimtab[] = {
/* RLIMIT_CPU	*/	"time",		"seconds",	1,
/* RLIMIT_FSIZE */	"file",		"blocks",	512,
/* RLIMIT_DATA	*/	"data",		"kbytes",	1024,
/* RLIMIT_STACK */	"stack",	"kbytes",	1024,
/* RLIMIT_CORE	*/	"coredump",	"blocks",	512,
/* RLIMIT_NOFILE */	"nofiles",	"descriptors",	1,
/* RLIMIT_VMEM */	"memory",	"kbytes",	1024,
};

void
sysulimit(int argc, char **argv)
{
	extern int opterr, optind;
	int savopterr, savoptind, savsp;
	char *savoptarg;
	char *args;
	char errargs[PATH_MAX];
	int hard, soft, cnt, c, res;
	rlim_t limit, new_limit;
	struct rlimit rlimit;
	char resources[RLIM_NLIMITS];

	for (res = 0;  res < RLIM_NLIMITS; res++) {
		resources[res] = 0;
	}

	savoptind = optind;
	savopterr = opterr;
	savsp = _sp;
	savoptarg = optarg;
	optind = 1;
	_sp = 1;
	opterr = 0;
	hard = 0;
	soft = 0;
	cnt = 0;

	while ((c = getopt(argc, argv, "HSacdfnstv")) != -1) {
		switch (c) {
		case 'S':
			soft++;
			continue;
		case 'H':
			hard++;
			continue;
		case 'a':
			for (res = 0;  res < RLIM_NLIMITS; res++) {
				resources[res]++;
			}
			cnt = RLIM_NLIMITS;
			continue;
		case 'c':
			res = RLIMIT_CORE;
			break;
		case 'd':
			res = RLIMIT_DATA;
			break;
		case 'f':
			res = RLIMIT_FSIZE;
			break;
		case 'n':
			res = RLIMIT_NOFILE;
			break;
		case 's':
			res = RLIMIT_STACK;
			break;
		case 't':
			res = RLIMIT_CPU;
			break;
		case 'v':
			res = RLIMIT_VMEM;
			break;
		case '?':
			gfailure(usage, ulimuse);
			goto err;
		}
		resources[res]++;
		cnt++;
	}

	if (cnt == 0) {
		resources[res = RLIMIT_FSIZE]++;
		cnt++;
	}

	/*
	 * if out of arguments, then print the specified resources
	 */

	if (optind == argc) {
		if (!hard && !soft) {
			soft++;
		}
		for (res = 0; res < RLIM_NLIMITS; res++) {
			if (resources[res] == 0) {
				continue;
			}
			if (getrlimit(res, &rlimit) < 0) {
				continue;
			}
			if (cnt > 1) {
				prs_buff(_gettext(rlimtab[res].name));
				prc_buff('(');
				prs_buff(_gettext(rlimtab[res].scale));
				prc_buff(')');
				prc_buff(' ');
			}
			if (soft) {
				if (rlimit.rlim_cur == RLIM_INFINITY) {
					prs_buff(_gettext("unlimited"));
				} else  {
					prull_buff(rlimit.rlim_cur /
					    rlimtab[res].divisor);
				}
			}
			if (hard && soft) {
				prc_buff(':');
			}
			if (hard) {
				if (rlimit.rlim_max == RLIM_INFINITY) {
					prs_buff(_gettext("unlimited"));
				} else  {
					prull_buff(rlimit.rlim_max /
					    rlimtab[res].divisor);
				}
			}
			prc_buff('\n');
		}
		goto err;
	}

	if (cnt > 1 || optind + 1 != argc) {
		gfailure(usage, ulimuse);
		goto err;
	}

	if (eq(argv[optind], "unlimited")) {
		limit = RLIM_INFINITY;
	} else {
		args = argv[optind];

		new_limit = limit = 0;
		do {
			if (*args < '0' || *args > '9') {
				snprintf(errargs, PATH_MAX-1,
				"%s: %s", argv[0], args);
				failure(errargs, badnum);
				goto err;
			}
			/* Check for overflow! */
			new_limit = (limit * 10) + (*args - '0');
			if (new_limit >= limit) {
				limit = new_limit;
			} else {
				snprintf(errargs, PATH_MAX-1,
				"%s: %s", argv[0], args);
				failure(errargs, badnum);
				goto err;
			}
		} while (*++args);

		/* Check for overflow! */
		new_limit = limit * rlimtab[res].divisor;
		if (new_limit >= limit) {
			limit = new_limit;
		} else {
			snprintf(errargs, PATH_MAX-1,
			"%s: %s", argv[0], args);
			failure(errargs, badnum);
			goto err;
		}
	}

	if (getrlimit(res, &rlimit) < 0) {
		failure(argv[0], badnum);
		goto err;
	}

	if (!hard && !soft) {
		hard++;
		soft++;
	}
	if (hard) {
		rlimit.rlim_max = limit;
	}
	if (soft) {
		rlimit.rlim_cur = limit;
	}

	if (setrlimit(res, &rlimit) < 0) {
		snprintf(errargs, PATH_MAX-1,
		"%s: %s", argv[0], argv[optind]);
		failure(errargs, badulimit);
	}

err:
	optind = savoptind;
	opterr = savopterr;
	_sp = savsp;
	optarg = savoptarg;
}
