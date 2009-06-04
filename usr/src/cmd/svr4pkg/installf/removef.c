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
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include "installf.h"

void
removef(int argc, char *argv[])
{
	struct cfextra *new;
	char	buf[PATH_MAX];
	char	*path;
	int	flag;
	int	len;
	int	max_eptnum;

	flag = strcmp(argv[0], "-") == 0;

	eptnum = 0;
	max_eptnum = 64;	/* starting size of array */
	extlist = malloc(max_eptnum * sizeof (struct cfextra *));

	for (;;) {
		if (flag) {
			if (fgets(buf, PATH_MAX, stdin) == NULL)
				break;

			/* strip trailing new line */
			len = strlen(buf);
			if (buf[len - 1] == '\n')
				buf[len - 1] = '\0';

			path = buf;
		} else {
			if (argc-- <= 0)
				break;
			path = argv[argc];
		}

		/*
		 * This strips the install root from the path using
		 * a questionable algorithm. This should go away as
		 * we define more precisely the command line syntax
		 * with our '-R' option. - JST
		 */
		path = orig_path_ptr(path);

		if (path == NULL) {
			logerr(gettext("ERROR: no pathname was provided"));
			warnflag++;
			continue;
		}

		if (*path != '/') {
			logerr(gettext(
			    "WARNING: relative pathname <%s> ignored"), path);
			warnflag++;
			continue;
		}

		new = calloc(1, sizeof (struct cfextra));
		if (new == NULL) {
			progerr(strerror(errno));
			quit(99);
		}
		new->cf_ent.ftype = '-';

		(void) eval_path(&(new->server_path), &(new->client_path),
		    &(new->map_path), path);

		new->cf_ent.path = new->client_path;

		extlist[eptnum++] = new;
		if (eptnum >= max_eptnum) {
			/* array size grows exponentially */
			max_eptnum <<= 1;
			extlist = realloc(extlist,
			    max_eptnum * sizeof (struct cfextra *));
			if (extlist == NULL) {
				progerr(strerror(errno));
				quit(99);
			}
		}
	}
	extlist[eptnum] = (struct cfextra *)NULL;

	qsort((char *)extlist,
	    (unsigned)eptnum, sizeof (struct cfextra *), cfentcmp);
}
