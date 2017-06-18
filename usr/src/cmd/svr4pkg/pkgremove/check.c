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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <utmpx.h>
#include <dirent.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <locale.h>
#include <libintl.h>
#include "install.h"
#include <pkglib.h>
#include "libadm.h"
#include "libinst.h"
#include "messages.h"

extern struct admin adm;

extern char	pkgloc[], *pkginst, *msgtext;

static boolean_t	preremoveCheck = B_FALSE;
static char		*zoneName = (char *)NULL;


void
rcksetPreremoveCheck(boolean_t a_preremoveCheck)
{
	preremoveCheck = a_preremoveCheck;
}

void
rcksetZoneName(char *a_zoneName)
{
	zoneName = a_zoneName;
}

int
rckrunlevel(void)
{
	struct utmpx utmpx;
	struct utmpx *putmpx;
	char	ans[MAX_INPUT];
	char	*pt;
	char	*rstates;
	int	n;
	char	*uxstate;

	if (ADM(runlevel, "nocheck")) {
		return (0);
	}

	pt = getenv("RSTATES");
	if (pt == NULL) {
		return (0);
	}

	utmpx.ut_type = RUN_LVL;
	putmpx = getutxid(&utmpx);
	if (putmpx == NULL) {
		progerr(ERR_RUNSTATE);
		return (99);
	}
	uxstate = strtok(&putmpx->ut_line[10], " \t\n");

	rstates = qstrdup(pt);
	if ((pt = strtok(pt, " \t\n, ")) == NULL)
		return (0); /* no list is no list */
	do {
		if (strcmp(pt, uxstate) == NULL) {
			free(rstates);
			return (0);
		}
	} while (pt = strtok(NULL, " \t\n, "));

	if (preremoveCheck == B_FALSE) {
		msgtext = MSG_PKGREMOVE_RUNLEVEL;
		ptext(stderr, msgtext, uxstate);
	} else {
		(void) fprintf(stdout, "runlevel=%s", uxstate);
	}

	pt = strtok(rstates, " \t\n, ");
	do {
		if (preremoveCheck == B_FALSE) {
			ptext(stderr, "\\t%s", pt);
		} else {
			(void) fprintf(stdout, ":%s", pt);
		}
	} while (pt = strtok(NULL, " \t\n, "));

	if (preremoveCheck == B_TRUE) {
		(void) fprintf(stdout, "\n");
	}

	free(rstates);

	if (ADM(runlevel, "quit")) {
		return (4);
	}

	if (echoGetFlag() == B_FALSE) {
		return (5);
	}

	msgtext = NULL;

	n = ckyorn(ans, NULL, NULL, HLP_PKGREMOVE_RUNLEVEL,
	    ASK_PKGREMOVE_CONTINUE);

	if (n != 0) {
		return (n);
	}

	if (strchr("yY", *ans) == NULL) {
		return (3);
	}

	return (0);
}

int
rckdepend(void)
{
	int	n;
	char	ans[MAX_INPUT];

	if (ADM(rdepend, "nocheck")) {
		return (0);
	}

	if (zoneName == (char *)NULL) {
		echo(MSG_CHECKREMOVE_PKG_IN_GZ, pkginst);
	} else {
		echo(MSG_CHECKREMOVE_PKG_IN_ZONE, pkginst, zoneName);
	}

	if (dockdeps(pkginst, 1, preremoveCheck)) {
		msgtext = MSG_PKGREMOVE_DEPEND;

		if (preremoveCheck == B_FALSE) {
			echo(msgtext);
		}

		if (ADM(rdepend, "quit")) {
			return (4);
		}

		if (echoGetFlag() == B_FALSE) {
			return (5);
		}

		msgtext = NULL;

		n = ckyorn(ans, NULL, NULL, HLP_PKGREMOVE_DEPEND,
		    ASK_PKGREMOVE_CONTINUE);

		if (n != 0) {
			return (n);
		}

		if (strchr("yY", *ans) == NULL) {
			return (3);
		}
	}

	return (0);
}

int
rckpriv(void)
{
	struct dirent	*dp;
	DIR		*dirfp;
	int		n;
	char		found;
	char		ans[MAX_INPUT];
	char		path[PATH_MAX];

	if (ADM(action, "nocheck")) {
		return (0);
	}

	(void) snprintf(path, sizeof (path), "%s/install", pkgloc);
	if ((dirfp = opendir(path)) == NULL)
		return (0);

	found = 0;
	while ((dp = readdir(dirfp)) != NULL) {
		if ((strcmp(dp->d_name, "preremove") == NULL) ||
		    (strcmp(dp->d_name, "postremove") == NULL) ||
		    (strncmp(dp->d_name, "r.", 2) == NULL)) {
			found++;
			break;
		}
	}
	(void) closedir(dirfp);

	if (found) {
		if (preremoveCheck == B_FALSE) {
			ptext(stderr, MSG_PKGREMOVE_PRIV);
		}
		msgtext = MSG_PKGSCRIPTS_FOUND;

		if (ADM(action, "quit")) {
			return (4);
		}

		if (echoGetFlag() == B_FALSE) {
			return (5);
		}

		msgtext = NULL;

		n = ckyorn(ans, NULL, NULL, HLP_PKGREMOVE_PRIV,
		    ASK_PKGREMOVE_CONTINUE);

		if (n != 0) {
			return (n);
		}

		if (strchr("yY", *ans) == NULL) {
			return (3);
		}
	}

	return (0);
}
