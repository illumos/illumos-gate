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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <valtools.h>
#include <locale.h>
#include <libintl.h>
#include <pkginfo.h>
#include "install.h"
#include <pkglib.h>
#include "libadm.h"
#include "libinst.h"
#include "pkginstall.h"
#include "messages.h"

extern struct admin adm;
extern char	*pkgarch, *pkgvers, *msgtext, *pkgabrv;
extern int	maxinst;

static char	newinst[PKGSIZ];
static char	*nextinst(void);
static char	*prompt(struct pkginfo *info, int npkgs);
static int	same_pkg;	/* same PKG, ARCH and VERSION */

/*
 * This returns the correct package instance based on how many packages are
 * already installed. If there are none (npkgs == 0), it just returns the
 * package abbreviation. Otherwise, it interacts with the user (or reads the
 * admin file) to determine if we should overwrite an instance which is
 * already installed, or possibly install a new instance of this package
 */
char *
getinst(int *updatingExisting, struct pkginfo *info, int npkgs,
	boolean_t a_preinstallCheck)
{
	char	*inst;
	char	*sameinst;
	int	i;
	int	nsamearch;
	int	samearch;

	/* entry debugging info */

	same_pkg = 0;

	/*
	 * If this is the first instance of the package, it's called the by
	 * the package abbreviation.
	 */

	if (npkgs == 0) {
		return (pkgabrv);
	}

	/*
	 * this package is already installed; determine how to handle the
	 * new instance of the package to install
	 */

	if (ADM(instance, "newonly") || ADM(instance, "quit")) {
		/*
		 * new instance is required, or quit if not new
		 */

		msgtext = MSG_NEWONLY;
		if (a_preinstallCheck == B_FALSE) {
			ptext(stderr, msgtext, pkgabrv);
		} else {
			(void) fprintf(stdout, "install-new-only=true\n");
			(void) fprintf(stdout, "ckinstance=4\n");
		}
		quit(4);
	}

	/*
	 * package already installed and new instance not required
	 * see if updating the same instance of the package
	 */

	samearch = nsamearch = 0;
	sameinst  = NULL;
	for (i = 0; i < npkgs; i++) {
		if (strcmp(info[i].arch, pkgarch) == 0) {
			samearch = i;
			nsamearch++;
			if (strcmp(info[i].version, pkgvers) == 0) {
				sameinst = info[i].pkginst;
			}
		}
	}

	if (sameinst) {
		/* same instance of package */
		if (a_preinstallCheck == B_FALSE) {
			ptext(stderr, MSG_SAME);
		} else {
			(void) fprintf(stdout, "install-same-instance=true\n");
			(void) fprintf(stdout, "ckinstance=0\n");
		}

		inst = sameinst;
		same_pkg++;
		(*updatingExisting)++;
		return (inst);
	}

	if (ADM(instance, "overwrite")) {
		/* not the same instance of the package */
		if (npkgs == 1) {
			samearch = 0; /* use only package we know about */
		} else if (nsamearch != 1) {
			/*
			 * more than one instance of the same ARCH is already
			 * installed on this machine
			 */
			msgtext = MSG_OVERWRITE;
			if (a_preinstallCheck == B_FALSE) {
				ptext(stderr, msgtext);
			} else {
				(void) fprintf(stdout,
					"install-ovewrite=true\n");
				(void) fprintf(stdout, "ckinstance=4\n");
			}
			quit(4);
		}

		inst = info[samearch].pkginst;

		(*updatingExisting)++;
		return (inst);
	}

	if (ADM(instance, "unique")) {
		if (maxinst <= npkgs) {
			/* too many instances */
			msgtext = MSG_UNIQ1;
			if (a_preinstallCheck == B_FALSE) {
				ptext(stderr, msgtext, pkgabrv);
			} else {
				(void) fprintf(stdout,
					"install-too-many-instances=true\n");
				(void) fprintf(stdout, "ckinstance=4\n");
			}
			quit(4);
		}
		inst = nextinst();
		return (inst);
	}

	if (a_preinstallCheck == B_FALSE) {
		if (echoGetFlag() == B_FALSE) {
			msgtext = MSG_NOINTERACT;
			ptext(stderr, msgtext);
			quit(5);
		}
	} else {
		(void) fprintf(stdout, "install-new-instance=true\n");
		(void) fprintf(stdout, "ckinstance=1\n");
	}

	inst = prompt(info, npkgs);
	if (strcmp(inst, "new") == 0) {
		inst = nextinst();
		return (inst);
	}

	(*updatingExisting)++;

	return (inst);
}

/*
 * This informs the caller whether the package in question is the same
 * version and architecture as an installed package of the same name.
 */

int
is_samepkg(void) {
	return (same_pkg);
}

static char *
nextinst(void)
{
	struct pkginfo info;
	int	n;

	n = 2; /* requirements say start at 2 */

	info.pkginst = NULL;
	(void) strcpy(newinst, pkgabrv);
	while (pkginfo(&info, newinst, NULL, NULL) == 0) {
		(void) snprintf(newinst, sizeof (newinst),
				"%s.%d", pkgabrv, n++);
	}
	return (newinst);
}

static char *
prompt(struct pkginfo *info, int npkgs)
{
	CKMENU	*menup;
	char	*inst;
	char	ans[MAX_INPUT];
	char	header[256];
	char	temp[256];
	int	i;
	int	n;

	if (maxinst > npkgs) {
		/*
		 * the user may choose to install a completely new
		 * instance of this package
		 */
		n = ckyorn(ans, NULL, NULL, MSG_GETINST_HELP1,
			MSG_GETINST_PROMPT1);
		if (n != 0) {
			quit(n);
		}
		if (strchr("yY", *ans) != NULL) {
			return ("new");
		}
	}

	(void) snprintf(header, sizeof (header), MSG_GETINST_HEADER, pkgabrv);
	menup = allocmenu(header, CKALPHA);

	for (i = 0; i < npkgs; i++) {
		(void) snprintf(temp, sizeof (temp),
				"%s %s\n(%s) %s", info[i].pkginst,
			info[i].name, info[i].arch, info[i].version);
		if (setitem(menup, temp)) {
			progerr("no memory");
			quit(99);
		}
	}

	if (npkgs == 1) {
		printmenu(menup);
		if (n = ckyorn(ans, NULL, NULL, NULL, MSG_GETINST_PROMPT0))
			quit(n);
		if (strchr("yY", *ans) == NULL)
			quit(3);
		(void) strcpy(newinst, info[0].pkginst);
	} else {
		if (n = ckitem(menup, &inst, 1, NULL, NULL, MSG_GETINST_HELP2,
		    MSG_GETINST_PROMPT2))
			quit(n);
		(void) strcpy(newinst, inst);
	}
	(void) setitem(menup, 0); /* clear resource usage */
	free(menup); /* clear resource usage */

	return (newinst);
}
