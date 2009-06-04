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


/*
 * This module constructs a list of entries from the pkgmap associated
 * with this package. When finished, this list is sorted in alphabetical
 * order and an accompanying structure list, mergstat, provides
 * information about how these new files merge with existing files
 * already on the system.
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <install.h>
#include <pkglib.h>
#include <libadm.h>
#include <libinst.h>

/* libinst/ocfile.c */
extern int	dbchg;

static int	client_refer(struct cfextra **ext);
static int	server_refer(struct cfextra **ext);

int
sortmap(struct cfextra ***extlist, VFP_T *pkgmapVfp,
    VFP_T *mapvfp, VFP_T *tmpvfp, char *a_zoneName)
{
	int	i, n, nparts;
	char *db_mrg = "unable to merge package and system information";

	if (a_zoneName == (char *)NULL) {
		echo(gettext("## Processing package information."));
	} else {
		echo(gettext("## Processing package information in zone <%s>."),
			a_zoneName);
	}

	/*
	 * The following instruction puts the client-relative basedir
	 * into the environment iff it's a relocatable package and
	 * we're installing to a client. Otherwise, it uses the regular
	 * basedir. The only reason for this is so that mappath() upon
	 * finding $BASEDIR in a path will properly resolve it to the
	 * client-relative path. This way eval_path() can properly
	 * construct the server-relative path.
	 */
	if (is_relocatable() && is_an_inst_root())
		putparam("BASEDIR", get_info_basedir());

	/*
	 * read the pkgmap provided by this package into
	 * memory; map parameters specified in the pathname
	 * and sort in memory by pathname
	 */

	vfpRewind(pkgmapVfp);		/* rewind input file */

	*extlist = pkgobjmap(pkgmapVfp, 2, NULL);

	if (*extlist == NULL) {
		progerr(gettext("unable to process pkgmap"));
		quit(99);
	}

	/* Make all paths client-relative if necessary. */
	if (is_an_inst_root()) {
		(void) client_refer(*extlist);
	}

	if (a_zoneName == (char *)NULL) {
		echo(gettext("## Processing system information."));
	} else {
		echo(gettext("## Processing system information in zone <%s>."),
			a_zoneName);
	}

	/*
	 * calculate the number of parts in this package
	 * by locating the entry with the largest "volno"
	 * associated with it
	 */
	nparts = 0;
	if (is_depend_pkginfo_DB() == B_FALSE) {
		for (i = 0; (*extlist)[i]; i++) {
			n = (*extlist)[i]->cf_ent.volno;
			if (n > nparts)
				nparts = n;
		}

		vfpTruncate(tmpvfp);

		dbchg = pkgdbmerg(mapvfp, tmpvfp, *extlist, 60);
		if (dbchg < 0) {
			progerr(gettext(db_mrg));
			quit(99);
		}
	}

	/* Restore the original BASEDIR. */
	if (is_relocatable() && is_an_inst_root())
		putparam("BASEDIR", get_basedir());

	if (is_an_inst_root()) {
		(void) server_refer(*extlist);
	}

	return (nparts);
}

static int
client_refer(struct cfextra **ext)
{
	int count;

	for (count = 0; ext[count] != (struct cfextra *)NULL; count++) {
		ext[count]->cf_ent.path = ext[count]->client_path;
		ext[count]->cf_ent.ainfo.local = ext[count]->client_local;
	}

	return (1);
}

static int
server_refer(struct cfextra **ext)
{
	int count;

	for (count = 0; ext[count] != (struct cfextra *)NULL; count++) {
		ext[count]->cf_ent.path = ext[count]->server_path;
		ext[count]->cf_ent.ainfo.local = ext[count]->server_local;
	}

	return (1);
}
