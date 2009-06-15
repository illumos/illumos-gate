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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include "install.h"
#include "libinst.h"
#include "libadm.h"

extern struct cfextra **extlist;
extern struct cfent **eptlist;

extern char	*pkginst;

#define	ERR_WRITE	"write of intermediate contents file failed"

static char *check_db_entry(VFP_T *, struct cfextra *, int, char *, int *);

/*ARGSUSED*/
int
dofinal(PKGserver server, VFP_T *vfpo, int rmflag, char *myclass, char *prog)
{
	struct cfextra entry;
	int	n, indx, dbchg;
	char	*save_path = NULL;

	entry.cf_ent.pinfo = NULL;
	entry.fsys_value = BADFSYS;
	entry.fsys_base = BADFSYS;
	indx = 0;

	while (extlist && extlist[indx] && (extlist[indx]->cf_ent.ftype == 'i'))
		indx++;

	dbchg = 0;

	if (pkgopenfilter(server, pkginst) != 0)
		quit(99);

	while (n = srchcfile(&(entry.cf_ent), "*", server)) {
		if (n < 0) {
			char	*errstr = getErrstr();
			progerr(gettext("bad entry read in contents file"));
			logerr(gettext("pathname=%s"),
			    (entry.cf_ent.path && *(entry.cf_ent.path)) ?
			    entry.cf_ent.path : "Unknown");
			logerr(gettext("problem=%s"),
			    (errstr && *errstr) ? errstr : "Unknown");
			quit(99);
		}
		save_path = check_db_entry(vfpo, &entry, rmflag, myclass,
		    &dbchg);

		/* Restore original server-relative path, if needed */
		if (save_path != NULL) {
			entry.cf_ent.path = save_path;
			save_path = NULL;
		}
	}

	pkgclosefilter(server);

	return (dbchg);
}

static char *
check_db_entry(VFP_T *vfpo, struct cfextra *entry, int rmflag, char *myclass,
		int *dbchg)
{
	struct pinfo *pinfo;
	int	fs_entry;
	char	*save_path = NULL;
	char	*tp;

	if (myclass && strcmp(myclass, entry->cf_ent.pkg_class)) {
		/*
		 * We already have it in the database we don't want
		 * to modify it.
		 */
		return (NULL);
	}

	/*
	 * Now scan each package instance holding this file or
	 * directory and see if it matches the package we are
	 * updating here.
	 */
	pinfo = entry->cf_ent.pinfo;
	while (pinfo) {
		if (strcmp(pkginst, pinfo->pkg) == 0)
			break;
		pinfo = pinfo->next;
	}

	/*
	 * If pinfo == NULL at this point, then this file or
	 * directory isn't part of the package of interest.
	 * So the code below executes only on files in the package
	 * of interest.
	 */

	if (pinfo == NULL)
		return (NULL);

	if (rmflag && (pinfo->status == RM_RDY)) {
		*dbchg = 1;

		(void) eptstat(&(entry->cf_ent), pkginst, '@');

		if (entry->cf_ent.npkgs) {
			if (putcvfpfile(&(entry->cf_ent), vfpo)) {
				progerr(gettext(ERR_WRITE));
				quit(99);
			}
		} else if (entry->cf_ent.path != NULL) {
			(void) vfpSetModified(vfpo);
			/* add "-<path>" to the file */
			vfpPutc(vfpo, '-');
			vfpPuts(vfpo, entry->cf_ent.path);
			vfpPutc(vfpo, '\n');
		}
		return (NULL);

	} else if (!rmflag && (pinfo->status == INST_RDY)) {
		*dbchg = 1;

		/* tp is the server-relative path */
		tp = fixpath(entry->cf_ent.path);
		/* save_path is the cmd line path */
		save_path = entry->cf_ent.path;
		/* entry has the server-relative path */
		entry->cf_ent.path = tp;

		/*
		 * The next if statement figures out how
		 * the contents file entry should be
		 * annotated.
		 *
		 * Don't install or verify objects for
		 * remote, read-only filesystems.  We
		 * need only verify their presence and
		 * flag them appropriately from some
		 * server. Otherwise, ok to do final
		 * check.
		 */
		fs_entry = fsys(entry->cf_ent.path);

		if (is_remote_fs_n(fs_entry) && !is_fs_writeable_n(fs_entry)) {
			/*
			 * Mark it shared whether it's present
			 * or not. life's too funny for me
			 * to explain.
			 */
			pinfo->status = SERVED_FILE;

			/*
			 * restore for now. This may
			 * chg soon.
			 */
			entry->cf_ent.path = save_path;
		} else {
			/*
			 * If the object is accessible, check
			 * the new entry for existence and
			 * attributes. If there's a problem,
			 * mark it NOT_FND; otherwise,
			 * ENTRY_OK.
			 */
			if (is_mounted_n(fs_entry)) {
				int	n;

				n = finalck((&entry->cf_ent), 1, 1, B_FALSE);

				pinfo->status = ENTRY_OK;
				if (n != 0) {
					pinfo->status = NOT_FND;
				}
			}

			/*
			 * It's not remote, read-only but it
			 * may look that way to the client.
			 * If it does, overwrite the above
			 * result - mark it shared.
			 */
			if (is_served_n(fs_entry))
				pinfo->status = SERVED_FILE;

			/* restore original path */
			entry->cf_ent.path = save_path;
			/*   and clear save_path */
			save_path = NULL;
		}
	}

	/* Output entry to contents file. */
	if (putcvfpfile(&(entry->cf_ent), vfpo)) {
		progerr(gettext(ERR_WRITE));
		quit(99);
	}

	return (save_path);
}
