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
#include <libadm.h>
#include <libinst.h>

extern int	dbchg, warnflag, otherstoo;
extern char	*pkginst;

#define	EPTMALLOC	128

#define	ERR_WRENT	"write of entry failed, errno=%d"
#define	ERR_MEMORY	"no memory, errno=%d"
#define	ERR_READ_C	"bad read of contents file"
#define	ERR_READ_DB	"bad read of the database"

extern struct cfent	**eptlist;
extern int	eptnum;

int
delmap(int flag, char *pkginst)
{
	struct cfent	*ept;
	struct pinfo	*pinfo;
	VFP_T		*vfp;
	VFP_T		*vfpo;
	int		n;
	char		*unknown = "Unknown";


	if (!ocfile(&vfp, &vfpo, 0L)) {
		quit(99);
	}

	/* re-use any memory used to store pathnames */
	(void) pathdup(NULL);

	if (eptlist != NULL)
		free(eptlist);
	eptlist = (struct cfent **)calloc(EPTMALLOC,
					sizeof (struct cfent *));
	if (eptlist == NULL) {
		progerr(gettext(ERR_MEMORY), errno);
		quit(99);
	}

	ept = (struct cfent *)calloc(1,
				(unsigned)sizeof (struct cfent));
	if (!ept) {
		progerr(gettext(ERR_MEMORY), errno);
		quit(99);
	}

	eptnum = 0;
	while (n = srchcfile(ept, "*", vfp, (VFP_T *)NULL)) {
		if (n < 0) {
			char	*errstr = getErrstr();
			progerr(gettext("bad read of contents file"));
			progerr(gettext("pathname=%s"),
				(ept->path && *ept->path) ? ept->path :
				unknown);
			progerr(gettext("problem=%s"),
				(errstr && *errstr) ? errstr : unknown);
			exit(99);
		}
		pinfo = eptstat(ept, pkginst, (flag ? '@' : '-'));
		if (ept->npkgs > 0) {
			if (putcvfpfile(ept, vfpo)) {
				progerr(gettext(ERR_WRENT), errno);
				quit(99);
			}
		}

		if (flag || (pinfo == NULL))
			continue;

		dbchg++;

		/*
		 * If (otherstoo > 0), more than one package has an
		 * interest in the ept entry in the database. Setting
		 * ept->ftype = '\0' effectively marks the file as being
		 * "shared", thus ensuring the ept entry will not
		 * subsequently be removed. Shared editable files (ftype
		 * 'e') are a special case: they should be passed to a
		 * class action script if present. Setting ept->ftype =
		 * '^' indicates this special case of shared editable
		 * file, allowing the distinction to be made later.
		 */
		if (!pinfo->editflag && otherstoo)
			ept->ftype = (ept->ftype == 'e') ? '^' : '\0';
		if (*pinfo->aclass)
			(void) strcpy(ept->pkg_class, pinfo->aclass);
		eptlist[eptnum] = ept;

		ept->path = pathdup(ept->path);
		if (ept->ainfo.local != NULL)
			ept->ainfo.local = pathdup(ept->ainfo.local);

		ept = (struct cfent *)calloc(1, sizeof (struct cfent));
		if ((++eptnum % EPTMALLOC) == 0) {
			eptlist = (struct cfent **)realloc(eptlist,
			(eptnum+EPTMALLOC)*sizeof (struct cfent *));
			if (eptlist == NULL) {
				progerr(gettext(ERR_MEMORY), errno);
				quit(99);
			}
		}
	}

	eptlist[eptnum] = (struct cfent *)NULL;

	n = swapcfile(&vfp, &vfpo, pkginst, dbchg);
	if (n == RESULT_WRN) {
		warnflag++;
	} else if (n == RESULT_ERR) {
		quit(99);
	}

	return (0);
}
