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
#include <memory.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pkgstrct.h>
#include <locale.h>
#include <libintl.h>
#include <unistd.h>
#include <stdlib.h>
#include "pkglib.h"
#include "install.h"
#include "libadm.h"
#include "libinst.h"

extern int	Lflag, lflag, aflag, cflag, fflag, qflag, nflag, xflag, vflag;
extern char	*basedir, *device, pkgspool[];

#define	NXTENTRY(P, VFP) (gpkgmapvfp((P), (VFP)))

#define	ERR_SPOOLED	"ERROR: unable to locate spooled object <%s>"
#define	MSG_NET_OBJ	"It is remote and may be available from the network."
#define	ERR_RMHIDDEN	"unable to remove hidden file"
#define	ERR_HIDDEN	"ERROR: hidden file in exclusive directory"

static char	*findspool(struct cfent *ept);
static int	xdir(int maptyp, VFP_T *vfp, PKGserver server, char *dirname);

int
ckentry(int envflag, int maptyp, struct cfent *ept, VFP_T *vfp,
    PKGserver server)
{
	int	a_err, c_err,
		errflg;
	char	*path;
	char	*ir = get_inst_root();

	if (ept->ftype != 'i') {
		if (envflag)
			mappath(2, ept->path);
		if (!device)
			basepath(ept->path, maptyp ? NULL : basedir, ir);
	}
	canonize(ept->path);
	if (strchr("sl", ept->ftype)) {
		if (envflag)				/* -e option */
			mappath(2, ept->ainfo.local);
		if (!RELATIVE(ept->ainfo.local)) {	/* Absolute Path */
			if (!device) {
				if (ept->ftype == 'l')	/* Hard Link */
					basepath(ept->ainfo.local, NULL, ir);
			}
		}
		if (!RELATIVE(ept->ainfo.local))	/* Absolute Path */
			canonize(ept->ainfo.local);
	}
	if (envflag) {
		if (!strchr("isl", ept->ftype)) {
			mapvar(2, ept->ainfo.owner);
			mapvar(2, ept->ainfo.group);
		}
	}

	if (lflag) {
		tputcfent(ept, stdout);
		return (0);
	} else if (Lflag)
		return (putcfile(ept, stdout));

	errflg = 0;
	if (device) {
		if (strchr("dxslcbp", ept->ftype))
			return (0);
		if ((path = findspool(ept)) == NULL) {
			logerr(gettext(ERR_SPOOLED), ept->path);
			return (-1);
		}

		/*
		 * If the package file attributes are to be sync'd up with
		 * the pkgmap, we fix the attributes here.
		 */
		if (fflag) {
			a_err = 0;
			/* Clear dangerous bits. */
			ept->ainfo.mode = (ept->ainfo.mode & S_IAMB);
			/*
			 * Make sure the file is readable by the world and
			 * writeable by root.
			 */
			ept->ainfo.mode |= 0644;
			if (!strchr("in", ept->ftype)) {
				/* Set the safe attributes. */
				if (a_err = averify(fflag, &ept->ftype,
				    path, &ept->ainfo)) {
					errflg++;
					if (!qflag || (a_err != VE_EXIST)) {
						logerr(gettext("ERROR: %s"),
						    ept->path);
						logerr(getErrbufAddr());
					}
					if (a_err == VE_EXIST)
						return (-1);
				}
			}
		}
		/* Report invalid modtimes by passing cverify a -1 */
		c_err = cverify((!fflag ? (-1) : fflag),  &ept->ftype, path,
			&ept->cinfo, 1);
		if (c_err) {
			logerr(gettext("ERROR: %s"), path);
			logerr(getErrbufAddr());
			return (-1);
		}
	} else {
		a_err = 0;
		if (aflag && !strchr("in", ept->ftype)) {
			/* validate attributes */
			if (a_err = averify(fflag, &ept->ftype, ept->path,
			    &ept->ainfo)) {
				errflg++;
				if (!qflag || (a_err != VE_EXIST)) {
					logerr(gettext("ERROR: %s"),
					    ept->path);
					logerr(getErrbufAddr());
					if (maptyp && ept->pinfo->status ==
					    SERVED_FILE)
						logerr(gettext(MSG_NET_OBJ));
				}
				if (a_err == VE_EXIST)
					return (-1);
			}
		}
		if (cflag && strchr("fev", ept->ftype) &&
		    (!nflag || ept->ftype != 'v') && /* bug # 1082144 */
		    (!nflag || ept->ftype != 'e')) {
			/* validate contents */
			/* Report invalid modtimes by passing cverify a -1 */
			if (c_err = cverify((!fflag ? (-1) : fflag),
				&ept->ftype, ept->path, &ept->cinfo, 1)) {
				errflg++;
				if (!qflag || (c_err != VE_EXIST)) {
					if (!a_err)
						logerr(gettext("ERROR: %s"),
						    ept->path);
					logerr(getErrbufAddr());
					if (maptyp && ept->pinfo->status ==
					    SERVED_FILE)
						logerr(gettext(MSG_NET_OBJ));
				}
				if (c_err == VE_EXIST)
					return (-1);
			}
		}
		if (xflag && (ept->ftype == 'x')) {
			/* must do verbose here since ept->path will change */
			path = strdup(ept->path);
			if (xdir(maptyp, vfp, server, path))
				errflg++;
			(void) strcpy(ept->path, path);
			free(path);
		}
	}
	if (vflag)
		(void) fprintf(stderr, "%s\n", ept->path);
	return (errflg);
}

static int
xdir(int maptyp, VFP_T *vfp, PKGserver server, char *dirname)
{
	DIR		*dirfp;
	char		badpath[PATH_MAX];
	int		dirfound;
	int		errflg;
	int		len;
	int		n;
	struct cfent	mine;
	struct dirent	*drp;
	struct pinfo	*pinfo;
	void		*pos;

	if (!maptyp)
		pos = vfpGetCurrCharPtr(vfp); /* get current position in file */

	if ((dirfp = opendir(dirname)) == NULL) {
		progerr(gettext("unable to open directory <%s>"), dirname);
		return (-1);
	}
	len = strlen(dirname);

	errflg = 0;
	(void) memset((char *)&mine, '\0', sizeof (struct cfent));
	while ((drp = readdir(dirfp)) != NULL) {
		if (strcmp(drp->d_name, ".") == 0 ||
		    strcmp(drp->d_name, "..") == 0)
			continue;
		(void) snprintf(badpath, sizeof (badpath), "%s/%s",
		    dirname, drp->d_name);
		if (!maptyp) {
			dirfound = 0;
			while ((n = NXTENTRY(&mine, vfp)) != 0) {
				if (n < 0) {
					char	*errstr = getErrstr();
					logerr(gettext("ERROR: garbled entry"));
					logerr(gettext("pathname: %s"),
					    (mine.path && *mine.path) ?
					    mine.path : "Unknown");
					logerr(gettext("problem: %s"),
					    (errstr && *errstr) ? errstr :
					    "Unknown");
					exit(99);
				}
				if (strncmp(mine.path, dirname, len) ||
				    (mine.path[len] != '/'))
					break;
				if (strcmp(drp->d_name, &mine.path[len+1]) ==
				    0) {
					dirfound++;
					break;
				}
			}

			vfpGetCurrCharPtr(vfp) = pos;

			if (dirfound)
				continue;
		} else {
			if (srchcfile(&mine, badpath, server) == 1) {
				while ((pinfo = mine.pinfo) != NULL) {
					mine.pinfo = pinfo->next;
					free((char *)pinfo);
				}
				continue;
			}
		}

		if (fflag) {
			if (unlink(badpath)) {
				errflg++;
				logerr(gettext("ERROR: %s"), badpath);
				logerr(gettext(ERR_RMHIDDEN));
			}
		} else {
			errflg++;
			logerr(gettext("ERROR: %s"), badpath);
			logerr(gettext(ERR_HIDDEN));
		}
	}

	(void) closedir(dirfp);
	return (errflg);
}

static char *
findspool(struct cfent *ept)
{
	static char	path[2*PATH_MAX+1];
	char		host[PATH_MAX+1];

	(void) strcpy(host, pkgspool);
	if (ept->ftype == 'i') {
		if (strcmp(ept->path, "pkginfo"))
			(void) strcat(host, "/install");
	} else if (ept->path[0] == '/') {
		(void) strcat(host, "/root");
	} else {
		(void) strcat(host, "/reloc");
	}

	(void) snprintf(path, sizeof (path), "%s/%s", host,
		ept->path + (ept->path[0] == '/'));

	if (access(path, 0) == 0) {
		return (path);
	}

	if ((ept->ftype != 'i') && (ept->volno > 0)) {
		(void) snprintf(path, sizeof (path),
				"%s.%d/%s", host, ept->volno,
			ept->path + (ept->path[0] == '/'));
		if (access(path, 0) == 0) {
			return (path);
		}
	}
	return (NULL);
}
