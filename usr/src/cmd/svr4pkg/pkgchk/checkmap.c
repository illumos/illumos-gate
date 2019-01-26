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
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <pkgstrct.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include "libadm.h"
#include "libinst.h"

extern int	qflag, lflag, Lflag, pkgcnt;
extern short	npaths;

extern char	*basedir, *pathlist[], *ppathlist[], **pkg, **environ;

extern short	used[];
extern struct cfent **eptlist;

/* ckentry.c */
extern int	ckentry(int, int, struct cfent *, VFP_T *, PKGserver);

#define	NXTENTRY(P, VFP, SRV) \
		(maptyp ? srchcfile((P), "*", (SRV)) : \
		gpkgmapvfp((P), (VFP)))

#define	MSG_ARCHIVE	"NOTE: some pathnames are in private formats " \
			    "and cannot be verified"
#define	WRN_NOPKG	"WARNING: no pathnames were associated with <%s>"
#define	WRN_NOPATH	"WARNING: no information associated with pathname <%s>"
#define	EMPTY_PKG "WARNING: Package <%s> is installed but empty"
#define	ERR_NOMEM	"unable to allocate dynamic memory, errno=%d"
#define	ERR_PKGMAP	"unable to open pkgmap file <%s>"
#define	ERR_ENVFILE	"unable to open environment file <%s>"

static struct cfent entry;

static int	shellmatch(char *, char *);
static int is_partial_path_in_DB(char *, char *);

int	selpath(char *, int);
int	selpkg(char *);

/*
 * This routine checks all files which are referenced in the pkgmap which is
 * identified by the mapfile arg. When the package is installed, the mapfile
 * may be the contents file or a separate pkgmap (maptyp tells the function
 * which it is). The variable uninst tells the function whether the package
 * is in the installed state or not. The envfile entry is usually a pkginfo
 * file, but it could be any environment parameter list.
 */

int
checkmap(int maptyp, int uninst, char *mapfile, char *envfile,
		char *pkginst, char *path, int pathtype)
{
	FILE		*fp;
	char		*cl = NULL;
	char		*value;
	char		param[MAX_PKG_PARAM_LENGTH];
	int		count;
	int		errflg;
	int		n;
	int		selected;
	struct pinfo	*pinfo;
	VFP_T		*vfp = (VFP_T *)NULL;
	PKGserver	server;

	if (envfile != NULL) {
		if ((fp = fopen(envfile, "r")) == NULL) {
			progerr(gettext(ERR_ENVFILE), envfile);
			return (-1);
		}
		param[0] = '\0';
		while (value = fpkgparam(fp, param)) {
			if (strcmp("PATH", param) != 0) {
				/*
				 * If checking an uninstalled package, we
				 * only want two parameters. If we took all
				 * of them, including path definitions, we
				 * wouldn't be looking in the right places in
				 * the reloc and root directories.
				 */
				if (uninst) {
					if ((strncmp("PKG_SRC_NOVERIFY", param,
					    16) == 0) && value) {
						logerr(gettext(MSG_ARCHIVE));
						putparam(param, value);
					}
					if ((strncmp("CLASSES", param,
					    7) == 0) && value)
						putparam(param, value);
				} else
					putparam(param, value);
			}

			free(value);

			param[0] = '\0';
		}
		(void) fclose(fp);
		basedir = getenv("BASEDIR");
	}

	/*
	 * If we are using a contents file for the map, this locks the
	 * contents file in order to freeze the database and assure it
	 * remains synchronized with the file system against which it is
	 * being compared. There is no practical way to lock another pkgmap
	 * on some unknown medium so we don't bother.
	 */
	if (maptyp) {	/* If this is the contents file */
		if (!socfile(&server, B_FALSE) ||
		    pkgopenfilter(server, pkgcnt == 1 ? pkginst : NULL) != 0) {
			progerr(gettext(ERR_PKGMAP), "contents");
			return (-1);
		}
	} else {
		if (vfpOpen(&vfp, mapfile, "r", VFP_NONE) != 0) {
			progerr(gettext(ERR_PKGMAP), mapfile);
			return (-1);
		}
	}

	if ((cl = getenv("CLASSES")) != NULL)
		cl_sets(qstrdup(cl));

	errflg = count = 0;

	do {
		if ((n = NXTENTRY(&entry, vfp, server)) == 0) {
			break;
		}
		/*
		 * Search for partial paths in the ext DB.
		 */
		if (pathtype) {
			/* LINTED warning: statement has no consequent: if */
			if (is_partial_path_in_DB(entry.path, path)) {
				/* Check this entry */
				;
			} else if (entry.ftype == 's' || entry.ftype == 'l') {
				if (is_partial_path_in_DB(
				/* LINTED warning: statement has no consequen */
					entry.ainfo.local, path)) {
					/* Check this entry */
					;
				} else {
					continue;
				}
			} else {
				/* Skip to next DB entry */
				continue;
			}
		}

		if (n < 0) {
			char	*errstr = getErrstr();
			logerr(gettext("ERROR: garbled entry"));
			logerr(gettext("pathname: %s"),
			    (entry.path && *entry.path) ? entry.path :
			    "Unknown");
			logerr(gettext("problem: %s"),
			    (errstr && *errstr) ? errstr : "Unknown");
			exit(99);
		}
		if (n == 0)
			break; /* done with file */

		/*
		 * The class list may not be complete for good reason, so
		 * there's no complaining if this returns an index of -1.
		 */
		if (cl != NULL)
			entry.pkg_class_idx = cl_idx(entry.pkg_class);

		if (maptyp && pkginst != NULL) {
			/*
			 * check to see if the entry we just read
			 * is associated with one of the packages
			 * we have listed on the command line
			 */
			selected = 0;
			pinfo = entry.pinfo;
			while (pinfo) {
				if (selpkg(pinfo->pkg)) {
					selected++;
					break;
				}
				pinfo = pinfo->next;
			}
			if (!selected)
				continue; /* not selected */
		}

		/*
		 * Check to see if the pathname associated with the entry
		 * we just read is associated with the list of paths we
		 * supplied on the command line
		 */
		if (!selpath(entry.path, pathtype))
			continue; /* not selected */

		/*
		 * Determine if this is a package object wanting
		 * verification. Metafiles are always checked, otherwise, we
		 * rely on the class to discriminate.
		 */
		if (entry.ftype != 'i')
			/* If there's no class list... */
			if (cl != NULL)
				/*
				 * ... or this entry isn't in that class list
				 * or it's in a private format, then don't
				 * check it.
				 */
				if (entry.pkg_class_idx == -1 ||
				    cl_svfy(entry.pkg_class_idx) == NOVERIFY)
					continue;

		count++;
		if (ckentry((envfile ? 1 : 0), maptyp, &entry, vfp, server))
			errflg++;
	} while (n != 0);

	if (maptyp)
		relslock();
	else
		(void) vfpClose(&vfp);

	if (environ) {
		/* free up environment resources */
		for (n = 0; environ[n]; n++)
			free(environ[n]);
		free(environ);
		environ = NULL;
	}

	if (maptyp) {
		/*
		 * make sure each listed package was associated with
		 * an entry from the prototype or pkgmap
		 */
		(void) selpkg(NULL);
	}
	if (!qflag && !lflag && !Lflag) {
		/*
		 * make sure each listed pathname was associated with an entry
		 * from the prototype or pkgmap
		 */
		(void) selpath(NULL, pathtype);
	}
	return (errflg);
}

int
selpkg(char *p)
{
	static char *selected;
	char buf[80];
	char *root;
	register int i;

	if (p == NULL) {
		if (selected == NULL) {
			if (pkgcnt) {
				for (i = 0; i < pkgcnt; ++i) {
					/* bugid 1227628 */
					root = get_inst_root();
					if (root)
						(void) snprintf(buf,
						sizeof (buf),
						"%s/var/sadm/pkg/%s/pkginfo",
						root, pkg[i]);
					else
						(void) snprintf(buf,
						sizeof (buf),
						"/var/sadm/pkg/%s/pkginfo",
						pkg[i]);

					if (access(buf, F_OK))
						logerr(gettext(WRN_NOPKG),
							pkg[i]);
					else
						logerr(gettext(EMPTY_PKG),
							pkg[i]);
				}
			}
		} else {
			for (i = 0; i < pkgcnt; ++i) {
				if (selected[i] == '\0') {
					root = get_inst_root();
					if (root)
						(void) snprintf(buf,
						sizeof (buf),
						"%s/var/sadm/pkg/%s/pkginfo",
						root, pkg[i]);
					else
						(void) snprintf(buf,
						sizeof (buf),
						"/var/sadm/pkg/%s/pkginfo",
						pkg[i]);

					if (access(buf, F_OK))
						logerr(gettext(WRN_NOPKG),
							pkg[i]);
					else
						logerr(gettext(EMPTY_PKG),
							pkg[i]);
				}
			}
		}
		return (0); /* return value not important */
	} else if (pkgcnt == 0)
		return (1);
	else if (selected == NULL) {
		selected =
		    (char *)calloc((unsigned)(pkgcnt+1), sizeof (char));
		if (selected == NULL) {
			progerr(gettext(ERR_NOMEM), errno);
			exit(99);
			/*NOTREACHED*/
		}
	}

	for (i = 0; i < pkgcnt; ++i) {
		if (pkgnmchk(p, pkg[i], 0) == 0) {
			if (selected != NULL)
				selected[i] = 'b';
			return (1);
		}
	}
	return (0);
}

int
selpath(char *path, int partial_path)
{
	int n;

	if (!npaths)
		return (1); /* everything is selectable */

	for (n = 0; n < npaths; n++) {
		if (path == NULL) {
			if (!used[n])
				logerr(gettext(WRN_NOPATH),
					partial_path ? ppathlist[n] :
					pathlist[n]);
		} else if (partial_path) {
			used[n] = 1;
			return (1);
		} else if (!shellmatch(pathlist[n], path)) {
			used[n] = 1;
			return (1);
		}
	}
	return (0); /* not selected */
}

static int
shellmatch(char *spec, char *path)
{
	/* Check if the value is NULL */
	if (spec == NULL || path == NULL)
		return (1);

	while (*spec && (*spec == *path)) {
		spec++, path++;
	}
	if ((*spec == *path) || (*spec == '*'))
		return (0);
	return (1);
}

static int
is_partial_path_in_DB(char *srcpath, char *trgtpath)
{
	if (strstr(srcpath, trgtpath) == NULL) {
		return (0);
	} else {
		return (1);
	}
}
