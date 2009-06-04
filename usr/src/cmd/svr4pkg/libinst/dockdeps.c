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
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include "libinst.h"
#include "libadm.h"
#include "messages.h"

#define	LSIZE	256
#define	NVERS	50

/*
 * internal global variables
 */

static struct pkginfo info;

static char	type;
static char	*alist[NVERS];
static char	*rmpkginst;
static char	*vlist[NVERS];
static char	file[128];
static char	name[128];
static char	rmpkg[PKGSIZ+1];
static char	wabbrev[128];

static int	errflg = 0;
static int	nlist;
static int	pkgexist;
static int	pkgokay;
static int	is_update;
static int	is_patch_update;

/*
 * IMPORTANT NOTE: THE SIZE OF 'abbrev' IS HARD CODED INTO THE CHARACTER
 * ARRAY SSCANF_FORMAT -- YOU MUST UPDATE BOTH VALUES AT THE SAME TIME!!
 */

static char	abbrev[128+1];
static char	*SSCANF_FORMAT = "%c %128s %[^\n]";

/*
 * forward declarations
 */

static void	ckrdeps(boolean_t a_preinstallCheck);
static void	ckpreq(FILE *fp, char *dname, boolean_t a_preinstallCheck);
static void	deponme(char *pkginst, char *pkgname,
				boolean_t a_preinstallCheck);
static void	prereq(char *pkginst, char *pkgname,
				boolean_t a_preinstallCheck);
static void	incompat(char *pkginst, char *pkgname,
				boolean_t a_preinstallCheck);
static int	getline(FILE *fp);

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

int
dockdeps(char *a_depfile, int a_removeFlag, boolean_t a_preinstallCheck)
{
	FILE	*fp;
	int	i;
	char	*inst;

	if (a_removeFlag) {
		/* check removal dependencies */
		rmpkginst = a_depfile;
		(void) strncpy(rmpkg, rmpkginst, PKGSIZ);
		(void) strtok(rmpkg, ".");
		(void) snprintf(file, sizeof (file),
				"%s/%s/%s", pkgdir, rmpkginst, DEPEND_FILE);
		if ((fp = fopen(file, "r")) == NULL)
			goto done;
	} else {
		if ((fp = fopen(a_depfile, "r")) == NULL) {
			progerr(ERR_CANNOT_OPEN_DEPEND_FILE, a_depfile,
					strerror(errno));
			quit(99);
		}
	}

	while (getline(fp)) {
		switch (type) {
		    case 'I':
		    case 'P':
			if (a_removeFlag) {
				continue;
			}
			break;

		    case 'R':
			if (!a_removeFlag) {
				continue;
			}
			break;

		    default:
			errflg++;
			progerr(ERR_UNKNOWN_DEPENDENCY, type);
			break;
		}

		/* check to see if any versions listed are installed */
		pkgexist = pkgokay = 0;
		i = 0;
		if (strchr(abbrev, '.')) {
			progerr(ERR_PKGABRV, abbrev);
		}
		(void) snprintf(wabbrev, sizeof (wabbrev), "%s.*", abbrev);

		do {
			inst = fpkginst(wabbrev, alist[i], vlist[i]);
			if (inst && (pkginfo(&info, inst, NULL, NULL) == 0)) {
				pkgexist++;
				if ((info.status == PI_INSTALLED) ||
				    (info.status == PI_PRESVR4))
					pkgokay++;
			}
		} while (++i < nlist);
		(void) fpkginst(NULL); 	/* force closing/rewind of files */

		if (!info.name) {
			info.name = name;
		}

		switch (type) {
		    case 'I':
			incompat(abbrev, info.name, a_preinstallCheck);
			break;

		    case 'P':
			prereq(abbrev, name, a_preinstallCheck);
			break;

		    case 'R':
			deponme(abbrev, info.name, a_preinstallCheck);
		}
	}
	(void) fclose(fp);

done:
	if (a_removeFlag) {
		ckrdeps(a_preinstallCheck);
	}

	return (errflg);
}

void
setPatchUpdate(void)
{
	is_patch_update = 1;
}

int
isPatchUpdate(void)
{
	return ((is_patch_update) ? 1 : 0);
}

void
setUpdate(void)
{
	is_update = 1;
}

int
isUpdate(void)
{
	return ((is_update) ? 1 : 0);
}

/*
 * *****************************************************************************
 * static internal (private) functions
 * *****************************************************************************
 */

static void
incompat(char *pkginst, char *pkgname, boolean_t a_preinstallCheck)
{
	char buf[512];

	if (!pkgexist)
		return;

	errflg++;
	if (a_preinstallCheck == B_TRUE) {
		(void) fprintf(stdout, "incompat=%s\n", pkginst);
		return;
	}

	logerr(ERR_WARNING);
	(void) snprintf(buf, sizeof (buf), ERR_INCOMP_VERS, pkginst, pkgname);
	puttext(stderr, buf, 4, 0);
	(void) putc('\n', stderr);
}

static void
prereq(char *pkginst, char *pkgname, boolean_t a_preinstallCheck)
{
	register int i;
	char buf[512];

	if (pkgokay) {
		return;
	}

	errflg++;

	if (a_preinstallCheck == B_TRUE) {
		if (pkgexist) {
			(void) fprintf(stdout,
				"prerequisite-incomplete=%s\n", pkginst);
		} else {
			(void) fprintf(stdout,
				"prerequisite-installed=%s\n", pkginst);
		}
		return;
	}

	logerr(ERR_WARNING);
	if (pkgexist) {
		(void) snprintf(buf, sizeof (buf), ERR_PRENCI, pkginst,
					pkgname);
		puttext(stderr, buf, 4, 0);
		(void) putc('\n', stderr);
	} else {
		(void) snprintf(buf, sizeof (buf), ERR_PREREQ, pkginst,
					pkgname);
		if (nlist) {
			(void) strcat(buf, ERR_VALINST);
		}
		puttext(stderr, buf, 4, 0);
		(void) putc('\n', stderr);
		for (i = 0; i < nlist; i++) {
			(void) printf("          ");
			if (alist[i])
				(void) printf("(%s) ", alist[i]);
			if (vlist[i])
				(void) printf("%s", vlist[i]);
			(void) printf("\n");
		}
	}
}

static void
deponme(char *pkginst, char *pkgname, boolean_t a_preinstallCheck)
{
	char buf[512];

	if (!pkgexist)
		return;

	errflg++;

	if (a_preinstallCheck == B_TRUE) {
		if (!pkgname || !pkgname[0]) {
			(void) snprintf(buf, sizeof (buf),
					"dependonme=%s", pkginst);
		} else {
			(void) snprintf(buf, sizeof (buf),
				"dependsonme=%s:%s", pkginst, pkgname);
		}
		(void) fprintf(stdout, "%s\n", buf);
		return;
	}

	logerr(ERR_WARNING);
	if (!pkgname || !pkgname[0]) {
		(void) snprintf(buf, sizeof (buf), ERR_DEPONME, pkginst);
	} else {
		(void) snprintf(buf, sizeof (buf), ERR_DEPNAM, pkginst,
				pkgname);
	}
	puttext(stderr, buf, 4, 0);
	(void) putc('\n', stderr);
}

static int
getline(FILE *fp)
{
	register int i, c, found;
	char *pt, *new, line[LSIZE];

	abbrev[0] = name[0] = type = '\0';

	for (i = 0; i < nlist; i++) {
		if (alist[i]) {
			free(alist[i]);
			alist[i] = NULL;
		}
		if (vlist[i]) {
			free(vlist[i]);
			vlist[i] = NULL;
		}
	}
	alist[0] = vlist[0] = NULL;

	found = (-1);
	nlist = 0;
	while ((c = getc(fp)) != EOF) {
		(void) ungetc(c, fp);
		if ((found >= 0) && !isspace(c))
			return (1);

		if (!fgets(line, LSIZE, fp))
			break;

		for (pt = line; isspace(*pt); /* void */)
			pt++;
		if (!*pt || (*pt == '#'))
			continue;

		if (pt == line) {
			/* begin new definition */
			/* LINTED variable format specifier to sscanf(): */
			(void) sscanf(line, SSCANF_FORMAT, &type, abbrev, name);
			found++;
			continue;
		}
		if (found < 0)
			return (0);

		if (*pt == '(') {
			/* architecture is specified */
			if (new = strchr(pt, ')'))
				*new++ = '\0';
			else
				return (-1); /* bad specification */
			alist[found] = qstrdup(pt+1);
			pt = new;
		}
		while (isspace(*pt))
			pt++;
		if (*pt) {
			vlist[found] = qstrdup(pt);
			if (pt = strchr(vlist[found], '\n'))
				*pt = '\0';
		}
		found++;
		nlist++;
	}
	return ((found >= 0) ? 1 : 0);
}

static void
ckrdeps(boolean_t a_preinstallCheck)
{
	struct dirent *drp;
	DIR	*dirfp;
	FILE	*fp;
	char	depfile[PATH_MAX+1];

	if ((dirfp = opendir(pkgdir)) == NULL)
		return;

	while ((drp = readdir(dirfp)) != NULL) {
		if (drp->d_name[0] == '.')
			continue;

		if (strcmp(drp->d_name, rmpkginst) == 0)
			continue; /* others don't include me */
		(void) snprintf(depfile, sizeof (depfile),
				"%s/%s/%s", pkgdir, drp->d_name, DEPEND_FILE);
		if ((fp = fopen(depfile, "r")) == NULL)
			continue;

		ckpreq(fp, drp->d_name, a_preinstallCheck);
	}
	(void) closedir(dirfp);
}

static void
ckpreq(FILE *fp, char *dname, boolean_t a_preinstallCheck)
{
	register int i;
	char	*inst;

	while (getline(fp)) {
		if (type != 'P')
			continue;

		if (strcmp(abbrev, rmpkg))
			continue;

		/* see if package is installed */
		i = 0;
		if (strchr(abbrev, '.') == 0) {
			(void) strcat(abbrev, ".*");
		}
		pkgexist = 1;

		do {
			if (inst = fpkginst(abbrev, alist[i], vlist[i])) {
				if (strcmp(inst, rmpkginst) == 0) {
					deponme(dname, "", a_preinstallCheck);
					(void) fclose(fp);
					(void) fpkginst(NULL);
					return;
				}
			}
		} while (++i < nlist);
		(void) fpkginst(NULL);
	}
	(void) fclose(fp);
}
