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
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include <locale.h>
#include <libintl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pkglib.h>
#include <install.h>
#include <libadm.h>
#include <libinst.h>

extern char	*basedir, *root, *rootlist[], **environ;

/*
 * IMPORTANT NOTE: PLEASE SEE THE DEFINITION OF temp[] BELOW BEFORE
 * CHANGING THE DEFINITION OF PATH_LGTH!!!!
 */

#define	PATH_LGTH 4096

#define	MAXPARAMS 256
#define	NRECURS 20

#define	MSG_BPARAMC	"parametric class specification for <%s> not allowed"
#define	MSG_SRCHLOC	"no object for <%s> found in local path"
#define	MSG_SRCHSRCH	"no object for <%s> found in search path"
#define	MSG_SRCHROOT	"no object for <%s> found in root directory"
#define	MSG_CONTENTS	"unable to process contents of object <%s>"
#define	MSG_WRITE	"write of entry failed, errno=%d"
#define	MSG_GARBDEFLT	"garbled default settings: %s"
#define	MSG_BANG	"unknown directive: %s"
#define	MSG_CHDIR	"unable to change directory to <%s>"
#define	MSG_INCOMPLETE	"processing of <%s> may be incomplete"
#define	MSG_NRECURS	"too many levels of include (limit is %d)"
#define	MSG_RDINCLUDE	"unable to process include file <%s>, errno=%d"
#define	MSG_IGNINCLUDE	"ignoring include file <%s>"
#define	MSG_NODEVICE	"device numbers cannot be determined for <%s>"

#define	WRN_BADATTR	"WARNING: attributes set to %04o %s %s for <%s>"
#define	WRN_BADATTRM	"WARNING: attributes set to %s %s %s for <%s>"
#define	WRN_FAKEBD	"WARNING: parametric paths may ignore BASEDIR"

#define	ERR_TEMP	"unable to obtain temporary file resources, errno=%d"
#define	ERR_ENVBUILD	"unable to build parameter environment, errno=%d"
#define	ERR_MAXPARAMS	"too many parameter definitions (limit is %d)"
#define	ERR_GETCWD	"unable to get current directory, errno=%d"
#define	ERR_PATHVAR	"cannot resolve all build parameters associated with " \
			    "path <%s>."

static struct cfent entry;
static FILE	*fp,
		*sfp[20];
static char	*dname[NRECURS],
		*params[256],
		*proto[NRECURS],
		*rootp[NRECURS][16],
		*srchp[NRECURS][16],
		*d_own[NRECURS],
		*d_grp[NRECURS],
		*rdonly[256];
static mode_t	d_mod[NRECURS];
static int	nfp = (-1);
static int	nrdonly = 0;
static int	errflg = 0;
static char	*separ = " \t\n, ";

/* libpkg/gpkgmap.c */
extern void	attrpreset(int mode, char *owner, char *group);
extern void	attrdefault();
static char	*findfile(char *path, char *local);
static char	*srchroot(char *path, char *copy);

static int	popenv(void);

static int	doattrib(void);
static void	doinclude(void);
static void	dorsearch(void);
static void	dosearch(void);
static void	error(int flag);
static void	lputenv(char *s);
static void	pushenv(char *file);
static void	translate(register char *pt, register char *copy);

int
mkpkgmap(char *outfile, char *protofile, char **envparam)
{
	FILE	*tmpfp;
	char	*pt, *path, mybuff[PATH_LGTH];
	char	**envsave;
	int	c, fakebasedir;
	int	i, n;

	/*
	 * NOTE: THE SIZE OF temp IS HARD CODED INTO CALLS TO fscanf.
	 * YOU *MUST* MAKE SURE TO CHANGE THOSE CALLS IF THE SIZE OF temp
	 * IS EVER CHANGED!!!!!!
	 */
	char	temp[PATH_LGTH];

	if ((tmpfp = fopen(outfile, "w")) == NULL) {
		progerr(gettext(ERR_TEMP), errno);
		quit(99);
	}
	envsave = environ;
	environ = params; /* use only local environ */
	attrdefault();	/* assume no default attributes */

	/*
	 * Environment parameters are optional, so variable
	 * (envparam[i]) could be NULL.
	 */
	for (i = 0; (envparam[i] != NULL) &&
	    (pt = strchr(envparam[i], '=')); i++) {
		*pt = '\0';
		rdonly[nrdonly++] = qstrdup(envparam[i]);
		*pt = '=';
		if (putenv(qstrdup(envparam[i]))) { /* bugid 1090920 */
			progerr(gettext(ERR_ENVBUILD), errno);
			quit(99);
		}
		if (nrdonly >= MAXPARAMS) {
			progerr(gettext(ERR_MAXPARAMS), MAXPARAMS);
			quit(1);
		}
	}

	pushenv(protofile);
	errflg = 0;
again:
	fakebasedir = 0;
	while (!feof(fp)) {
		c = getc(fp);
		while (isspace(c))
			c = getc(fp);

		if (c == '#') {
			do c = getc(fp); while ((c != EOF) && (c != '\n'));
			continue;
		}
		if (c == EOF)
			break;

		if (c == '!') {
			/*
			 * IMPORTANT NOTE: THE SIZE OF temp IS HARD CODED INTO
			 * the FOLLOWING CALL TO fscanf -- YOU MUST CHANGE THIS
			 * LINE IF THE SIZE OF fscanf IS EVER CHANGED!!!
			 */
			(void) fscanf(fp, "%4096s", temp);

			if (strcmp(temp, "include") == 0)
				doinclude();
			else if (strcmp(temp, "rsearch") == 0)
				dorsearch();
			else if (strcmp(temp, "search") == 0)
				dosearch();
			else if (strcmp(temp, "default") == 0) {
				if (doattrib())
					break;
			} else if (strchr(temp, '=')) {
				translate(temp, mybuff);
				/* put this into the local environment */
				lputenv(mybuff);
				(void) fscanf(fp, "%*[^\n]"); /* rest of line */
				(void) fscanf(fp, "\n"); /* rest of line */
			} else {
				error(1);
				logerr(gettext(MSG_BANG), temp);
				(void) fscanf(fp, "%*[^\n]"); /* read of line */
				(void) fscanf(fp, "\n"); /* read of line */
			}
			continue;
		}
		(void) ungetc(c, fp);

		if ((n = gpkgmap(&entry, fp)) < 0) {
			char	*errstr;

			error(1);
			errstr = getErrstr();
			logerr(gettext("garbled entry"));
			logerr(gettext("- pathname: %s"),
			    (entry.path && *entry.path) ? entry.path :
			    "Unknown");
			logerr(gettext("- problem: %s"),
			    (errstr && *errstr) ? errstr : "Unknown");
			break;
		}
		if (n == 0)
			break; /* done with file */

		/* don't allow classname to be parametric */
		if (entry.ftype != 'i') {
			if (entry.pkg_class[0] == '$') {
				error(1);
				logerr(gettext(MSG_BPARAMC), entry.path);
			}
		}

		if (strchr("dxlscbp", entry.ftype)) {
			/*
			 * We don't need to search for things without any
			 * contents in them.
			 */
			if (strchr("cb", entry.ftype)) {
				if (entry.ainfo.major == BADMAJOR ||
				    entry.ainfo.minor == BADMINOR) {
					error(1);
					logerr(gettext(MSG_NODEVICE),
					    entry.path);
				}
			}
			path = NULL;
		} else {
			path = findfile(entry.path, entry.ainfo.local);
			if (!path)
				continue;

			entry.ainfo.local = path;
			if (strchr("fevin?", entry.ftype)) {
				if (cverify(0, &entry.ftype, path,
				    &entry.cinfo, 1)) {
					error(1);
					logerr(gettext(MSG_CONTENTS), path);
				}
			}
		}

		/* Warn if attributes are not set correctly. */
		if (!strchr("isl", entry.ftype)) {
			int dowarning = 0;
			int hasbadmode = 0;

			if (entry.ainfo.mode == NOMODE) {
				entry.ainfo.mode = CURMODE;
				dowarning = 1;
				hasbadmode = 1;
			}

			if (strcmp(entry.ainfo.owner, NOOWNER) == 0) {
				(void) strlcpy(entry.ainfo.owner, CUROWNER,
						sizeof (entry.ainfo.owner));
				dowarning = 1;
			}

			if (strcmp(entry.ainfo.group, NOGROUP) == 0) {
				(void) strlcpy(entry.ainfo.group, CURGROUP,
						sizeof (entry.ainfo.group));
				dowarning = 1;
			}


			if (dowarning) {
				if (hasbadmode)
					logerr(gettext(WRN_BADATTRM),
						"?",
					    entry.ainfo.owner,
					    entry.ainfo.group,
					    entry.path);
				else
					logerr(gettext(WRN_BADATTR),
						(int)entry.ainfo.mode,
						entry.ainfo.owner,
						entry.ainfo.group,
						entry.path);
			}
		}

		/*
		 * Resolve build parameters (initial lower case) in
		 * the link and target paths.
		 */
		if (strchr("ls", entry.ftype)) {
			if (!RELATIVE(entry.ainfo.local) ||
					PARAMETRIC(entry.ainfo.local)) {
				if (mappath(1, entry.ainfo.local)) {
					error(1);
					logerr(gettext(ERR_PATHVAR),
					    entry.ainfo.local);
					break;
				}

				canonize(entry.ainfo.local);
			}
		}

		/*
		 * Warn if top level file or directory is an install
		 * parameter
		 */
		if (entry.ftype != 'i') {
			if (entry.path[0] == '$' && isupper(entry.path[1]))
				fakebasedir = 1;
		}

		if (mappath(1, entry.path)) {
			error(1);
			logerr(gettext(ERR_PATHVAR), entry.path);
			break;
		}

		canonize(entry.path);
		if (ppkgmap(&entry, tmpfp)) {
			error(1);
			logerr(gettext(MSG_WRITE), errno);
			break;
		}
	}

	if (fakebasedir) {
		logerr(gettext(WRN_FAKEBD));
		fakebasedir = 0;
	}

	if (popenv())
		goto again;

	(void) fclose(tmpfp);
	environ = envsave; /* restore environment */

	return (errflg ? 1 : 0);
}

static char *
findfile(char *path, char *local)
{
	struct stat statbuf;
	static char host[PATH_MAX];
	register char *pt;
	char	temp[PATH_MAX], *basename;
	int	i;

	/*
	 * map any parameters specified in path to their corresponding values
	 * and make sure the path is in its canonical form; any parmeters for
	 * which a value is not defined will be left unexpanded. Since this
	 * is an actual search for a real file (which will not end up in the
	 * package) - we map ALL variables (both build and Install).
	 */
	(void) strlcpy(temp, (local && local[0] ? local : path), sizeof (temp));
	mappath(0, temp);
	canonize(temp);

	*host = '\0';
	if (rootlist[0] || (basedir && (*temp != '/'))) {
		/*
		 * search for path in the pseudo-root/basedir directory; note
		 * that package information files should NOT be included in
		 * this list
		 */
		if (entry.ftype != 'i')
			return (srchroot(temp, host));
	}

	/* looking for local object file  */
	if (local && *local) {
		basepath(temp, dname[nfp], NULL);
		/*
		 * If it equals "/dev/null", that just means it's an empty
		 * file. Otherwise, we'll really be writing stuff, so we need
		 * to verify the source.
		 */
		if (strcmp(temp, "/dev/null") != 0) {
			if (stat(temp, &statbuf) ||
			    !(statbuf.st_mode & S_IFREG)) {
				error(1);
				logerr(gettext(MSG_SRCHLOC), path);
				return (NULL);
			}
		}
		(void) strlcpy(host, temp, sizeof (host));
		return (host);
	}

	for (i = 0; rootp[nfp][i]; i++) {
		(void) snprintf(host, sizeof (host), "%s/%s", rootp[nfp][i],
		    temp + (*temp == '/' ? 1 : 0));
		if ((stat(host, &statbuf) == 0) &&
		    (statbuf.st_mode & S_IFREG)) {
			return (host);
		}
	}

	pt = strrchr(temp, '/');
	if (!pt++)
		pt = temp;

	basename = pt;

	for (i = 0; srchp[nfp][i]; i++) {
		(void) snprintf(host, sizeof (host), "%s/%s",
			srchp[nfp][i], basename);
		if ((stat(host, &statbuf) == 0) &&
		    (statbuf.st_mode & S_IFREG)) {
			return (host);
		}
	}

	/* check current directory as a last resort */
	(void) snprintf(host, sizeof (host), "%s/%s", dname[nfp], basename);
	if ((stat(host, &statbuf) == 0) && (statbuf.st_mode & S_IFREG))
		return (host);

	error(1);
	logerr(gettext(MSG_SRCHSRCH), path);
	return (NULL);
}

static void
dosearch(void)
{
	char temp[PATH_MAX], lookpath[PATH_MAX], *pt;
	int n;

	(void) fgets(temp, PATH_MAX, fp);
	translate(temp, lookpath);

	for (n = 0; srchp[nfp][n]; n++)
		free(srchp[nfp][n]);

	n = 0;
	pt = strtok(lookpath, separ);
	if (pt && *pt) {
		do {
			if (*pt != '/') {
				/* make relative path an absolute directory */
				(void) snprintf(temp, sizeof (temp),
						"%s/%s", dname[nfp], pt);
				pt = temp;
			}
			canonize(pt);
			srchp[nfp][n++] = qstrdup(pt);
		} while (pt = strtok(NULL, separ));
		srchp[nfp][n] = NULL;
	}
}

static void
dorsearch(void)
{
	char temp[PATH_MAX], lookpath[PATH_MAX], *pt;
	int n;

	(void) fgets(temp, PATH_MAX, fp);
	translate(temp, lookpath);

	for (n = 0; rootp[nfp][n]; n++)
		free(rootp[nfp][n]);

	n = 0;
	pt = strtok(lookpath, separ);
	do {
		if (*pt != '/') {
			/* make relative path an absolute directory */
			(void) snprintf(temp, sizeof (temp),
					"%s/%s", dname[nfp], pt);
			pt = temp;
		}
		canonize(pt);
		rootp[nfp][n++] = qstrdup(pt);
	} while (pt = strtok(NULL, separ));
	rootp[nfp][n] = NULL;
}

/*
 * This function reads the default mode, owner and group from the prototype
 * file and makes that available.
 */
static int
doattrib(void)
{
	char *pt, attrib[PATH_MAX], *mode_ptr, *owner_ptr, *group_ptr, *eol;
	int mode;
	char owner[ATRSIZ+1], group[ATRSIZ+1], attrib_save[(4*ATRSIZ)];

	(void) fgets(attrib, PATH_MAX, fp);

	(void) strlcpy(attrib_save, attrib, sizeof (attrib_save));

	/*
	 * Now resolve any variables that may be present. Start on group and
	 * move backward since that keeps the resolved string from
	 * overwriting any of the other entries. This is required since
	 * mapvar() writes the resolved string over the string provided.
	 */
	mode_ptr = strtok(attrib, " \t");
	owner_ptr = strtok(NULL, " \t");
	group_ptr = strtok(NULL, " \t\n");
	eol = strtok(NULL, " \t\n");
	if (strtok(NULL, " \t\n")) {
		/* extra tokens on the line */
		error(1);
		logerr(gettext(MSG_GARBDEFLT), (eol) ? eol :
		    gettext("unreadable at end of line"));
		return (1);
	}

	if (group_ptr && mapvar(1, group_ptr) == 0)
		(void) strncpy(group, group_ptr, ATRSIZ);
	else {
		error(1);
		logerr(gettext(MSG_GARBDEFLT), (attrib_save) ?
		    ((attrib_save[0]) ? attrib_save : gettext("none")) :
		    gettext("unreadable at group"));
		return (1);
	}

	if (owner_ptr && mapvar(1, owner_ptr) == 0)
		(void) strncpy(owner, owner_ptr, ATRSIZ);
	else {
		error(1);
		logerr(gettext(MSG_GARBDEFLT), (attrib_save) ?
		    ((attrib_save[0]) ? attrib_save : gettext("none")) :
		    gettext("unreadable at owner"));
		return (1);
	}

	/*
	 * For mode, don't use scanf, since we want to force an octal
	 * interpretation and need to limit the length of the owner and group
	 * specifications.
	 */
	if (mode_ptr && mapvar(1, mode_ptr) == 0)
		mode = strtol(mode_ptr, &pt, 8);
	else {
		error(1);
		logerr(gettext(MSG_GARBDEFLT), (attrib_save) ?
		    ((attrib_save[0]) ? attrib_save : gettext("none")) :
		    gettext("unreadable at mode"));
		return (1);
	}

	/* free any previous memory from qstrdup */
	if (d_own[nfp])
		free(d_own[nfp]);
	if (d_grp[nfp])
		free(d_grp[nfp]);

	d_mod[nfp] = mode;
	d_own[nfp] = qstrdup(owner);
	d_grp[nfp] = qstrdup(group);

	attrpreset(d_mod[nfp], d_own[nfp], d_grp[nfp]);

	return (0);
}

static void
doinclude(void)
{
	char	file[PATH_MAX];
	char	temp[PATH_MAX];

	(void) fgets(temp, PATH_MAX, fp);

	/*
	 * IMPORTANT NOTE: THE SIZE OF temp IS HARD CODED INTO THE
	 * FOLLOWING CALL TO fscanf -- YOU MUST CHANGE THIS LINE IF
	 * THE SIZE OF fscanf IS EVER CHANGED!!!
	 */
	(void) sscanf(temp, "%1024s", file);

	translate(file, temp);
	canonize(temp);

	if (*temp == '\0')
		return;
	else if (*temp != '/')
		(void) snprintf(file, sizeof (file), "%s/%s", dname[nfp], temp);
	else
		(void) strlcpy(file, temp, sizeof (file));

	canonize(file);
	pushenv(file);
}

/*
 * This does what mappath() does except that it does it for ALL variables
 * using whitespace as a token separator. This is used to resolve search
 * paths and assignment statements. It doesn't effect the build versus
 * install decision made for pkgmap variables.
 */
static void
translate(register char *pt, register char *copy)
{
	char *pt2, varname[MAX_PKG_PARAM_LENGTH];

token:
	/* eat white space */
	while (isspace(*pt))
		pt++;
	while (*pt && !isspace(*pt)) {
		if (*pt == '$') {
			pt2 = varname;
			while (*++pt && !strchr("/= \t\n\r", *pt))
				*pt2++ = *pt;
			*pt2 = '\0';
			if (pt2 = getenv(varname)) {
				while (*pt2)
					*copy++ = *pt2++;
			}
		} else
			*copy++ = *pt++;
	}
	if (*pt) {
		*copy++ = ' ';
		goto token;
	}
	*copy = '\0';
}

static void
error(int flag)
{
	static char *lasterr = NULL;

	if (lasterr != proto[nfp]) {
		lasterr = proto[nfp];
		(void) fprintf(stderr, gettext("ERROR in %s:\n"), lasterr);
	}
	if (flag)
		errflg++;
}

/* Set up defaults and change to the build directory. */
static void
pushenv(char *file)
{
	register char *pt;
	static char	topdir[PATH_MAX];

	if ((nfp+1) >= NRECURS) {
		error(1);
		logerr(gettext(MSG_NRECURS), NRECURS);
		logerr(gettext(MSG_IGNINCLUDE), file);
		return;
	}

	if (strcmp(file, "-") == 0) {
		fp = stdin;
	} else if ((fp = fopen(file, "r")) == NULL) {
		error(1);
		logerr(gettext(MSG_RDINCLUDE), file, errno);
		if (nfp >= 0) {
			logerr(gettext(MSG_IGNINCLUDE), file);
			fp = sfp[nfp];
			return;
		} else
			quit(1);
	}
	sfp[++nfp] = fp;
	srchp[nfp][0] = NULL;
	rootp[nfp][0] = NULL;
	d_mod[nfp] = (mode_t)(-1);
	d_own[nfp] = NULL;
	d_grp[nfp] = NULL;

	if (!nfp) {
		/* upper level proto file */
		proto[nfp] = file;
		if (file[0] == '/')
			pt = strcpy(topdir, file);
		else {
			/* path is relative to the prototype file specified */
			pt = getcwd(NULL, PATH_MAX);
			if (pt == NULL) {
				progerr(gettext(ERR_GETCWD), errno);
				quit(99);
			}
			(void) snprintf(topdir, sizeof (topdir),
						"%s/%s", pt, file);
		}
		if (pt = strrchr(topdir, '/'))
			*pt = '\0'; /* should always happen */
		if (topdir[0] == '\0')
			(void) strlcpy(topdir, "/", sizeof (topdir));
		dname[nfp] = topdir;
	} else {
		proto[nfp] = qstrdup(file);
		dname[nfp] = qstrdup(file);
		if (pt = strrchr(dname[nfp], '/'))
			*pt = '\0';
		else {
			/* same directory as the last prototype */
			free(dname[nfp]);
			dname[nfp] = qstrdup(dname[nfp-1]);
			return; /* no need to canonize() or chdir() */
		}
	}

	canonize(dname[nfp]);

	if (chdir(dname[nfp])) {
		error(1);
		logerr(gettext(MSG_CHDIR), dname[nfp]);
		if (!nfp)
			quit(1); /* must be able to cd to upper level */
		logerr(gettext(MSG_IGNINCLUDE), proto[nfp]);
		(void) popenv();
	}
}

/* Restore defaults and return to the prior directory. */
static int
popenv(void)
{
	int i;

	(void) fclose(fp);
	if (nfp) {
		if (proto[nfp])
			free(proto[nfp]);
		if (dname[nfp])
			free(dname[nfp]);
		for (i = 0; srchp[nfp][i]; i++)
			free(srchp[nfp][i]);
		for (i = 0; rootp[nfp][i]; i++)
			free(rootp[nfp][i]);
		if (d_own[nfp])
			free(d_own[nfp]);
		if (d_grp[nfp])
			free(d_grp[nfp]);

		fp = sfp[--nfp];

		if (chdir(dname[nfp])) {
			error(1);
			logerr(gettext(MSG_CHDIR), dname[nfp]);
			logerr(gettext(MSG_INCOMPLETE), proto[nfp]);
			return (popenv());
		}
		return (1);
	}
	return (0);
}

/*
 * If this parameter isn't already in place, put it into the local
 * environment. This means that command line directives override prototype
 * file directives.
 */
static void
lputenv(char *s)
{
	char *pt;
	int i;

	pt = strchr(s, '=');
	if (!pt)
		return;

	*pt = '\0';
	for (i = 0; i < nrdonly; i++) {
		if (strcmp(rdonly[i], s) == 0) {
			*pt = '=';
			return;
		}
	}
	*pt = '=';

	if (putenv(qstrdup(s))) {
		progerr(gettext(ERR_ENVBUILD), errno);
		quit(99);
	}
}

static char *
srchroot(char *path, char *copy)
{
	struct stat statbuf;
	int i;

	i = 0;
	root = rootlist[i++];
	do {
		/* convert with root & basedir info */
		cvtpath(path, copy);
		/* make it pretty again */
		canonize(copy);

		if (stat(copy, &statbuf) || !(statbuf.st_mode & S_IFREG)) {
			root = rootlist[i++];
			continue; /* host source must be a regular file */
		}
		return (copy);
	} while (root != NULL);
	error(1);
	logerr(gettext(MSG_SRCHROOT), path);
	return (NULL);
}
