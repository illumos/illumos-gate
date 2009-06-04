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
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pkgstrct.h>
#include <errno.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include "libadm.h"
#include "libinst.h"

extern int	holdcinfo;

#define	WRN_SCARYLINK	"WARNING: <%s>, target of symlink <%s>, does not exist."

#define	ERR_PATHLONG	"path argument too long"
#define	ERR_CLASSLONG	"classname argument too long"
#define	ERR_CLASSCHAR	"bad character in classname"
#define	ERR_STAT	"unable to stat <%s>"
#define	ERR_WRITE	"write of entry failed"
#define	ERR_POPEN	"unable to create pipe to <%s>"
#define	ERR_PCLOSE	"unable to close pipe to <%s>"
#define	ERR_RDLINK	"unable to read link for <%s>"
#define	ERR_MEMORY	"memory allocation failure, errno=%d"

#define	LINK	1

struct link {
	char	*path;
	ino_t	ino;
	dev_t	dev;
	struct link *next;
};

static struct link *firstlink = (struct link *)0;
static struct link *lastlink = (struct link *)0;
static char *scan_raw_ln(char *targ_name, char *link_name);

static char	*def_class = "none";

static int	errflg = 0;
static int	iflag = 0;	/* follow symlinks */
static int	xflag = 0;	/* confirm contents of files */
static int	nflag = 0;
static char	construction[PATH_MAX], mylocal[PATH_MAX];

static void	findlink(struct cfent *ept, char *path, char *svpath);
static void	follow(char *path);
static void	output(char *path, int n, char *local);
static void	usage(void);

int
main(int argc, char *argv[])
{
	int c;
	char *pt, path[PATH_MAX];
	char	*abi_sym_ptr;
	extern char	*optarg;
	extern int	optind;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) set_prog_name(argv[0]);

	while ((c = getopt(argc, argv, "xnic:?")) != EOF) {
		switch (c) {
		    case 'x':	/* include content info */
			xflag++;
			break;

		    case 'n':
			nflag++;
			break;

		    case 'c':	/* assign class */
			def_class = optarg;
			/* validate that classname is acceptable */
			if (strlen(def_class) > (size_t)CLSSIZ) {
				progerr(gettext(ERR_CLASSLONG));
				exit(1);
			}
			for (pt = def_class; *pt; pt++) {
				if (!isalpha(*pt) && !isdigit(*pt)) {
					progerr(gettext(ERR_CLASSCHAR));
					exit(1);
				}
			}
			break;

		    case 'i':	/* follow symlinks */
			iflag++;
			break;

		    default:
			usage();
		}
	}

	if (iflag) {
		/* follow symlinks */
		set_nonABI_symlinks();
	} else {
		/* bug id 4244631, not ABI compliant */
		abi_sym_ptr = getenv("PKG_NONABI_SYMLINKS");
		if (abi_sym_ptr && strncasecmp(abi_sym_ptr, "TRUE", 4) == 0) {
			set_nonABI_symlinks();
		}
	}
	holdcinfo = !xflag;
	if (optind == argc) {
		/* take path list from stdin */
		while (fgets(path, sizeof (path), stdin) != (char *)NULL) {
			output(path, 0, NULL);
		}
	} else {
		while (optind < argc) {
			follow(argv[optind++]);
		}
	}

	return (errflg ? 1 : 0);
}

static void
output(char *path, int n, char *local)
{
	char		mypath[PATH_MAX];
	int		len;
	int		s;
	struct cfent	entry;

	/*
	 * remove any trailing newline characters from the end of path
	 */

	len = strlen(path);
	while ((len > 0) && (path[len-1] == '\n')) {
		path[--len] = '\0';
	}

	entry.volno = 0;
	entry.ftype = '?';
	entry.path = mypath;
	(void) strlcpy(entry.pkg_class, def_class, sizeof (entry.pkg_class));
	(void) strlcpy(entry.path, path, PATH_MAX);
	entry.ainfo.local = NULL;
	entry.ainfo.mode = BADMODE;
	(void) strlcpy(entry.ainfo.owner, BADOWNER, sizeof (entry.ainfo.owner));
	(void) strlcpy(entry.ainfo.group, BADGROUP, sizeof (entry.ainfo.group));
	errflg = 0;

	if (xflag) {
		entry.ftype = '?';
		if (cverify(0, &entry.ftype, path, &entry.cinfo, 1)) {
			errflg++;
			logerr(gettext("ERROR: %s"), path);
			logerr(getErrbufAddr());
			return;
		}
	}

	/*
	 * Use averify to figure out the attributes. This has trouble
	 * divining the identity of a symlink which points to a
	 * non-existant target. For that reason, if it comes back as
	 * an existence problem, we fake in a symlink and see if averify
	 * likes that. If it does, all we have is a risky symlink.
	 */
	if ((s = averify(0, &entry.ftype, path, &entry.ainfo)) == VE_EXIST &&
	    !iflag) {
		entry.ftype = 's';	/* try again assuming symlink */
		/* try to read what it points to */
		if ((s = readlink(path, mylocal, PATH_MAX)) > 0) {
			mylocal[s] = '\000';	/* terminate it */
			entry.ainfo.local = mylocal;
			if (averify(0, &entry.ftype, path, &entry.ainfo)) {
				errflg++;
			} else
				/* It's a link to a file not in this package. */
				ptext(stderr, gettext(WRN_SCARYLINK),
				    mylocal, path);
		} else {
			errflg++;
		}
	} else if (s != 0 && s != VE_CONT)
		errflg++;

	if (errflg) {
		logerr(gettext("ERROR: %s"), path);
		logerr(getErrbufAddr());
		return;
	}

	if (n) {
		/* replace first n characters with 'local' */
		if (strchr("fev", entry.ftype)) {
			entry.ainfo.local = mylocal;
			(void) strlcpy(entry.ainfo.local, entry.path,
				PATH_MAX);
			canonize(entry.ainfo.local);
		}
		if (local[0]) {
			entry.ainfo.local = mylocal;
			(void) strlcpy(entry.path, local, PATH_MAX);
			(void) strcat(entry.path, path+n);
		} else
			(void) strlcpy(entry.path,
				(path[n] == '/') ? path+n+1 : path+n,
				PATH_MAX);
	}

	canonize(entry.path);
	if (entry.path[0]) {
		findlink(&entry, path, entry.path);
		if (strchr("dcbp", entry.ftype) ||
		(nflag && !strchr("sl", entry.ftype)))
			entry.ainfo.local = NULL;
		if (ppkgmap(&entry, stdout)) {
			progerr(gettext(ERR_WRITE));
			exit(99);
		}
	}
}

static void
follow(char *path)
{
	struct stat stbuf;
	FILE	*pp;
	char	*pt,
		local[PATH_MAX],
		newpath[PATH_MAX],
		cmd[PATH_MAX+32];
	int n;

	errflg = 0;

	if (pt = strchr(path, '=')) {
		*pt++ = '\0';
		n = ((unsigned int)pt - (unsigned int)path - 1);
		if (n >= PATH_MAX) {
			progerr(gettext(ERR_PATHLONG));
			errflg++;
			return;
		}

		n = strlen(pt);

		if (n < PATH_MAX) {
			(void) strlcpy(local, pt, sizeof (local));
			n = strlen(path);
		} else {
			progerr(gettext(ERR_PATHLONG));
			errflg++;
			return;
		}
	} else {
		n = 0;
		local[0] = '\0';
	}

	if (stat(path, &stbuf)) {
		progerr(gettext(ERR_STAT), path);
		errflg++;
		return;
	}

	if (stbuf.st_mode & S_IFDIR) {
		(void) snprintf(cmd, sizeof (cmd), "find %s -print", path);
		if ((pp = popen(cmd, "r")) == NULL) {
			progerr(gettext(ERR_POPEN), cmd);
			exit(1);
		}
		while (fscanf(pp, "%[^\n]\n", newpath) == 1)
			output(newpath, n, local);
		if (pclose(pp)) {
			progerr(gettext(ERR_PCLOSE), cmd);
			errflg++;
		}
	} else
		output(path, n, local);
}

/*
 * Scan a raw link for origination errors. Given
 *	targ_name = hlink/path/file1
 *		and
 *	link_name = hlink/path/file2
 * we don't want the link to be verbatim since link_name must be relative
 * to it's source. This functions checks for identical directory paths
 * and if it's clearly a misplaced relative path, the duplicate
 * directories are stripped. This is necessary because pkgadd is actually
 * in the source directory (hlink/path) when it creates the link.
 *
 * NOTE : The buffer we get with targ_name is going to be used later
 * and cannot be modified. That's why we have yet another PATH_MAX
 * size buffer in this function.
 */
static char *
scan_raw_ln(char *targ_name, char *link_name)
{
	char *const_ptr;	/* what we return */
	char *file_name;	/* name of the file in link_name */
	char *this_dir;		/* current directory in targ_name */
	char *next_dir;		/* next directory in targ_name  */
	char *targ_ptr;		/* current character in targ_name */

	const_ptr = targ_name;	/* Point to here 'til we know it's different. */

	/*
	 * If the link is absolute or it is in the current directory, no
	 * further testing necessary.
	 */
	if (RELATIVE(targ_name) &&
	    (file_name = strrchr(link_name, '/')) != NULL) {

		/*
		 * This will be walked down to the highest directory
		 * not common to both the link and the target.
		 */
		targ_ptr = targ_name;

		/*
		 * At this point targ_name is a relative path through at
		 * least one directory.
		 */
		this_dir = targ_ptr;	/* first directory in targ_name */
		file_name++;		/* point to the name not the '/' */

		/*
		 * Scan across the pathname until we reach a different
		 * directory or the final file name.
		 */
		do {
			size_t str_size;

			next_dir = strchr(targ_ptr, '/');
			if (next_dir)
				next_dir++;	/* point to name not '/' */
			else	/* point to the end of the string */
				next_dir = targ_ptr+strlen(targ_ptr);

			/* length to compare */
			str_size = ((ptrdiff_t)next_dir - (ptrdiff_t)this_dir);

			/*
			 * If both paths begin with the same directory, then
			 * skip that common directory in both the link and
			 * the target.
			 */
			if (strncmp(this_dir, link_name, str_size) == 0) {
				/* point to the target so far */
				const_ptr = this_dir = next_dir;
				/* Skip past it in the target */
				targ_ptr = (char *)(targ_ptr+str_size);
				/* Skip past it in the link */
				link_name = (char *)(link_name+str_size);
			/*
			 * If these directories don't match then the
			 * directory above is the lowest common directory. We
			 * need to construct a relative path from the lowest
			 * child up to that directory.
			 */
			} else {
				int d = 0;
				char *dptr = link_name;

				/* Count the intermediate directories. */
				while ((dptr = strchr(dptr, '/')) != NULL) {
					dptr++;
					d++;
				}
				/*
				 * Now targ_ptr is pointing to the fork in
				 * the path and dptr is pointing to the lowest
				 * child in the link. We now insert the
				 * appropriate number of "../'s" to get to
				 * the first common directory. We'll
				 * construct this in the construction
				 * buffer.
				 */
				if (d) {
					char *tptr;

					const_ptr = tptr = construction;
					while (d--) {
						(void) strlcpy(tptr,
							"../", PATH_MAX);
						tptr += 3;
					}
					(void) strlcpy(tptr, targ_ptr,
						PATH_MAX);
				}
				break;		/* done */
			}
		} while (link_name != file_name);	/* at file name */
	}

	return (const_ptr);
}

static void
findlink(struct cfent *ept, char *path, char *svpath)
{
	struct stat	statbuf;
	struct link	*link, *new;
	char		buf[PATH_MAX];
	int		n;

	if (lstat(path, &statbuf)) {
		progerr(gettext(ERR_STAT), path);
		errflg++;
	}
	if ((statbuf.st_mode & S_IFMT) == S_IFLNK) {
		if (!iflag) {
			ept->ainfo.local = mylocal;
			ept->ftype = 's';
			n = readlink(path, buf, PATH_MAX);
			if (n <= 0) {
				progerr(gettext(ERR_RDLINK), path);
				errflg++;
				(void) strlcpy(ept->ainfo.local,
					"unknown", PATH_MAX);
			} else {
				(void) strncpy(ept->ainfo.local, buf, n);
				ept->ainfo.local[n] = '\0';
			}
		}
		return;
	}

	if (stat(path, &statbuf))
		return;
	if (statbuf.st_nlink <= 1)
		return;

	for (link = firstlink; link; link = link->next) {
		if ((statbuf.st_ino == link->ino) &&
		(statbuf.st_dev == link->dev)) {
			ept->ftype = 'l';
			ept->ainfo.local = mylocal;
			(void) strlcpy(ept->ainfo.local,
					scan_raw_ln(link->path, ept->path),
					PATH_MAX);
			return;
		}
	}
	if ((new = (struct link *)calloc(1, sizeof (struct link))) == NULL) {
		progerr(gettext(ERR_MEMORY), errno);
		exit(1);
	}

	if (firstlink) {
		lastlink->next = new;
		lastlink = new;
	} else
		firstlink = lastlink = new;

	new->path = strdup(svpath);
	new->ino = statbuf.st_ino;
	new->dev = statbuf.st_dev;
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: %s [-i] [-c class] [path ...]\n"), get_prog_name());
	exit(1);
	/*NOTREACHED*/
}
