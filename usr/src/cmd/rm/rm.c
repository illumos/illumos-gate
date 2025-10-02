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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * rm [-fiRr] file ...
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <values.h>
#include "getresponse.h"

#define	DIR_CANTCLOSE		1

static struct stat rootdir;

struct dlist {
	int fd;			/* Stores directory fd */
	int flags;		/* DIR_* Flags */
	DIR *dp;		/* Open directory (opened with fd) */
	long diroff;		/* Saved directory offset when closing */
	struct dlist *up;	/* Up one step in the tree (toward "/") */
	struct dlist *down;	/* Down one step in the tree */
	ino_t ino;		/* st_ino of directory */
	dev_t dev;		/* st_dev of directory */
	int pathend;		/* Offset of name end in the pathbuffer */
};

static struct dlist top = {
	(int)AT_FDCWD,
	DIR_CANTCLOSE,
};

static struct dlist *cur, *rec;

static int rm(const char *, struct dlist *);
static int confirm(FILE *, const char *, ...);
static void memerror(void);
static int checkdir(struct dlist *, struct dlist *);
static int errcnt;
static boolean_t silent, interactive, recursive, ontty;

static char *pathbuf;
static size_t pathbuflen = MAXPATHLEN;

static int maxfds = MAXINT;
static int nfds;

int
main(int argc, char **argv)
{
	int errflg = 0;
	int c;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "frRi")) != EOF)
		switch (c) {
		case 'f':
			silent = B_TRUE;
#ifdef XPG4
			interactive = B_FALSE;
#endif
			break;
		case 'i':
			interactive = B_TRUE;
#ifdef XPG4
			silent = B_FALSE;
#endif
			break;
		case 'r':
		case 'R':
			recursive = B_TRUE;
			break;
		case '?':
			errflg = 1;
			break;
		}

	/*
	 * For BSD compatibility allow '-' to delimit the end
	 * of options.  However, if options were already explicitly
	 * terminated with '--', then treat '-' literally: otherwise,
	 * "rm -- -" won't remove '-'.
	 */
	if (optind < argc &&
	    strcmp(argv[optind], "-") == 0 &&
	    strcmp(argv[optind - 1], "--") != 0)
		optind++;

	argc -= optind;
	argv = &argv[optind];

	if ((argc < 1 && !silent) || errflg) {
		(void) fprintf(stderr, gettext("usage: rm [-fiRr] file ...\n"));
		exit(2);
	}

	ontty = isatty(STDIN_FILENO) != 0;

	if (recursive && stat("/", &rootdir) != 0) {
		(void) fprintf(stderr,
		    gettext("rm: cannot stat root directory: %s\n"),
		    strerror(errno));
		exit(2);
	}

	pathbuf = malloc(pathbuflen);
	if (pathbuf == NULL)
		memerror();

	if (init_yes() < 0) {
		(void) fprintf(stderr, gettext(ERR_MSG_INIT_YES),
		    strerror(errno));
		exit(2);
	}

	for (; *argv != NULL; argv++) {
		char *p = strrchr(*argv, '/');
		if (p == NULL)
			p = *argv;
		else
			p = p + 1;
		if (strcmp(p, ".") == 0 || strcmp(p, "..") == 0) {
			(void) fprintf(stderr,
			    gettext("rm of %s is not allowed\n"), *argv);
			errcnt++;
			continue;
		}
		/* Retry when we can't walk back up. */
		while (rm(*argv, rec = cur = &top) != 0)
			;
	}

	return (errcnt != 0 ? 2 : 0);
}

static void
pushfilename(const char *fname)
{
	char *p;
	const char *q = fname;

	if (cur == &top) {
		p = pathbuf;
	} else {
		p = pathbuf + cur->up->pathend;
		*p++ = '/';
	}
	while (*q != '\0') {
		if (p - pathbuf + 2 >= pathbuflen) {
			char *np;
			pathbuflen += MAXPATHLEN;
			np = realloc(pathbuf, pathbuflen);
			if (np == NULL)
				memerror();
			p = np + (p - pathbuf);
			pathbuf = np;
		}
		*p++ = *q++;
	}
	*p = '\0';
	cur->pathend = p - pathbuf;
}

static void
closeframe(struct dlist *frm)
{
	if (frm->dp != NULL) {
		(void) closedir(frm->dp);
		nfds--;
		frm->dp = NULL;
		frm->fd = -1;
	}
}

static int
reclaim(void)
{
	while (rec != NULL && (rec->flags & DIR_CANTCLOSE) != 0)
		rec = rec->down;
	if (rec == NULL || rec == cur || rec->dp == NULL)
		return (-1);
	rec->diroff = telldir(rec->dp);
	closeframe(rec);
	rec = rec->down;
	return (0);
}

static void
pushdir(struct dlist *frm)
{
	frm->up = cur;
	frm->down = NULL;
	cur->down = frm;
	cur = frm;
}

static int
opendirat(int dirfd, const char *entry, struct dlist *frm)
{
	int fd;

	if (nfds >= maxfds)
		(void) reclaim();

	while ((fd = openat(dirfd, entry, O_RDONLY|O_NONBLOCK)) == -1 &&
	    errno == EMFILE) {
		if (nfds < maxfds)
			maxfds = nfds;
		if (reclaim() != 0)
			return (-1);
	}
	if (fd < 0)
		return (-1);
	frm->fd = fd;
	frm->dp = fdopendir(fd);
	if (frm->dp == NULL) {
		(void) close(fd);
		return (-1);
	}
	nfds++;
	return (0);
}

/*
 * Since we never pop the top frame, cur->up can never be NULL.
 * If we pop beyond a frame we closed, we try to reopen "..".
 */
static int
popdir(boolean_t noerror)
{
	struct stat buf;
	int ret = noerror ? 0 : -1;
	pathbuf[cur->up->pathend] = '\0';

	if (noerror && cur->up->fd == -1) {
		rec = cur->up;
		if (opendirat(cur->fd, "..", rec) != 0 ||
		    fstat(rec->fd, &buf) != 0) {
			(void) fprintf(stderr,
			    gettext("rm: cannot reopen %s: %s\n"),
			    pathbuf, strerror(errno));
			exit(2);
		}
		if (rec->ino != buf.st_ino || rec->dev != buf.st_dev) {
			(void) fprintf(stderr, gettext("rm: WARNING: "
			    "The directory %s was moved or linked to "
			    "another directory during the execution of rm\n"),
			    pathbuf);
			closeframe(rec);
			ret = -1;
		} else {
			/* If telldir failed, we take it from the top. */
			if (rec->diroff != -1)
				seekdir(rec->dp, rec->diroff);
		}
	} else if (rec == cur)
		rec = cur->up;
	closeframe(cur);
	cur = cur->up;
	cur->down = NULL;
	return (ret);
}

/*
 * The stack frame of this function is minimized so that we can
 * recurse quite a bit before we overflow the stack; around
 * 30,000-40,000 nested directories can be removed with the default
 * stack limit.
 */
static int
rm(const char *entry, struct dlist *caller)
{
	struct dlist frame;
	int flag;
	struct stat temp;
	struct dirent *dent;
	int err;

	/*
	 * Construct the pathname: note that the entry may live in memory
	 * allocated by readdir and that after return from recursion
	 * the memory is no longer valid.  So after the recursive rm()
	 * call, we use the global pathbuf instead of the entry argument.
	 */
	pushfilename(entry);

	if (fstatat(caller->fd, entry, &temp, AT_SYMLINK_NOFOLLOW) != 0) {
		if (!silent) {
			(void) fprintf(stderr, "rm: %s: %s\n", pathbuf,
			    strerror(errno));
			errcnt++;
		}
		return (0);
	}

	if (S_ISDIR(temp.st_mode)) {
		/*
		 * If "-r" wasn't specified, trying to remove directories
		 * is an error.
		 */
		if (!recursive) {
			(void) fprintf(stderr,
			    gettext("rm: %s is a directory\n"), pathbuf);
			errcnt++;
			return (0);
		}

		if (temp.st_ino == rootdir.st_ino &&
		    temp.st_dev == rootdir.st_dev) {
			(void) fprintf(stderr,
			    gettext("rm of %s is not allowed\n"), "/");
			errcnt++;
			return (0);
		}
		/*
		 * TRANSLATION_NOTE - The following message will contain the
		 * first character of the strings for "yes" and "no" defined
		 * in the file "nl_langinfo.po".  After substitution, the
		 * message will appear as follows:
		 *	rm: examine files in directory <directoryname> (y/n)?
		 * where <directoryname> is the directory to be removed
		 *
		 */
		if (interactive && !confirm(stderr,
		    gettext("rm: examine files in directory %s (%s/%s)? "),
		    pathbuf, yesstr, nostr)) {
			return (0);
		}

		frame.dev = temp.st_dev;
		frame.ino = temp.st_ino;
		frame.flags = 0;
		flag = AT_REMOVEDIR;

#ifdef XPG4
		/*
		 * XCU4 and POSIX.2: If not interactive, check to see whether
		 * or not directory is readable or writable and if not,
		 * prompt user for response.
		 */
		if (ontty && !interactive && !silent &&
		    faccessat(caller->fd, entry, W_OK|X_OK, AT_EACCESS) != 0 &&
		    !confirm(stderr,
		    gettext("rm: examine files in directory %s (%s/%s)? "),
		    pathbuf, yesstr, nostr)) {
			return (0);
		}
#endif
		if (opendirat(caller->fd, entry, &frame) == -1) {
			err = errno;

			if (interactive) {
				/*
				 * Print an error message that
				 * we could not read the directory
				 * as the user wanted to examine
				 * files in the directory.  Only
				 * affect the error status if
				 * user doesn't want to remove the
				 * directory as we still may be able
				 * remove the directory successfully.
				 */
				(void) fprintf(stderr, gettext(
				    "rm: cannot read directory %s: %s\n"),
				    pathbuf, strerror(err));

/*
 * TRANSLATION_NOTE - The following message will contain the
 * first character of the strings for "yes" and "no" defined
 * in the file "nl_langinfo.po".  After substitution, the
 * message will appear as follows:
 *	rm: remove <filename> (y/n)?
 * For example, in German, this will appear as
 *	rm: löschen <filename> (j/n)?
 * where j=ja, n=nein, <filename>=the file to be removed
 */
				if (!confirm(stderr,
				    gettext("rm: remove %s (%s/%s)? "),
				    pathbuf, yesstr, nostr)) {
					errcnt++;
					return (0);
				}
			}
			/* If it's empty we may still be able to rm it */
			if (unlinkat(caller->fd, entry, flag) == 0)
				return (0);
			if (interactive)
				err = errno;
			(void) fprintf(stderr,
			    interactive ?
			    gettext("rm: Unable to remove directory %s: %s\n") :
			    gettext("rm: cannot read directory %s: %s\n"),
			    pathbuf, strerror(err));
			errcnt++;
			return (0);
		}

		/*
		 * There is a race condition here too; if we open a directory
		 * we have to make sure it's still the same directory we
		 * stat'ed and checked against root earlier.  Let's check.
		 */
		if (fstat(frame.fd, &temp) != 0 ||
		    frame.ino != temp.st_ino ||
		    frame.dev != temp.st_dev) {
			(void) fprintf(stderr,
			    gettext("rm: %s: directory renamed\n"), pathbuf);
			closeframe(&frame);
			errcnt++;
			return (0);
		}

		if (caller != &top) {
			if (checkdir(caller, &frame) != 0) {
				closeframe(&frame);
				goto unlinkit;
			}
		}
		pushdir(&frame);

		/*
		 * rm() only returns -1 if popdir failed at some point;
		 * frame.dp is no longer reliable and we must drop out.
		 */
		while ((dent = readdir(frame.dp)) != NULL) {
			if (strcmp(dent->d_name, ".") == 0 ||
			    strcmp(dent->d_name, "..") == 0)
				continue;

			if (rm(dent->d_name, &frame) != 0)
				break;
		}

		if (popdir(dent == NULL) != 0)
			return (-1);

		/*
		 * We recursed and the subdirectory may have set the CANTCLOSE
		 * flag; we need to clear it except for &top.
		 * Recursion may have invalidated entry because of closedir().
		 */
		if (caller != &top) {
			caller->flags &= ~DIR_CANTCLOSE;
			entry = &pathbuf[caller->up->pathend + 1];
		}
	} else {
		flag = 0;
	}
unlinkit:
	/*
	 * If interactive, ask for acknowledgement.
	 */
	if (interactive) {
		if (!confirm(stderr, gettext("rm: remove %s (%s/%s)? "),
		    pathbuf, yesstr, nostr)) {
			return (0);
		}
	} else if (!silent && flag == 0) {
		/*
		 * If not silent, and stdin is a terminal, and there's
		 * no write access, and the file isn't a symbolic link,
		 * ask for permission.  If flag is set, then we know it's
		 * a directory so we skip this test as it was done above.
		 *
		 * TRANSLATION_NOTE - The following message will contain the
		 * first character of the strings for "yes" and "no" defined
		 * in the file "nl_langinfo.po".  After substitution, the
		 * message will appear as follows:
		 *	rm: <filename>: override protection XXX (y/n)?
		 * where XXX is the permission mode bits of the file in octal
		 * and <filename> is the file to be removed
		 *
		 */
		if (ontty && !S_ISLNK(temp.st_mode) &&
		    faccessat(caller->fd, entry, W_OK, AT_EACCESS) != 0 &&
		    !confirm(stdout,
		    gettext("rm: %s: override protection %o (%s/%s)? "),
		    pathbuf, temp.st_mode & 0777, yesstr, nostr)) {
			return (0);
		}
	}

	if (unlinkat(caller->fd, entry, flag) != 0) {
		err = errno;
		if (err == ENOENT)
			return (0);

		if (flag != 0) {
			if (err == EINVAL) {
				(void) fprintf(stderr, gettext(
				    "rm: Cannot remove any directory in the "
				    "path of the current working directory\n"
				    "%s\n"), pathbuf);
			} else {
				if (err == EEXIST)
					err = ENOTEMPTY;
				(void) fprintf(stderr,
				    gettext("rm: Unable to remove directory %s:"
				    " %s\n"), pathbuf, strerror(err));
			}
		} else {
#ifndef XPG4
			if (!silent || interactive) {
#endif

				(void) fprintf(stderr,
				    gettext("rm: %s not removed: %s\n"),
				    pathbuf, strerror(err));
#ifndef XPG4
			}
#endif
		}
		errcnt++;
	}
	return (0);
}

static int
confirm(FILE *fp, const char *q, ...)
{
	va_list ap;

	va_start(ap, q);
	(void) vfprintf(fp, q, ap);
	va_end(ap);
	return (yes());
}

static void
memerror(void)
{
	(void) fprintf(stderr, gettext("rm: Insufficient memory.\n"));
	exit(1);
}

/*
 * If we can't stat "..", it's either not there or we can't search
 * the current directory; in that case we can't return back through
 * "..", so we need to keep the parent open.
 * Check that we came from "..", if not then this directory entry is an
 * additional link and there is risk of a filesystem cycle and we also
 * can't go back up through ".." and we keep the directory open.
 */
static int
checkdir(struct dlist *caller, struct dlist *frmp)
{
	struct stat up;
	struct dlist *ptr;

	if (fstatat(frmp->fd, "..", &up, 0) != 0) {
		caller->flags |= DIR_CANTCLOSE;
		return (0);
	} else if (up.st_ino == caller->ino && up.st_dev == caller->dev) {
		return (0);
	}

	/* Directory hard link, check cycle */
	for (ptr = caller; ptr != NULL; ptr = ptr->up) {
		if (frmp->dev == ptr->dev && frmp->ino == ptr->ino) {
			(void) fprintf(stderr,
			    gettext("rm: cycle detected for %s\n"), pathbuf);
			errcnt++;
			return (-1);
		}
	}
	caller->flags |= DIR_CANTCLOSE;
	return (0);
}
