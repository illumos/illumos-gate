/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rm [-fiRr] file ...
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <locale.h>
#include <langinfo.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/resource.h>

#define	ARGCNT		5		/* Number of arguments */
#define	CHILD		0
#define	DIRECTORY	((buffer.st_mode&S_IFMT) == S_IFDIR)
#define	SYMLINK		((buffer.st_mode&S_IFMT) == S_IFLNK)
#define	FAIL		-1
#define	MAXFORK		100		/* Maximum number of forking attempts */
#define	NAMESIZE	MAXNAMLEN + 1	/* "/" + (file name size) */
#define	TRUE		1
#define	FALSE		0
#define	WRITE		02
#define	SEARCH		07

static	int	errcode;
static	int interactive, recursive, silent; /* flags for command line options */

static	void	rm(char *, int);
static	void	undir(char *, int, dev_t, ino_t);
static	int	yes(void);
static	int	mypath(dev_t, ino_t);

static	char	yeschr[SCHAR_MAX + 2];
static	char	nochr[SCHAR_MAX + 2];

static char *fullpath;
static int homedirfd;

static void push_name(char *name, int first);
static void pop_name(int first);
static void force_chdir(char *);
static void ch_dir(char *);
static char *get_filename(char *name);
static void chdir_home(void);
static void check_homedir(void);
static void cleanup(void);

static char 	*cwd;		/* pathname of home dir, from getcwd() */
static rlim_t	maxfiles;	/* maximum number of open files */
static int	first_dir = 1;	/* flag set when first trying to remove a dir */
	/* flag set when can't get dev/inode of a parent dir */
static int	parent_err = 0;

struct dir_id {
	dev_t	dev;
	ino_t	inode;
	struct dir_id *next;
};

	/*
	 * homedir is the first of a linked list of structures
	 * containing unique identifying device and inode numbers for
	 * each directory, from the home dir up to the root.
	 */
static struct dir_id homedir;

int
main(int argc, char *argv[])
{
	extern int	optind;
	int	errflg = 0;
	int	c;
	struct rlimit rl;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) strncpy(yeschr, nl_langinfo(YESSTR), SCHAR_MAX + 1);
	(void) strncpy(nochr, nl_langinfo(NOSTR), SCHAR_MAX + 1);

	while ((c = getopt(argc, argv, "frRi")) != EOF)
		switch (c) {
		case 'f':
			silent = TRUE;
#ifdef XPG4
			interactive = FALSE;
#endif
			break;
		case 'i':
			interactive = TRUE;
#ifdef XPG4
			silent = FALSE;
#endif
			break;
		case 'r':
		case 'R':
			recursive = TRUE;
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
		(void) fprintf(stderr,
			gettext("usage: rm [-fiRr] file ...\n"));
		exit(2);
	}

	if (getrlimit(RLIMIT_NOFILE, &rl)) {
		perror("getrlimit");
		exit(2);
	} else
		maxfiles = rl.rlim_cur - 2;

	while (argc-- > 0) {
		rm(*argv, 1);
		argv++;
	}

	cleanup();
	return (errcode ? 2 : 0);
	/* NOTREACHED */
}

static void
rm(char *path, int first)
{
	struct stat buffer;
	char	*filepath;
	char	*p;
	char	resolved_path[PATH_MAX];

	/*
	 * Check file to see if it exists.
	 */
	if (lstat(path, &buffer) == FAIL) {
		if (!silent) {
			perror(path);
			++errcode;
		}
		return;
	}

	/* prevent removal of / but allow removal of sym-links */
	if (!S_ISLNK(buffer.st_mode) && realpath(path, resolved_path) != NULL &&
	    strcmp(resolved_path, "/") == 0) {
		(void) fprintf(stderr,
		    gettext("rm of %s is not allowed\n"), resolved_path);
		errcode++;
		return;
	}

	/* prevent removal of . or .. (directly) */
	if (p = strrchr(path, '/'))
		p++;
	else
		p = path;
	if (strcmp(".", p) == 0 || strcmp("..", p) == 0) {
		if (!silent) {
			(void) fprintf(stderr,
			    gettext("rm of %s is not allowed\n"), path);
			errcode++;
		}
		return;
	}
	/*
	 * If it's a directory, remove its contents.
	 */
	if (DIRECTORY) {
		/*
		 * If "-r" wasn't specified, trying to remove directories
		 * is an error.
		 */
		if (!recursive) {
			(void) fprintf(stderr,
			    gettext("rm: %s is a directory\n"), path);
			++errcode;
			return;
		}

		if (first_dir) {
			check_homedir();
			first_dir = 0;
		}

		undir(path, first, buffer.st_dev, buffer.st_ino);
		return;
	}

	filepath = get_filename(path);

	/*
	 * If interactive, ask for acknowledgement.
	 *
	 * TRANSLATION_NOTE - The following message will contain the
	 * first character of the strings for "yes" and "no" defined
	 * in the file "nl_langinfo.po".  After substitution, the
	 * message will appear as follows:
	 *	rm: remove <filename> (y/n)?
	 * For example, in German, this will appear as
	 *	rm: löschen <filename> (j/n)?
	 * where j=ja, n=nein, <filename>=the file to be removed
	 *
	 */


	if (interactive) {
		(void) fprintf(stderr, gettext("rm: remove %s (%s/%s)? "),
			filepath, yeschr, nochr);
		if (!yes()) {
			free(filepath);
			return;
		}
	} else if (!silent) {
		/*
		 * If not silent, and stdin is a terminal, and there's
		 * no write access, and the file isn't a symbolic link,
		 * ask for permission.
		 *
		 * TRANSLATION_NOTE - The following message will contain the
		 * first character of the strings for "yes" and "no" defined
		 * in the file "nl_langinfo.po".  After substitution, the
		 * message will appear as follows:
		 * 	rm: <filename>: override protection XXX (y/n)?
		 * where XXX is the permission mode bits of the file in octal
		 * and <filename> is the file to be removed
		 *
		 */
		if (!SYMLINK && access(path, W_OK) == FAIL &&
		    isatty(fileno(stdin))) {
			(void) printf(
			    gettext("rm: %s: override protection %o (%s/%s)? "),
			    filepath, buffer.st_mode & 0777, yeschr, nochr);
			/*
			 * If permission isn't given, skip the file.
			 */
			if (!yes()) {
				free(filepath);
				return;
			}
		}
	}

	/*
	 * If the unlink fails, inform the user. For /usr/bin/rm, only inform
	 * the user if interactive or not silent.
	 * If unlink fails with errno = ENOENT because file was removed
	 * in between the lstat call and unlink don't inform the user and
	 * don't change errcode.
	 */

	if (unlink(path) == FAIL) {
		if (errno == ENOENT) {
			free(filepath);
			return;
		}
#ifndef XPG4
		if (!silent || interactive) {
#endif
			(void) fprintf(stderr,
				    gettext("rm: %s not removed: "), filepath);
				perror("");
#ifndef XPG4
		}
#endif
		++errcode;
	}

	free(filepath);
}

static void
undir(char *path, int first, dev_t dev, ino_t ino)
{
	char	*newpath;
	DIR	*name;
	struct dirent *direct;
	int	ismypath;
	int	chdir_failed = 0;
	size_t	len;

	push_name(path, first);

	/*
	 * If interactive and this file isn't in the path of the
	 * current working directory, ask for acknowledgement.
	 *
	 * TRANSLATION_NOTE - The following message will contain the
	 * first character of the strings for "yes" and "no" defined
	 * in the file "nl_langinfo.po".  After substitution, the
	 * message will appear as follows:
	 *	rm: examine files in directory <directoryname> (y/n)?
	 * where <directoryname> is the directory to be removed
	 *
	 */
	ismypath = mypath(dev, ino);
	if (interactive) {
		(void) fprintf(stderr,
		    gettext("rm: examine files in directory %s (%s/%s)? "),
			fullpath, yeschr, nochr);
		/*
		 * If the answer is no, skip the directory.
		 */
		if (!yes()) {
			pop_name(first);
			return;
		}
	}

#ifdef XPG4
	/*
	 * XCU4 and POSIX.2: If not interactive and file is not in the
	 * path of the current working directory, check to see whether
	 * or not directory is readable or writable and if not,
	 * prompt user for response.
	 */
	if (!interactive && !ismypath &&
	    (access(path, W_OK|X_OK) == FAIL) && isatty(fileno(stdin))) {
		if (!silent) {
			(void) fprintf(stderr,
			    gettext(
				"rm: examine files in directory %s (%s/%s)? "),
			    fullpath, yeschr, nochr);
			/*
			 * If the answer is no, skip the directory.
			 */
			if (!yes()) {
				pop_name(first);
				return;
			}
		}
	}
#endif

	/*
	 * Open the directory for reading.
	 */
	if ((name = opendir(path)) == NULL) {
		int	saveerrno = errno;

		/*
		 * If interactive, ask for acknowledgement.
		 */
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
			    "rm: cannot read directory %s: "),
			    fullpath);
			errno = saveerrno;
			perror("");
			(void) fprintf(stderr, gettext(
			    "rm: remove %s: (%s/%s)? "),
			    fullpath, yeschr, nochr);
			if (!yes()) {
				++errcode;
				pop_name(first);
				return;
			}
		}

		/*
		 * If the directory is empty, we may be able to
		 * go ahead and remove it.
		 */
		if (rmdir(path) == FAIL) {
			if (interactive) {
				int	rmdirerr = errno;
				(void) fprintf(stderr, gettext(
				    "rm: Unable to remove directory %s: "),
				    fullpath);
				errno = rmdirerr;
				perror("");
			} else {
				(void) fprintf(stderr, gettext(
				    "rm: cannot read directory %s: "),
				    fullpath);
				errno = saveerrno;
				perror("");
			}
			++errcode;
		}

		/* Continue to next file/directory rather than exit */
		pop_name(first);
		return;
	}

	/*
	 * XCU4 requires that rm -r descend the directory
	 * hierarchy without regard to PATH_MAX.  If we can't
	 * chdir() do not increment error counter and do not
	 * print message.
	 *
	 * However, if we cannot chdir because someone has taken away
	 * execute access we may still be able to delete the directory
	 * if it's empty. The old rm could do this.
	 */

	if (chdir(path) == -1) {
		chdir_failed = 1;
	}

	/*
	 * Read every directory entry.
	 */
	while ((direct = readdir(name)) != NULL) {
		/*
		 * Ignore "." and ".." entries.
		 */
		if (strcmp(direct->d_name, ".") == 0 ||
		    strcmp(direct->d_name, "..") == 0)
			continue;
		/*
		 * Try to remove the file.
		 */
		len = strlen(direct->d_name) + 1;
		if (chdir_failed) {
			len += strlen(path) + 2;
		}

		newpath = malloc(len);
		if (newpath == NULL) {
			(void) fprintf(stderr,
			    gettext("rm: Insufficient memory.\n"));
			cleanup();
			exit(1);
		}

		if (!chdir_failed) {
			(void) strcpy(newpath, direct->d_name);
		} else {
			(void) snprintf(newpath, len, "%s/%s",
			    path, direct->d_name);
		}


		/*
		 * If a spare file descriptor is available, just call the
		 * "rm" function with the file name; otherwise close the
		 * directory and reopen it when the child is removed.
		 */
		if (name->dd_fd >= maxfiles) {
			(void) closedir(name);
			rm(newpath, 0);
			if (!chdir_failed)
				name = opendir(".");
			else
				name = opendir(path);
			if (name == NULL) {
				(void) fprintf(stderr,
				    gettext("rm: cannot read directory %s: "),
				    fullpath);
				perror("");
				cleanup();
				exit(2);
			}
		} else
			rm(newpath, 0);

		free(newpath);
	}

	/*
	 * Close the directory we just finished reading.
	 */
	(void) closedir(name);

	/*
	 * The contents of the directory have been removed.  If the
	 * directory itself is in the path of the current working
	 * directory, don't try to remove it.
	 * When the directory itself is the current working directory, mypath()
	 * has a return code == 2.
	 *
	 * XCU4: Because we've descended the directory hierarchy in order
	 * to avoid PATH_MAX limitation, we must now start ascending
	 * one level at a time and remove files/directories.
	 */

	if (!chdir_failed) {
		if (first)
			chdir_home();
		else if (chdir("..") == -1) {
			(void) fprintf(stderr,
			    gettext("rm: cannot change to parent of "
				    "directory %s: "),
			    fullpath);
			perror("");
			cleanup();
			exit(2);
		}
	}

	switch (ismypath) {
	case 3:
		pop_name(first);
		return;
	case 2:
		(void) fprintf(stderr,
		    gettext("rm: Cannot remove any directory in the path "
			"of the current working directory\n%s\n"), fullpath);
		++errcode;
		pop_name(first);
		return;
	case 1:
		++errcode;
		pop_name(first);
		return;
	case 0:
		break;
	}

	/*
	 * If interactive, ask for acknowledgement.
	 */
	if (interactive) {
		(void) fprintf(stderr, gettext("rm: remove %s: (%s/%s)? "),
			fullpath, yeschr, nochr);
		if (!yes()) {
			pop_name(first);
			return;
		}
	}
	if (rmdir(path) == FAIL) {
		(void) fprintf(stderr,
			gettext("rm: Unable to remove directory %s: "),
			fullpath);
		perror("");
		++errcode;
	}
	pop_name(first);
}


static int
yes(void)
{
	int	i, b;
	char	ans[SCHAR_MAX + 1];

	for (i = 0; ; i++) {
		b = getchar();
		if (b == '\n' || b == '\0' || b == EOF) {
			ans[i] = 0;
			break;
		}
		if (i < SCHAR_MAX)
			ans[i] = b;
	}
	if (i >= SCHAR_MAX) {
		i = SCHAR_MAX;
		ans[SCHAR_MAX] = 0;
	}
	if ((i == 0) | (strncmp(yeschr, ans, i)))
		return (0);
	return (1);
}


static int
mypath(dev_t dev, ino_t ino)
{
	struct dir_id *curdir;

	/*
	 * Check to see if this is our current directory
	 * Indicated by return 2;
	 */
	if (dev == homedir.dev && ino == homedir.inode) {
		return (2);
	}

	curdir = homedir.next;

	while (curdir != NULL) {
		/*
		 * If we find a match, the directory (dev, ino) passed to
		 * mypath() is an ancestor of ours. Indicated by return 3.
		 */
		if (curdir->dev == dev && curdir->inode == ino)
			return (3);
		curdir = curdir->next;
	}
	/*
	 * parent_err indicates we couldn't stat or chdir to
	 * one of our parent dirs, so the linked list of dir_id structs
	 * is incomplete
	 */
	if (parent_err) {
#ifndef XPG4
		if (!silent || interactive) {
#endif
			(void) fprintf(stderr, gettext("rm: cannot determine "
			    "if this is an ancestor of the current "
			    "working directory\n%s\n"), fullpath);
#ifndef XPG4
		}
#endif
		/* assume it is. least dangerous */
		return (1);
	}
	return (0);
}

static int maxlen;
static int curlen;

static char *
get_filename(char *name)
{
	char *path;
	size_t len;

	if (fullpath == NULL || *fullpath == '\0') {
		path = strdup(name);
		if (path == NULL) {
			(void) fprintf(stderr,
			    gettext("rm: Insufficient memory.\n"));
			cleanup();
			exit(1);
		}
	} else {
		len = strlen(fullpath) + strlen(name) + 2;
		path = malloc(len);
		if (path == NULL) {
			(void) fprintf(stderr,
			    gettext("rm: Insufficient memory.\n"));
			cleanup();
			exit(1);
		}
		(void) snprintf(path, len, "%s/%s", fullpath, name);
	}
	return (path);
}

static void
push_name(char *name, int first)
{
	int	namelen;

	namelen = strlen(name) + 1; /* 1 for "/" */
	if ((curlen + namelen) >= maxlen) {
		maxlen += PATH_MAX;
		fullpath = (char *)realloc(fullpath, (size_t)(maxlen + 1));
	}
	if (first) {
		(void) strcpy(fullpath, name);
	} else {
		(void) strcat(fullpath, "/");
		(void) strcat(fullpath, name);
	}
	curlen = strlen(fullpath);
}

static void
pop_name(int first)
{
	char *slash;

	if (first) {
		*fullpath = '\0';
		return;
	}
	slash = strrchr(fullpath, '/');
	if (slash)
		*slash = '\0';
	else
		*fullpath = '\0';
	curlen = strlen(fullpath);
}

static void
force_chdir(char *dirname)
{
	char 	*pathname, *mp, *tp;

	/* use pathname instead of dirname, so dirname won't be modified */
	if ((pathname = strdup(dirname)) == NULL) {
		(void) fprintf(stderr, gettext("rm: strdup: "));
		perror("");
		cleanup();
		exit(2);
	}

	/* pathname is an absolute full path from getcwd() */
	mp = pathname;
	while (mp) {
		tp = strchr(mp, '/');
		if (strlen(mp) >= PATH_MAX) {
			/*
			 * after the first iteration through this
			 * loop, the below will NULL out the '/'
			 * which follows the first dir on pathname
			 */
			*tp = 0;
			tp++;
			if (*mp == NULL)
				ch_dir("/");
			else
				/*
				 * mp points to the start of a dirname,
				 * terminated by NULL, so ch_dir()
				 * here will move down one directory
				 */
				ch_dir(mp);
			/*
			 * reset mp to the start of the dirname
			 * which follows the one we just chdir'd to
			 */
			mp = tp;
			continue;	/* probably can remove this */
		} else {
			ch_dir(mp);
			break;
		}
	}
	free(pathname);
}

static void
ch_dir(char *dirname)
{
	if (chdir(dirname) == -1) {
		(void) fprintf(stderr,
		gettext("rm: cannot change to %s directory: "), dirname);
			perror("");
			cleanup();
			exit(2);
	}
}

static void
chdir_home(void)
{
	/*
	 * Go back to home dir--the dir from where rm was executed--using
	 * one of two methods, depending on which method works
	 * for the given permissions of the home dir and its
	 * parent directories.
	 */
	if (homedirfd != -1) {
		if (fchdir(homedirfd) == -1) {
			(void) fprintf(stderr,
			    gettext("rm: cannot change to starting "
			    "directory: "));
			perror("");
			cleanup();
			exit(2);
		}
	} else {
		if (strlen(cwd) < PATH_MAX)
			ch_dir(cwd);
		else
			force_chdir(cwd);
	}
}

/*
 * check_homedir -
 * is only called the first time rm tries to
 * remove a directory.  It saves the current directory, i.e.,
 * home dir, so we can go back to it after traversing elsewhere.
 * It also saves all the device and inode numbers of each
 * dir from the home dir back to the root in a linked list, so we
 * can later check, via mypath(), if we are trying to remove our current
 * dir or an ancestor.
 */
static void
check_homedir(void)
{
	int	size;	/* size allocated for pathname of home dir (cwd) */
	struct stat buffer;
	struct dir_id *lastdir, *curdir;

	/*
	 * We need to save where we currently are (the "home dir") so
	 * we can return after traversing down directories we're
	 * removing.  Two methods are attempted:
	 *
	 * 1) open() the home dir so we can use the fd
	 *    to fchdir() back.  This requires read permission
	 *    on the home dir.
	 *
	 * 2) getcwd() so we can chdir() to go back.  This
	 *    requires search (x) permission on the home dir,
	 *    and read and search permission on all parent dirs.  Also,
	 *    getcwd() will not work if the home dir is > 341
	 *    directories deep (see open bugid 4033182 - getcwd needs
	 *    to work for pathnames of any depth).
	 *
	 * If neither method works, we can't remove any directories
	 * and rm will fail.
	 *
	 * For future enhancement, a possible 3rd option to use
	 * would be to fork a process to remove a directory,
	 * eliminating the need to chdir back to the home directory
	 * and eliminating the permission restrictions on the home dir
	 * or its parent dirs.
	 */
	homedirfd = open(".", O_RDONLY);
	if (homedirfd == -1) {
		size = PATH_MAX;
		while ((cwd = getcwd(NULL, size)) == NULL) {
			if (errno == ERANGE) {
				size = PATH_MAX + size;
				continue;
			} else {
				(void) fprintf(stderr,
				    gettext("rm: cannot open starting "
				    "directory: "));
				perror("pwd");
				exit(2);
			}
		}
	}

	/*
	 * since we exit on error here, we're guaranteed to at least
	 * have info in the first dir_id struct, homedir
	 */
	if (stat(".", &buffer) == -1) {
		(void) fprintf(stderr,
		    gettext("rm: cannot stat current directory: "));
		perror("");
		exit(2);
	}
	homedir.dev = buffer.st_dev;
	homedir.inode = buffer.st_ino;
	homedir.next = NULL;

	lastdir = &homedir;
	/*
	 * Starting from current working directory, walk toward the
	 * root, looking at each directory along the way.
	 */
	for (;;) {
		if (chdir("..") == -1 || lstat(".", &buffer) == -1) {
			parent_err = 1;
			break;
		}

		if ((lastdir->next = malloc(sizeof (struct dir_id))) ==
		    NULL) {
			(void) fprintf(stderr,
			    gettext("rm: Insufficient memory.\n"));
			cleanup();
			exit(1);
		}

		curdir = lastdir->next;
		curdir->dev = buffer.st_dev;
		curdir->inode = buffer.st_ino;
		curdir->next = NULL;

		/*
		 * Stop when we reach the root; note that chdir("..")
		 * at the root dir will stay in root. Get rid of
		 * the redundant dir_id struct for root.
		 */
		if (curdir->dev == lastdir->dev && curdir->inode ==
		    lastdir->inode) {
			lastdir->next = NULL;
			free(curdir);
			break;
		}

			/* loop again to go back another level */
		lastdir = curdir;
	}
		/* go back to home directory */
	chdir_home();
}

/*
 * cleanup the dynamically-allocated list of device numbers and inodes,
 * if any.  If homedir was never used, it is external and static so
 * it is guaranteed initialized to zero, thus homedir.next would be NULL.
 */

static void
cleanup(void) {

	struct dir_id *lastdir, *curdir;

	curdir = homedir.next;

	while (curdir != NULL) {
		lastdir = curdir;
		curdir = curdir->next;
		free(lastdir);
	}
}
