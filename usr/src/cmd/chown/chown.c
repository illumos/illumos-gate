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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * chown [-fhR] uid[:gid] file ...
 * chown -R [-f] [-H|-L|-P] uid[:gid] file ...
 * chown -s [-fhR] ownersid[:groupsid] file ...
 * chown -s -R [-f] [-H|-L|-P] ownersid[:groupsid] file ...
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/avl.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <locale.h>
#include <errno.h>
#include <libcmdutils.h>
#include <aclutils.h>

static struct		passwd	*pwd;
static struct		group	*grp;
static struct		stat	stbuf;
static uid_t		uid = (uid_t)-1;
static gid_t		gid = (gid_t)-1;
static int		status = 0;	/* total number of errors received */
static int		hflag = 0,
			rflag = 0,
			fflag = 0,
			Hflag = 0,
			Lflag = 0,
			Pflag = 0,
			sflag = 0;
static avl_tree_t	*tree;

static int		Perror(char *);
static int		isnumber(char *);
static void		chownr(char *, uid_t, gid_t);
static void		usage();

/*
 * Check to see if we are to follow symlinks specified on the command line.
 * This assumes we've already checked to make sure neither -h or -P was
 * specified, so we are just looking to see if -R -H, or -R -L was specified.
 */
#define	FOLLOW_CL_LINKS	(rflag && (Hflag || Lflag))

/*
 * Follow symlinks when traversing directories.  Only follow symlinks
 * to other parts of the file hierarchy if -L was specified.
 */
#define	FOLLOW_D_LINKS	(Lflag)

#define	CHOWN(f, u, g)	if (chown(f, u, g) < 0) { \
				status += Perror(f); \
			}
#define	LCHOWN(f, u, g)	if (lchown(f, u, g) < 0) { \
				status += Perror(f); \
			}


int
main(int argc, char *argv[])
{
	int c;
	int ch;
	char *grpp;			/* pointer to group name arg */
	extern int optind;
	int errflg = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((ch = getopt(argc, argv, "hRfHLPs")) != EOF) {
		switch (ch) {
		case 'h':
			hflag++;
			break;

		case 'R':
			rflag++;
			break;

		case 'f':
			fflag++;
			break;

		case 'H':
			/*
			 * If more than one of -H, -L, and -P
			 * are specified, only the last option
			 * specified determines the behavior of
			 * chown.
			 */
			Lflag = Pflag = 0;
			Hflag++;
			break;

		case 'L':
			Hflag = Pflag = 0;
			Lflag++;
			break;

		case 'P':
			Hflag = Lflag = 0;
			Pflag++;
			break;

		case 's':
			sflag++;
			break;

		default:
			errflg++;
			break;
		}
	}
	/*
	 * Set Pflag by default for recursive operations
	 * if no other options were specified.
	 */
	if (rflag && !(Lflag || Hflag || Pflag || hflag)) {
		Pflag = 1;
	}
	/*
	 * Check for sufficient arguments
	 * or a usage error.
	 */

	argc -= optind;
	argv = &argv[optind];

	if (errflg || (argc < 2) ||
	    ((Hflag || Lflag || Pflag) && !rflag) ||
	    ((Hflag || Lflag || Pflag) && hflag)) {
		usage();
	}

	/*
	 * POSIX.2
	 * Check for owner[:group]
	 */
	if ((grpp = strchr(argv[0], ':')) != NULL) {
		*grpp++ = 0;

		if (sflag) {
			if (sid_to_id(grpp, B_FALSE, &gid)) {
				(void) fprintf(stderr, gettext(
				    "chown: invalid owning group sid %s\n"),
				    grpp);
				exit(2);
			}
		} else if ((grp = getgrnam(grpp)) != NULL) {
			gid = grp->gr_gid;
		} else {
			if (isnumber(grpp)) {
				errno = 0;
				gid = (gid_t)strtoul(grpp, NULL, 10);
				if (errno != 0) {
					if (errno == ERANGE) {
						(void) fprintf(stderr, gettext(
						"chown: group id too large\n"));
						exit(2);
					} else {
						(void) fprintf(stderr, gettext(
						"chown: invalid group id\n"));
						exit(2);
					}
				}
			} else {
				(void) fprintf(stderr, gettext(
				    "chown: unknown group id %s\n"), grpp);
				exit(2);
			}
		}
	}

	if (sflag) {
		if (sid_to_id(argv[0], B_TRUE, &uid)) {
			(void) fprintf(stderr, gettext(
			    "chown: invalid owner sid %s\n"), argv[0]);
			exit(2);
		}
	} else if ((pwd = getpwnam(argv[0])) != NULL) {
		uid = pwd->pw_uid;
	} else {
		if (isnumber(argv[0])) {
			errno = 0;
			uid = (uid_t)strtoul(argv[0], NULL, 10);
			if (errno != 0) {
				if (errno == ERANGE) {
					(void) fprintf(stderr, gettext(
					"chown: user id too large\n"));
					exit(2);
				} else {
					(void) fprintf(stderr, gettext(
					"chown: invalid user id\n"));
					exit(2);
				}
			}
		} else {
			(void) fprintf(stderr, gettext(
			"chown: unknown user id %s\n"), argv[0]);
			exit(2);
		}
	}

	for (c = 1; c < argc; c++) {
		tree = NULL;
		if (lstat(argv[c], &stbuf) < 0) {
			status += Perror(argv[c]);
			continue;
		}
		if (rflag && ((stbuf.st_mode & S_IFMT) == S_IFLNK)) {
			if (hflag || Pflag) {
				/*
				 * Change the ownership of the symlink
				 * specified on the command line.
				 * Don't follow the symbolic link to
				 * any other part of the file hierarchy.
				 */
				LCHOWN(argv[c], uid, gid);
			} else {
				struct stat stbuf2;
				if (stat(argv[c], &stbuf2) < 0) {
					status += Perror(argv[c]);
					continue;
				}
				/*
				 * We know that we are to change the
				 * ownership of the file referenced by the
				 * symlink specified on the command line.
				 * Now check to see if we are to follow
				 * the symlink to any other part of the
				 * file hierarchy.
				 */
				if (FOLLOW_CL_LINKS) {
					if ((stbuf2.st_mode & S_IFMT)
					    == S_IFDIR) {
						/*
						 * We are following symlinks so
						 * traverse into the directory.
						 * Add this node to the search
						 * tree so we don't get into an
						 * endless loop.
						 */
						if (add_tnode(&tree,
						    stbuf2.st_dev,
						    stbuf2.st_ino) == 1) {
							chownr(argv[c],
							    uid, gid);
						} else {
							/*
							 * Error occurred.
							 * rc can't be 0
							 * as this is the first
							 * node to be added to
							 * the search tree.
							 */
							status += Perror(
							    argv[c]);
						}
					} else {
						/*
						 * Change the user ID of the
						 * file referenced by the
						 * symlink.
						 */
						CHOWN(argv[c], uid, gid);
					}
				} else {
					/*
					 * Change the user ID of the file
					 * referenced by the symbolic link.
					 */
					CHOWN(argv[c], uid, gid);
				}
			}
		} else if (rflag && ((stbuf.st_mode & S_IFMT) == S_IFDIR)) {
			/*
			 * Add this node to the search tree so we don't
			 * get into a endless loop.
			 */
			if (add_tnode(&tree, stbuf.st_dev,
			    stbuf.st_ino) == 1) {
				chownr(argv[c], uid, gid);
			} else {
				/*
				 * An error occurred while trying
				 * to add the node to the tree.
				 * Continue on with next file
				 * specified.  Note: rc shouldn't
				 * be 0 as this was the first node
				 * being added to the search tree.
				 */
				status += Perror(argv[c]);
			}
		} else if (hflag || Pflag) {
			LCHOWN(argv[c], uid, gid);
		} else {
			CHOWN(argv[c], uid, gid);
		}
	}
	return (status);
}

/*
 * chownr() - recursive chown()
 *
 * Recursively chowns the input directory then its contents.  rflag must
 * have been set if chownr() is called.  The input directory should not
 * be a sym link (this is handled in the calling routine).  In
 * addition, the calling routine should have already added the input
 * directory to the search tree so we do not get into endless loops.
 * Note: chownr() doesn't need a return value as errors are reported
 * through the global "status" variable.
 */
static void
chownr(char *dir, uid_t uid, gid_t gid)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat st, st2;
	char savedir[1024];

	if (getcwd(savedir, 1024) == (char *)0) {
		(void) Perror("getcwd");
		exit(255);
	}

	/*
	 * Attempt to chown the directory, however don't return if we
	 * can't as we still may be able to chown the contents of the
	 * directory.  Note: the calling routine resets the SUID bits
	 * on this directory so we don't have to perform an extra 'stat'.
	 */
	CHOWN(dir, uid, gid);

	if (chdir(dir) < 0) {
		status += Perror(dir);
		return;
	}
	if ((dirp = opendir(".")) == NULL) {
		status += Perror(dir);
		return;
	}
	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
		if (strcmp(dp->d_name, ".") == 0 ||	/* skip . and .. */
		    strcmp(dp->d_name, "..") == 0) {
			continue;
		}
		if (lstat(dp->d_name, &st) < 0) {
			status += Perror(dp->d_name);
			continue;
		}
		if ((st.st_mode & S_IFMT) == S_IFLNK) {
			if (hflag || Pflag) {
				/*
				 * Change the ownership of the symbolic link
				 * encountered while traversing the
				 * directory.  Don't follow the symbolic
				 * link to any other part of the file
				 * hierarchy.
				 */
				LCHOWN(dp->d_name, uid, gid);
			} else {
				if (stat(dp->d_name, &st2) < 0) {
					status += Perror(dp->d_name);
					continue;
				}
				/*
				 * We know that we are to change the
				 * ownership of the file referenced by the
				 * symlink encountered while traversing
				 * the directory.  Now check to see if we
				 * are to follow the symlink to any other
				 * part of the file hierarchy.
				 */
				if (FOLLOW_D_LINKS) {
					if ((st2.st_mode & S_IFMT) == S_IFDIR) {
						/*
						 * We are following symlinks so
						 * traverse into the directory.
						 * Add this node to the search
						 * tree so we don't get into an
						 * endless loop.
						 */
						int rc;
						if ((rc = add_tnode(&tree,
						    st2.st_dev,
						    st2.st_ino)) == 1) {
							chownr(dp->d_name,
							    uid, gid);
						} else if (rc == 0) {
							/* already visited */
							continue;
						} else {
							/*
							 * An error occurred
							 * while trying to add
							 * the node to the tree.
							 */
							status += Perror(
							    dp->d_name);
							continue;
						}
					} else {
						/*
						 * Change the user id of the
						 * file referenced by the
						 * symbolic link.
						 */
						CHOWN(dp->d_name, uid, gid);
					}
				} else {
					/*
					 * Change the user id of the file
					 * referenced by the symbolic link.
					 */
					CHOWN(dp->d_name, uid, gid);
				}
			}
		} else if ((st.st_mode & S_IFMT) == S_IFDIR) {
			/*
			 * Add this node to the search tree so we don't
			 * get into a endless loop.
			 */
			int rc;
			if ((rc = add_tnode(&tree, st.st_dev,
			    st.st_ino)) == 1) {
				chownr(dp->d_name, uid, gid);
			} else if (rc == 0) {
				/* already visited */
				continue;
			} else {
				/*
				 * An error occurred while trying
				 * to add the node to the search tree.
				 */
				status += Perror(dp->d_name);
				continue;
			}
		} else {
			CHOWN(dp->d_name, uid, gid);
		}
	}

	(void) closedir(dirp);
	if (chdir(savedir) < 0) {
		(void) fprintf(stderr, gettext(
		    "chown: can't change back to %s\n"), savedir);
		exit(255);
	}
}

static int
isnumber(char *s)
{
	int c;

	while ((c = *s++) != '\0')
		if (!isdigit(c))
			return (0);
	return (1);
}

static int
Perror(char *s)
{
	if (!fflag) {
		(void) fprintf(stderr, "chown: ");
		perror(s);
	}
	return (!fflag);
}

static void
usage()
{
	(void) fprintf(stderr, gettext(
	    "usage:\n"
	    "\tchown [-fhR] owner[:group] file...\n"
	    "\tchown -R [-f] [-H|-L|-P] owner[:group] file...\n"
	    "\tchown -s [-fhR] ownersid[:groupsid] file...\n"
	    "\tchown -s -R [-f] [-H|-L|-P] ownersid[:groupsid] file...\n"));
	exit(2);
}
