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

/*
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * chgrp [-fhR] gid file ...
 * chgrp -R [-f] [-H|-L|-P] gid file ...
 * chgrp -s [-fhR] groupsid file ...
 * chgrp -s -R [-f] [-H|-L|-P] groupsid file ...
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/avl.h>
#include <grp.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>
#include <libcmdutils.h>
#include <errno.h>
#include <strings.h>
#include <aclutils.h>

static struct group	*gr;
static struct stat	stbuf;
static struct stat	stbuf2;
static gid_t		gid;
static int		hflag = 0,
			fflag = 0,
			rflag = 0,
			Hflag = 0,
			Lflag = 0,
			Pflag = 0,
			sflag = 0;
static int		status = 0;	/* total number of errors received */

static avl_tree_t	*tree;		/* search tree to store inode data */

static void usage(void);
static int isnumber(char *);
static int Perror(char *);
static void chgrpr(char *, gid_t);

/*
 * Check to see if we are to follow symlinks specified on the command line.
 * This assumes we've already checked to make sure neither -h or -P was
 * specified, so we are just looking to see if -R -L, or -R -H was specified.
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
/*
 * We're ignoring errors here because preserving the SET[UG]ID bits is just
 * a courtesy.  This is only used on directories.
 */
#define	SETUGID_PRESERVE(dir, mode) \
	if (((mode) & (S_ISGID|S_ISUID)) != 0) \
		(void) chmod((dir), (mode) & ~S_IFMT)

extern int		optind;


int
main(int argc, char *argv[])
{
	int		c;

	/* set the locale for only the messages system (all else is clean) */

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "RhfHLPs")) != EOF)
		switch (c) {
			case 'R':
				rflag++;
				break;
			case 'h':
				hflag++;
				break;
			case 'f':
				fflag++;
				break;
			case 'H':
				/*
				 * If more than one of -H, -L, and -P
				 * are specified, only the last option
				 * specified determines the behavior of
				 * chgrp.  In addition, make [-H|-L]
				 * mutually exclusive of -h.
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
				usage();
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

	if ((argc < 2) ||
	    ((Hflag || Lflag || Pflag) && !rflag) ||
	    ((Hflag || Lflag || Pflag) && hflag)) {
		usage();
	}

	if (sflag) {
		if (sid_to_id(argv[0], B_FALSE, &gid)) {
			(void) fprintf(stderr, gettext(
			    "chgrp: invalid group sid %s\n"), argv[0]);
			exit(2);
		}
	} else if ((gr = getgrnam(argv[0])) != NULL) {
		gid = gr->gr_gid;
	} else {
		if (isnumber(argv[0])) {
			errno = 0;
			/* gid is an int */
			gid = (gid_t)strtoul(argv[0], NULL, 10);
			if (errno != 0) {
				if (errno == ERANGE) {
					(void) fprintf(stderr, gettext(
					"chgrp: group id is too large\n"));
					exit(2);
				} else {
					(void) fprintf(stderr, gettext(
					"chgrp: invalid group id\n"));
					exit(2);
				}
			}
		} else {
			(void) fprintf(stderr, "chgrp: ");
			(void) fprintf(stderr, gettext("unknown group: %s\n"),
			    argv[0]);
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
				 * Change the group id of the symbolic link
				 * specified on the command line.
				 * Don't follow the symbolic link to
				 * any other part of the file hierarchy.
				 */
				LCHOWN(argv[c], -1, gid);
			} else {
				if (stat(argv[c], &stbuf2) < 0) {
					status += Perror(argv[c]);
					continue;
				}
				/*
				 * We know that we are to change the
				 * group of the file referenced by the
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
							chgrpr(argv[c], gid);
							/*
							 * Try to restore the
							 * SET[UG]ID bits.
							 */
							SETUGID_PRESERVE(
							    argv[c],
							    stbuf2.st_mode &
							    ~S_IFMT);
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
						 * Change the group id of the
						 * file referenced by the
						 * symbolic link.
						 */
						CHOWN(argv[c], -1, gid);
					}
				} else {
					/*
					 * Change the group id of the file
					 * referenced by the symbolic link.
					 */
					CHOWN(argv[c], -1, gid);

					if ((stbuf2.st_mode & S_IFMT)
					    == S_IFDIR) {
						/* Reset the SET[UG]ID bits. */
						SETUGID_PRESERVE(argv[c],
						    stbuf2.st_mode & ~S_IFMT);
					}
				}
			}
		} else if (rflag && ((stbuf.st_mode & S_IFMT) == S_IFDIR)) {
			/*
			 * Add this node to the search tree so we don't
			 * get into a endless loop.
			 */
			if (add_tnode(&tree, stbuf.st_dev,
			    stbuf.st_ino) == 1) {
				chgrpr(argv[c], gid);

				/* Restore the SET[UG]ID bits. */
				SETUGID_PRESERVE(argv[c],
				    stbuf.st_mode & ~S_IFMT);
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
		} else {
			if (hflag || Pflag) {
				LCHOWN(argv[c], -1, gid);
			} else {
				CHOWN(argv[c], -1, gid);
			}
			/* If a directory, reset the SET[UG]ID bits. */
			if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
				SETUGID_PRESERVE(argv[c],
				    stbuf.st_mode & ~S_IFMT);
			}
		}
	}
	return (status);
}

/*
 * chgrpr() - recursive chown()
 *
 * Recursively chowns the input directory then its contents.  rflag must
 * have been set if chgrpr() is called.  The input directory should not
 * be a sym link (this is handled in the calling routine).  In
 * addition, the calling routine should have already added the input
 * directory to the search tree so we do not get into endless loops.
 * Note: chgrpr() doesn't need a return value as errors are reported
 * through the global "status" variable.
 */
static void
chgrpr(char *dir, gid_t gid)
{
	struct dirent *dp;
	DIR *dirp;
	struct stat st, st2;
	char savedir[1024];

	if (getcwd(savedir, 1024) == 0) {
		(void) fprintf(stderr, "chgrp: ");
		(void) fprintf(stderr, gettext("%s\n"), savedir);
		exit(255);
	}

	/*
	 * Attempt to chown the directory, however don't return if we
	 * can't as we still may be able to chown the contents of the
	 * directory.  Note: the calling routine resets the SUID bits
	 * on this directory so we don't have to perform an extra 'stat'.
	 */
	CHOWN(dir, -1, gid);

	if (chdir(dir) < 0) {
		status += Perror(dir);
		return;
	}
	if ((dirp = opendir(".")) == NULL) {
		status += Perror(dir);
		return;
	}
	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0)) {
			continue;	/* skip "." and ".." */
		}
		if (lstat(dp->d_name, &st) < 0) {
			status += Perror(dp->d_name);
			continue;
		}
		if ((st.st_mode & S_IFMT) == S_IFLNK) {
			if (hflag || Pflag) {
				/*
				 * Change the group id of the symbolic link
				 * encountered while traversing the
				 * directory.  Don't follow the symbolic
				 * link to any other part of the file
				 * hierarchy.
				 */
				LCHOWN(dp->d_name, -1, gid);
			} else {
				if (stat(dp->d_name, &st2) < 0) {
					status += Perror(dp->d_name);
					continue;
				}
				/*
				 * We know that we are to change the
				 * group of the file referenced by the
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
							chgrpr(dp->d_name, gid);

							/*
							 * Restore SET[UG]ID
							 * bits.
							 */
							SETUGID_PRESERVE(
							    dp->d_name,
							    st2.st_mode &
							    ~S_IFMT);
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
						 * Change the group id of the
						 * file referenced by the
						 * symbolic link.
						 */
						CHOWN(dp->d_name, -1, gid);

					}
				} else {
					/*
					 * Change the group id of the file
					 * referenced by the symbolic link.
					 */
					CHOWN(dp->d_name, -1, gid);

					if ((st2.st_mode & S_IFMT) == S_IFDIR) {
						/* Restore SET[UG]ID bits. */
						SETUGID_PRESERVE(dp->d_name,
						    st2.st_mode & ~S_IFMT);
					}
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
				chgrpr(dp->d_name, gid);

				/* Restore the SET[UG]ID bits. */
				SETUGID_PRESERVE(dp->d_name,
				    st.st_mode & ~S_IFMT);
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
			CHOWN(dp->d_name, -1, gid);
		}
	}
	(void) closedir(dirp);
	if (chdir(savedir) < 0) {
		(void) fprintf(stderr, "chgrp: ");
		(void) fprintf(stderr, gettext("can't change back to %s\n"),
		    savedir);
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
		(void) fprintf(stderr, "chgrp: ");
		perror(s);
	}
	return (!fflag);
}


static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage:\n"
	    "\tchgrp [-fhR] group file ...\n"
	    "\tchgrp -R [-f] [-H|-L|-P] group file ...\n"
	    "\tchgrp -s [-fhR] groupsid file ...\n"
	    "\tchgrp -s -R [-f] [-H|-L|-P] groupsid file ...\n"));
	exit(2);
}
