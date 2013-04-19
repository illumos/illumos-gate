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
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

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
 * Combined mv/cp/ln command:
 *	mv file1 file2
 *	mv dir1 dir2
 *	mv file1 ... filen dir1
 */
#include <sys/time.h>
#include <signal.h>
#include <locale.h>
#include <stdarg.h>
#include <sys/acl.h>
#include <libcmdutils.h>
#include <aclutils.h>
#include "getresponse.h"

#define	FTYPE(A)	(A.st_mode)
#define	FMODE(A)	(A.st_mode)
#define	UID(A)		(A.st_uid)
#define	GID(A)		(A.st_gid)
#define	IDENTICAL(A, B)	(A.st_dev == B.st_dev && A.st_ino == B.st_ino)
#define	ISDIR(A)	((A.st_mode & S_IFMT) == S_IFDIR)
#define	ISDOOR(A)	((A.st_mode & S_IFMT) == S_IFDOOR)
#define	ISLNK(A)	((A.st_mode & S_IFMT) == S_IFLNK)
#define	ISREG(A)	(((A).st_mode & S_IFMT) == S_IFREG)
#define	ISDEV(A)	((A.st_mode & S_IFMT) == S_IFCHR || \
			(A.st_mode & S_IFMT) == S_IFBLK || \
			(A.st_mode & S_IFMT) == S_IFIFO)
#define	ISSOCK(A)	((A.st_mode & S_IFMT) == S_IFSOCK)

#define	DELIM	'/'
#define	EQ(x, y)	(strcmp(x, y) == 0)
#define	FALSE	0
#define	MODEBITS (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)
#define	TRUE 1

static char		*dname(char *);
static int		lnkfil(char *, char *);
static int		cpymve(char *, char *);
static int		chkfiles(char *, char **);
static int		rcopy(char *, char *);
static int		chk_different(char *, char *);
static int		chg_time(char *, struct stat);
static int		chg_mode(char *, uid_t, gid_t, mode_t);
static int		copydir(char *, char *);
static int		copyspecial(char *);
static int		getrealpath(char *, char *);
static void		usage(void);
static void		Perror(char *);
static void		Perror2(char *, char *);
static int		use_stdin(void);
static int		copyattributes(char *, char *);
static int		copy_sysattr(char *, char *);
static tree_node_t	*create_tnode(dev_t, ino_t);

static struct stat 	s1, s2, s3, s4;
static int 		cpy = FALSE;
static int 		mve = FALSE;
static int 		lnk = FALSE;
static char		*cmd;
static int		silent = 0;
static int		fflg = 0;
static int		iflg = 0;
static int		pflg = 0;
static int		Rflg = 0;	/* recursive copy */
static int		rflg = 0;	/* recursive copy */
static int		sflg = 0;
static int		Hflg = 0;	/* follow cmd line arg symlink to dir */
static int		Lflg = 0;	/* follow symlinks */
static int		Pflg = 0;	/* do not follow symlinks */
static int		atflg = 0;
static int		attrsilent = 0;
static int		targetexists = 0;
static int		cmdarg;		/* command line argument */
static avl_tree_t	*stree = NULL;	/* source file inode search tree */
static acl_t		*s1acl;
static int		saflg = 0;	/* 'cp' extended system attr. */
static int		srcfd = -1;
static int		targfd = -1;
static int		sourcedirfd = -1;
static int		targetdirfd = -1;
static DIR 		*srcdirp = NULL;
static int		srcattrfd = -1;
static int		targattrfd = -1;
static struct stat 	attrdir;

/* Extended system attributes support */

static int open_source(char  *);
static int open_target_srctarg_attrdirs(char  *, char *);
static int open_attrdirp(char *);
static int traverse_attrfile(struct dirent *, char *, char *, int);
static void rewind_attrdir(DIR *);
static void close_all();


int
main(int argc, char *argv[])
{
	int c, i, r, errflg = 0;
	char target[PATH_MAX];
	int (*move)(char *, char *);

	/*
	 * Determine command invoked (mv, cp, or ln)
	 */

	if (cmd = strrchr(argv[0], '/'))
		++cmd;
	else
		cmd = argv[0];

	/*
	 * Set flags based on command.
	 */

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);
	if (init_yes() < 0) {
		(void) fprintf(stderr, gettext(ERR_MSG_INIT_YES),
		    strerror(errno));
		exit(3);
	}

	if (EQ(cmd, "mv"))
		mve = TRUE;
	else if (EQ(cmd, "ln"))
		lnk = TRUE;
	else if (EQ(cmd, "cp"))
		cpy = TRUE;
	else {
		(void) fprintf(stderr,
		    gettext("Invalid command name (%s); expecting "
		    "mv, cp, or ln.\n"), cmd);
		exit(1);
	}

	/*
	 * Check for options:
	 * 	cp [ -r|-R [-H|-L|-P]] [-afip@/] file1 [file2 ...] target
	 * 	cp [-afiprR@/] file1 [file2 ...] target
	 *	ln [-f] [-n] [-s] file1 [file2 ...] target
	 *	ln [-f] [-n] [-s] file1 [file2 ...]
	 *	mv [-f|i] file1 [file2 ...] target
	 *	mv [-f|i] dir1 target
	 */

	if (cpy) {
		while ((c = getopt(argc, argv, "afHiLpPrR@/")) != EOF)
			switch (c) {
			case 'f':
				fflg++;
				break;
			case 'i':
				iflg++;
				break;
			case 'p':
				pflg++;
#ifdef XPG4
				attrsilent = 1;
				atflg = 0;
				saflg = 0;
#else
				if (atflg == 0)
					attrsilent = 1;
#endif
				break;
			case 'H':
				/*
				 * If more than one of -H, -L, or -P are
				 * specified, only the last option specified
				 * determines the behavior.
				 */
				Lflg = Pflg = 0;
				Hflg++;
				break;
			case 'L':
				Hflg = Pflg = 0;
				Lflg++;
				break;
			case 'P':
				Lflg = Hflg = 0;
				Pflg++;
				break;
			case 'R':
				/*
				 * The default behavior of cp -R|-r
				 * when specified without -H|-L|-P
				 * is -L.
				 */
				Rflg++;
				/*FALLTHROUGH*/
			case 'r':
				rflg++;
				break;
			case 'a':
				Lflg = Hflg = 0;
				pflg++;
				Pflg++;
				Rflg++;
				rflg++;
				break;
			case '@':
				atflg++;
				attrsilent = 0;
#ifdef XPG4
				pflg = 0;
#endif
				break;
			case '/':
				saflg++;
				attrsilent = 0;
#ifdef XPG4
				pflg = 0;
#endif
				break;
			default:
				errflg++;
			}

		/* -R or -r must be specified with -H, -L, or -P */
		if ((Hflg || Lflg || Pflg) && !(Rflg || rflg)) {
			errflg++;
		}

	} else if (mve) {
		while ((c = getopt(argc, argv, "fis")) != EOF)
			switch (c) {
			case 'f':
				silent++;
#ifdef XPG4
				iflg = 0;
#endif
				break;
			case 'i':
				iflg++;
#ifdef XPG4
				silent = 0;
#endif
				break;
			default:
				errflg++;
			}
	} else { /* ln */
		while ((c = getopt(argc, argv, "fns")) != EOF)
			switch (c) {
			case 'f':
				silent++;
				break;
			case 'n':
				/* silently ignored; this is the default */
				break;
			case 's':
				sflg++;
				break;
			default:
				errflg++;
			}
	}

	/*
	 * For BSD compatibility allow - to delimit the end of
	 * options for mv.
	 */
	if (mve && optind < argc && (strcmp(argv[optind], "-") == 0))
		optind++;

	/*
	 * Check for sufficient arguments
	 * or a usage error.
	 */

	argc -= optind;
	argv  = &argv[optind];

	if ((argc < 2 && lnk != TRUE) || (argc < 1 && lnk == TRUE)) {
		(void) fprintf(stderr,
		    gettext("%s: Insufficient arguments (%d)\n"),
		    cmd, argc);
		usage();
	}

	if (errflg != 0)
		usage();

	/*
	 * If there is more than a source and target,
	 * the last argument (the target) must be a directory
	 * which really exists.
	 */

	if (argc > 2) {
		if (stat(argv[argc-1], &s2) < 0) {
			(void) fprintf(stderr,
			    gettext("%s: %s not found\n"),
			    cmd, argv[argc-1]);
			exit(2);
		}

		if (!ISDIR(s2)) {
			(void) fprintf(stderr,
			    gettext("%s: Target %s must be a directory\n"),
			    cmd, argv[argc-1]);
			usage();
		}
	}

	if (strlen(argv[argc-1]) >= PATH_MAX) {
		(void) fprintf(stderr,
		    gettext("%s: Target %s file name length exceeds PATH_MAX"
		    " %d\n"), cmd, argv[argc-1], PATH_MAX);
		exit(78);
	}

	if (argc == 1) {
		if (!lnk)
			usage();
		(void) strcpy(target, ".");
	} else {
		(void) strcpy(target, argv[--argc]);
	}

	/*
	 * Perform a multiple argument mv|cp|ln by
	 * multiple invocations of cpymve() or lnkfil().
	 */
	if (lnk)
		move = lnkfil;
	else
		move = cpymve;

	r = 0;
	for (i = 0; i < argc; i++) {
		stree = NULL;
		cmdarg = 1;
		r += move(argv[i], target);
	}

	/*
	 * Show errors by nonzero exit code.
	 */

	return (r?2:0);
}

static int
lnkfil(char *source, char *target)
{
	char	*buf = NULL;

	if (sflg) {

		/*
		 * If target is a directory make complete
		 * name of the new symbolic link within that
		 * directory.
		 */

		if ((stat(target, &s2) >= 0) && ISDIR(s2)) {
			size_t len;

			len = strlen(target) + strlen(dname(source)) + 4;
			if ((buf = (char *)malloc(len)) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: Insufficient memory "
				    "to %s %s\n"), cmd, cmd, source);
				exit(3);
			}
			(void) snprintf(buf, len, "%s/%s",
			    target, dname(source));
			target = buf;
		}

		/*
		 * Check to see if the file exists already.
		 * In this case we use lstat() instead of stat():
		 * unlink(2) and symlink(2) will operate on the file
		 * itself, not its reference, if the file is a symlink.
		 */

		if ((lstat(target, &s2) == 0)) {
			/*
			 * Check if the silent flag is set ie. the -f option
			 * is used.  If so, use unlink to remove the current
			 * target to replace with the new target, specified
			 * on the command line.  Proceed with symlink.
			 */
			if (silent) {
			/*
			 * Don't allow silent (-f) removal of an existing
			 * directory; could leave unreferenced directory
			 * entries.
			 */
				if (ISDIR(s2)) {
					(void) fprintf(stderr,
					    gettext("%s: cannot create link "
					    "over directory %s\n"), cmd,
					    target);
					return (1);
				}
				if (unlink(target) < 0) {
					(void) fprintf(stderr,
					    gettext("%s: cannot unlink %s: "),
					    cmd, target);
					perror("");
					return (1);
				}
			}
		}


		/*
		 * Create a symbolic link to the source.
		 */

		if (symlink(source, target) < 0) {
			(void) fprintf(stderr,
			    gettext("%s: cannot create %s: "),
			    cmd, target);
			perror("");
			if (buf != NULL)
				free(buf);
			return (1);
		}
		if (buf != NULL)
			free(buf);
		return (0);
	}

	switch (chkfiles(source, &target)) {
		case 1: return (1);
		case 2: return (0);
			/* default - fall through */
	}

	/*
	 * Make sure source file is not a directory,
	 * we cannot link directories...
	 */

	if (ISDIR(s1)) {
		(void) fprintf(stderr,
		    gettext("%s: %s is a directory\n"), cmd, source);
		return (1);
	}

	/*
	 * hard link, call link() and return.
	 */

	if (link(source, target) < 0) {
		if (errno == EXDEV)
			(void) fprintf(stderr,
			    gettext("%s: %s is on a different file system\n"),
			    cmd, target);
		else {
			(void) fprintf(stderr,
			    gettext("%s: cannot create link %s: "),
			    cmd, target);
			perror("");
		}
		if (buf != NULL)
			free(buf);
		return (1);
	} else {
		if (buf != NULL)
			free(buf);
		return (0);
	}
}

static int
cpymve(char *source, char *target)
{
	int	n;
	int fi, fo;
	int ret = 0;
	int attret = 0;
	int sattret = 0;
	int errno_save;
	int error = 0;

	switch (chkfiles(source, &target)) {
		case 1: return (1);
		case 2: return (0);
			/* default - fall through */
	}

	/*
	 * If it's a recursive copy and source
	 * is a directory, then call rcopy (from copydir).
	 */
	if (cpy) {
		if (ISDIR(s1)) {
			int		rc;
			avl_index_t	where = 0;
			tree_node_t	*tnode;
			tree_node_t	*tptr;
			dev_t		save_dev = s1.st_dev;
			ino_t		save_ino = s1.st_ino;

			/*
			 * We will be recursing into the directory so
			 * save the inode information to a search tree
			 * to avoid getting into an endless loop.
			 */
			if ((rc = add_tnode(&stree, save_dev, save_ino)) != 1) {
				if (rc == 0) {
					/*
					 * We've already visited this directory.
					 * Don't remove the search tree entry
					 * to make sure we don't get into an
					 * endless loop if revisited from a
					 * different part of the hierarchy.
					 */
					(void) fprintf(stderr, gettext(
					    "%s: cycle detected: %s\n"),
					    cmd, source);
				} else {
					Perror(source);
				}
				return (1);
			}

			cmdarg = 0;
			rc = copydir(source, target);

			/*
			 * Create a tnode to get an index to the matching
			 * node (same dev and inode) in the search tree,
			 * then use the index to remove the matching node
			 * so it we do not wrongly detect a cycle when
			 * revisiting this directory from another part of
			 * the hierarchy.
			 */
			if ((tnode = create_tnode(save_dev,
			    save_ino)) == NULL) {
				Perror(source);
				return (1);
			}
			if ((tptr = avl_find(stree, tnode, &where)) != NULL) {
				avl_remove(stree, tptr);
			}
			free(tptr);
			free(tnode);
			return (rc);

		} else if (ISDEV(s1) && Rflg) {
			return (copyspecial(target));
		} else {
			goto copy;
		}
	}

	if (mve) {
		if (rename(source, target) >= 0)
			return (0);
		if (errno != EXDEV) {
			if (errno == ENOTDIR && ISDIR(s1)) {
				(void) fprintf(stderr,
				    gettext("%s: %s is a directory\n"),
				    cmd, source);
				return (1);
			}
			(void) fprintf(stderr,
			    gettext("%s: cannot rename %s to %s: "),
			    cmd, source, target);
			perror("");
			return (1);
		}

		/*
		 * cannot move a non-directory (source) onto an existing
		 * directory (target)
		 *
		 */
		if (targetexists && ISDIR(s2) && (!ISDIR(s1))) {
			(void) fprintf(stderr,
			    gettext("%s: cannot mv a non directory %s "
			    "over existing directory"
			    " %s \n"), cmd, source, target);
			return (1);
		}
		if (ISDIR(s1)) {
#ifdef XPG4
			if (targetexists && ISDIR(s2)) {
				/* existing target dir must be empty */
				if (rmdir(target) < 0) {
					errno_save = errno;
					(void) fprintf(stderr,
					    gettext("%s: cannot rmdir %s: "),
					    cmd, target);
					errno = errno_save;
					perror("");
					return (1);
				}
			}
#endif
			if ((n =  copydir(source, target)) == 0)
				(void) rmdir(source);
			return (n);
		}

		/* doors cannot be moved across filesystems */
		if (ISDOOR(s1)) {
			(void) fprintf(stderr,
			    gettext("%s: %s: cannot move door "
			    "across file systems\n"), cmd, source);
			return (1);
		}

		/* sockets cannot be moved across filesystems */
		if (ISSOCK(s1)) {
			(void) fprintf(stderr,
			    gettext("%s: %s: cannot move socket "
			    "across file systems\n"), cmd, source);
			return (1);
		}

		/*
		 * File cannot be renamed, try to recreate the symbolic
		 * link or special device, or copy the file wholesale
		 * between file systems.
		 */
		if (ISLNK(s1)) {
			register int	m;
			register mode_t md;
			char symln[PATH_MAX + 1];

			if (targetexists && unlink(target) < 0) {
				(void) fprintf(stderr,
				    gettext("%s: cannot unlink %s: "),
				    cmd, target);
				perror("");
				return (1);
			}

			if ((m = readlink(source, symln,
			    sizeof (symln) - 1)) < 0) {
				Perror(source);
				return (1);
			}
			symln[m] = '\0';

			md = umask(~(s1.st_mode & MODEBITS));
			if (symlink(symln, target) < 0) {
				Perror(target);
				return (1);
			}
			(void) umask(md);
			m = lchown(target, UID(s1), GID(s1));
#ifdef XPG4
			if (m < 0) {
				(void) fprintf(stderr, gettext("%s: cannot"
				    " change owner and group of"
				    " %s: "), cmd, target);
				perror("");
			}
#endif
			goto cleanup;
		}
		if (ISDEV(s1)) {

			if (targetexists && unlink(target) < 0) {
				(void) fprintf(stderr,
				    gettext("%s: cannot unlink %s: "),
				    cmd, target);
				perror("");
				return (1);
			}

			if (mknod(target, s1.st_mode, s1.st_rdev) < 0) {
				Perror(target);
				return (1);
			}

			(void) chg_mode(target, UID(s1), GID(s1), FMODE(s1));
			(void) chg_time(target, s1);
			goto cleanup;
		}

		if (ISREG(s1)) {
			if (ISDIR(s2)) {
				if (targetexists && rmdir(target) < 0) {
					(void) fprintf(stderr,
					    gettext("%s: cannot rmdir %s: "),
					    cmd, target);
					perror("");
					return (1);
				}
			} else {
				if (targetexists && unlink(target) < 0) {
					(void) fprintf(stderr,
					    gettext("%s: cannot unlink %s: "),
					    cmd, target);
					perror("");
					return (1);
				}
			}


copy:
			/*
			 * If the source file is a symlink, and either
			 * -P or -H flag (only if -H is specified and the
			 * source file is not a command line argument)
			 * were specified, then action is taken on the symlink
			 * itself, not the file referenced by the symlink.
			 * Note: this is executed for 'cp' only.
			 */
			if (cpy && (Pflg || (Hflg && !cmdarg)) && (ISLNK(s1))) {
				int	m;
				mode_t	md;
				char symln[PATH_MAX + 1];

				m = readlink(source, symln, sizeof (symln) - 1);

				if (m < 0) {
					Perror(source);
					return (1);
				}
				symln[m] = '\0';

				/*
				 * Copy the sym link to the target.
				 * Note: If the target exists, write a
				 * diagnostic message, do nothing more
				 * with the source file, and return to
				 * process any remaining files.
				 */
				md = umask(~(s1.st_mode & MODEBITS));
				if (symlink(symln, target) < 0) {
					Perror(target);
					return (1);
				}
				(void) umask(md);
				m = lchown(target, UID(s1), GID(s1));

				if (m < 0) {
					(void) fprintf(stderr, gettext(
					    "cp: cannot change owner and "
					    "group of %s:"), target);
					perror("");
				}
			} else {
				/*
				 * Copy the file.  If it happens to be a
				 * symlink, copy the file referenced
				 * by the symlink.
				 */
				fi = open(source, O_RDONLY);
				if (fi < 0) {
					(void) fprintf(stderr,
					    gettext("%s: cannot open %s: "),
					    cmd, source);
					perror("");
					return (1);
				}

				fo = creat(target, s1.st_mode & MODEBITS);
				if (fo < 0) {
					/*
					 * If -f and creat() failed, unlink
					 * and try again.
					 */
					if (fflg) {
						(void) unlink(target);
						fo = creat(target,
						    s1.st_mode & MODEBITS);
					}
				}
				if (fo < 0) {
					(void) fprintf(stderr,
					    gettext("%s: cannot create %s: "),
					    cmd, target);
					perror("");
					(void) close(fi);
					return (1);
				} else {
					/* stat the new file, its used below */
					(void) stat(target, &s2);
				}

				/*
				 * Set target's permissions to the source
				 * before any copying so that any partially
				 * copied file will have the source's
				 * permissions (at most) or umask permissions
				 * whichever is the most restrictive.
				 *
				 * ACL for regular files
				 */

				if (pflg || mve) {
					(void) chmod(target, FMODE(s1));
					if (s1acl != NULL) {
						if ((acl_set(target,
						    s1acl)) < 0) {
							error++;
							(void) fprintf(stderr,
							    gettext("%s: "
							    "Failed to set "
							    "acl entries "
							    "on %s\n"), cmd,
							    target);
							acl_free(s1acl);
							s1acl = NULL;
							/*
							 * else: silent and
							 * continue
							 */
						}
					}
				}

				if (fstat(fi, &s1) < 0) {
					(void) fprintf(stderr,
					    gettext("%s: cannot access %s\n"),
					    cmd, source);
					return (1);
				}
				if (IDENTICAL(s1, s2)) {
					(void) fprintf(stderr,
					    gettext(
					    "%s: %s and %s are identical\n"),
					    cmd, source, target);
					return (1);
				}

				if (writefile(fi, fo, source, target, NULL,
				    NULL, &s1, &s2) != 0) {
					return (1);
				}

				(void) close(fi);
				if (close(fo) < 0) {
					Perror2(target, "write");
					return (1);
				}
			}
			/* Copy regular extended attributes */
			if (pflg || atflg || mve || saflg) {
				attret = copyattributes(source, target);
				if (attret != 0 && !attrsilent) {
					(void) fprintf(stderr, gettext(
					    "%s: Failed to preserve"
					    " extended attributes of file"
					    " %s\n"), cmd, source);
				}
				/* Copy extended system attributes */
				if (pflg || mve || saflg)
					sattret = copy_sysattr(source, target);
				if (mve && attret != 0) {
					(void) unlink(target);
					return (1);
				}
				if (attrsilent) {
					attret = 0;
				}
			}

			/*
			 * XPG4: the write system call will clear setgid
			 * and setuid bits, so set them again.
			 */
			if (pflg || mve) {
				if ((ret = chg_mode(target, UID(s1), GID(s1),
				    FMODE(s1))) > 0)
					return (1);
				/*
				 * Reapply ACL, since chmod may have
				 * altered ACL
				 */
				if (s1acl != NULL) {
					if ((acl_set(target, s1acl)) < 0) {
						error++;
						(void) fprintf(stderr,
						    gettext("%s: Failed to "
						    "set acl entries "
						    "on %s\n"), cmd, target);
						/*
						 * else: silent and
						 * continue
						 */
					}
				}
				if ((ret = chg_time(target, s1)) > 0)
					return (1);
			}
			if (cpy) {
				if (error != 0 || attret != 0 || sattret != 0)
					return (1);
				return (0);
			}
			goto cleanup;
		}
		(void) fprintf(stderr,
		    gettext("%s: %s: unknown file type 0x%x\n"), cmd,
		    source, (s1.st_mode & S_IFMT));
		return (1);

cleanup:
		if (unlink(source) < 0) {
			(void) unlink(target);
			(void) fprintf(stderr,
			    gettext("%s: cannot unlink %s: "),
			    cmd, source);
			perror("");
			return (1);
		}
		if (error != 0 || attret != 0 || sattret != 0)
			return (1);
		return (ret);
	}
	/*NOTREACHED*/
	return (ret);
}

/*
 * create_tnode()
 *
 * Create a node for use with the search tree which contains the
 * inode information (device id and inode number).
 *
 * Input
 *	dev	- device id
 *	ino	- inode number
 *
 * Output
 *	tnode	- NULL on error, otherwise returns a tnode structure
 *		  which contains the input device id and inode number.
 */
static tree_node_t *
create_tnode(dev_t dev, ino_t ino)
{
	tree_node_t	*tnode;

	if ((tnode = (tree_node_t *)malloc(sizeof (tree_node_t))) != NULL) {
		tnode->node_dev = dev;
		tnode->node_ino = ino;
	}

	return (tnode);
}

static int
chkfiles(char *source, char **to)
{
	char	*buf = (char *)NULL;
	int	(*statf)() = (cpy &&
	    !(Pflg || (Hflg && !cmdarg))) ? stat : lstat;
	char    *target = *to;
	int	error;

	/*
	 * Make sure source file exists.
	 */
	if ((*statf)(source, &s1) < 0) {
		/*
		 * Keep the old error message except when someone tries to
		 * mv/cp/ln a symbolic link that has a trailing slash and
		 * points to a file.
		 */
		if (errno == ENOTDIR)
			(void) fprintf(stderr, "%s: %s: %s\n", cmd, source,
			    strerror(errno));
		else
			(void) fprintf(stderr,
			    gettext("%s: cannot access %s\n"), cmd, source);
		return (1);
	}

	/*
	 * Get ACL info: don't bother with ln or cp/mv'ing symlinks
	 */
	if (!lnk && !ISLNK(s1)) {
		if (s1acl != NULL) {
			acl_free(s1acl);
			s1acl = NULL;
		}
		if ((error = acl_get(source, ACL_NO_TRIVIAL, &s1acl)) != 0) {
			(void) fprintf(stderr,
			    "%s: failed to get acl entries: %s\n", source,
			    acl_strerror(error));
			return (1);
		}
		/* else: just permission bits */
	}

	/*
	 * If stat fails, then the target doesn't exist,
	 * we will create a new target with default file type of regular.
	 */

	FTYPE(s2) = S_IFREG;
	targetexists = 0;
	if ((*statf)(target, &s2) >= 0) {
		if (ISLNK(s2))
			(void) stat(target, &s2);
		/*
		 * If target is a directory,
		 * make complete name of new file
		 * within that directory.
		 */
		if (ISDIR(s2)) {
			size_t len;

			len = strlen(target) + strlen(dname(source)) + 4;
			if ((buf = (char *)malloc(len)) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: Insufficient memory to "
				    "%s %s\n "), cmd, cmd, source);
				exit(3);
			}
			(void) snprintf(buf, len, "%s/%s",
			    target, dname(source));
			*to = target = buf;
		}

		if ((*statf)(target, &s2) >= 0) {
			int overwrite	= FALSE;
			int override	= FALSE;

			targetexists++;
			if (cpy || mve) {
				/*
				 * For cp and mv, it is an error if the
				 * source and target are the same file.
				 * Check for the same inode and file
				 * system, but don't check for the same
				 * absolute pathname because it is an
				 * error when the source and target are
				 * hard links to the same file.
				 */
				if (IDENTICAL(s1, s2)) {
					(void) fprintf(stderr,
					    gettext(
					    "%s: %s and %s are identical\n"),
					    cmd, source, target);
					if (buf != NULL)
						free(buf);
					return (1);
				}
			}
			if (lnk) {
				/*
				 * For ln, it is an error if the source and
				 * target are identical files (same inode,
				 * same file system, and filenames resolve
				 * to same absolute pathname).
				 */
				if (!chk_different(source, target)) {
					if (buf != NULL)
						free(buf);
					return (1);
				}
			}
			if (lnk && !silent) {
				(void) fprintf(stderr,
				    gettext("%s: %s: File exists\n"),
				    cmd, target);
				if (buf != NULL)
					free(buf);
				return (1);
			}

			/*
			 * overwrite:
			 * If the user does not have access to
			 * the target, ask ----if it is not
			 * silent and user invoked command
			 * interactively.
			 *
			 * override:
			 * If not silent, and stdin is a terminal, and
			 * there's no write access, and the file isn't a
			 * symbolic link, ask for permission.
			 *
			 * XPG4: both overwrite and override:
			 * ask only one question.
			 *
			 * TRANSLATION_NOTE - The following messages will
			 * contain the first character of the strings for
			 * "yes" and "no" defined in the file
			 * "nl_langinfo.po".  After substitution, the
			 * message will appear as follows:
			 *	<cmd>: overwrite <filename> (y/n)?
			 * where <cmd> is the name of the command
			 * (cp, mv) and <filename> is the destination file
			 */


			overwrite = iflg && !silent && use_stdin();
			override = !cpy && (access(target, 2) < 0) &&
			    !silent && use_stdin() && !ISLNK(s2);

			if (overwrite && override) {
				(void) fprintf(stderr,
				    gettext("%s: overwrite %s and override "
				    "protection %o (%s/%s)? "), cmd, target,
				    FMODE(s2) & MODEBITS, yesstr, nostr);
				if (yes() == 0) {
					if (buf != NULL)
						free(buf);
					return (2);
				}
			} else if (overwrite && ISREG(s2)) {
				(void) fprintf(stderr,
				    gettext("%s: overwrite %s (%s/%s)? "),
				    cmd, target, yesstr, nostr);
				if (yes() == 0) {
					if (buf != NULL)
						free(buf);
					return (2);
				}
			} else if (override) {
				(void) fprintf(stderr,
				    gettext("%s: %s: override protection "
				    /*CSTYLED*/
				    "%o (%s/%s)? "),
				    /*CSTYLED*/
				    cmd, target, FMODE(s2) & MODEBITS,
				    yesstr, nostr);
				if (yes() == 0) {
					if (buf != NULL)
						free(buf);
					return (2);
				}
			}

			if (lnk && unlink(target) < 0) {
				(void) fprintf(stderr,
				    gettext("%s: cannot unlink %s: "),
				    cmd, target);
				perror("");
				return (1);
			}
		}
	}
	return (0);
}

/*
 * check whether source and target are different
 * return 1 when they are different
 * return 0 when they are identical, or when unable to resolve a pathname
 */
static int
chk_different(char *source, char *target)
{
	char	rtarget[PATH_MAX], rsource[PATH_MAX];

	if (IDENTICAL(s1, s2)) {
		/*
		 * IDENTICAL will be true for hard links, therefore
		 * check whether the filenames are different
		 */
		if ((getrealpath(source, rsource) == 0) ||
		    (getrealpath(target, rtarget) == 0)) {
			return (0);
		}
		if (strncmp(rsource, rtarget, PATH_MAX) == 0) {
			(void) fprintf(stderr, gettext(
			    "%s: %s and %s are identical\n"),
			    cmd, source, target);
			return (0);
		}
	}
	return (1);
}

/*
 * get real path (resolved absolute pathname)
 * return 1 on success, 0 on failure
 */
static int
getrealpath(char *path, char *rpath)
{
	if (realpath(path, rpath) == NULL) {
		int	errno_save = errno;
		(void) fprintf(stderr, gettext(
		    "%s: cannot resolve path %s: "), cmd, path);
		errno = errno_save;
		perror("");
		return (0);
	}
	return (1);
}

static int
rcopy(char *from, char *to)
{
	DIR *fold = opendir(from);
	struct dirent *dp;
	struct stat statb, s1save;
	int errs = 0;
	char fromname[PATH_MAX];

	if (fold == 0 || ((pflg || mve) && fstat(fold->dd_fd, &statb) < 0)) {
		Perror(from);
		return (1);
	}
	if (pflg || mve) {
		/*
		 * Save s1 (stat information for source dir) so that
		 * mod and access times can be reserved during "cp -p"
		 * or mv, since s1 gets overwritten.
		 */
		s1save = s1;
	}
	for (;;) {
		dp = readdir(fold);
		if (dp == 0) {
			(void) closedir(fold);
			if (pflg || mve)
				return (chg_time(to, s1save) + errs);
			return (errs);
		}
		if (dp->d_ino == 0)
			continue;
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		if (strlen(from)+1+strlen(dp->d_name) >=
		    sizeof (fromname) - 1) {
			(void) fprintf(stderr,
			    gettext("%s : %s/%s: Name too long\n"),
			    cmd, from, dp->d_name);
			errs++;
			continue;
		}
		(void) snprintf(fromname, sizeof (fromname),
		    "%s/%s", from, dp->d_name);
		errs += cpymve(fromname, to);
	}
}

static char *
dname(char *name)
{
	register char *p;

	/*
	 * Return just the file name given the complete path.
	 * Like basename(1).
	 */

	p = name;

	/*
	 * While there are characters left,
	 * set name to start after last
	 * delimiter.
	 */

	while (*p)
		if (*p++ == DELIM && *p)
			name = p;
	return (name);
}

static void
usage(void)
{
	/*
	 * Display usage message.
	 */

	if (mve) {
		(void) fprintf(stderr, gettext(
		    "Usage: mv [-f] [-i] f1 f2\n"
		    "       mv [-f] [-i] f1 ... fn d1\n"
		    "       mv [-f] [-i] d1 d2\n"));
	} else if (lnk) {
#ifdef XPG4
		(void) fprintf(stderr, gettext(
		    "Usage: ln [-f] [-s] f1 [f2]\n"
		    "       ln [-f] [-s] f1 ... fn d1\n"
		    "       ln [-f] -s d1 d2\n"));
#else
		(void) fprintf(stderr, gettext(
		    "Usage: ln [-f] [-n] [-s] f1 [f2]\n"
		    "       ln [-f] [-n] [-s] f1 ... fn d1\n"
		    "       ln [-f] [-n] -s d1 d2\n"));
#endif
	} else if (cpy) {
		(void) fprintf(stderr, gettext(
		    "Usage: cp [-a] [-f] [-i] [-p] [-@] [-/] f1 f2\n"
		    "       cp [-a] [-f] [-i] [-p] [-@] [-/] f1 ... fn d1\n"
		    "       cp [-r|-R [-H|-L|-P]] [-a] [-f] [-i] [-p] [-@] "
		    "[-/] d1 ... dn-1 dn\n"));
	}
	exit(2);
}

/*
 * chg_time()
 *
 * Try to preserve modification and access time.
 * If 1) pflg is not set, or 2) pflg is set and this is the Solaris version,
 * don't report a utimensat() failure.
 * If this is the XPG4 version and utimensat fails, if 1) pflg is set (cp -p)
 * or 2) we are doing a mv, print a diagnostic message; arrange for a non-zero
 * exit status only if pflg is set.
 * utimensat(2) is being used to achieve granularity in nanoseconds
 * (if supported by the underlying file system) while setting file times.
 */
static int
chg_time(char *to, struct stat ss)
{
	struct timespec times[2];
	int rc;

	times[0] = ss.st_atim;
	times[1] = ss.st_mtim;

	rc = utimensat(AT_FDCWD, to, times,
	    ISLNK(s1) ? AT_SYMLINK_NOFOLLOW : 0);
#ifdef XPG4
	if ((pflg || mve) && rc != 0) {
		(void) fprintf(stderr,
		    gettext("%s: cannot set times for %s: "), cmd, to);
		perror("");
		if (pflg)
			return (1);
	}
#endif

	return (0);

}

/*
 * chg_mode()
 *
 * This function is called upon "cp -p" or mv across filesystems.
 *
 * Try to preserve the owner and group id.  If chown() fails,
 * only print a diagnostic message if doing a mv in the XPG4 version;
 * try to clear S_ISUID and S_ISGID bits in the target.  If unable to clear
 * S_ISUID and S_ISGID bits, print a diagnostic message and arrange for a
 * non-zero exit status because this is a security violation.
 * Try to preserve permissions.
 * If this is the XPG4 version and chmod() fails, print a diagnostic message
 * and arrange for a non-zero exit status.
 * If this is the Solaris version and chmod() fails, do not print a
 * diagnostic message or exit with a non-zero value.
 */
static int
chg_mode(char *target, uid_t uid, gid_t gid, mode_t mode)
{
	int clearflg = 0; /* controls message printed upon chown() error */
	struct stat st;

	/* Don't change mode if target is symlink */
	if (lstat(target, &st) == 0 && ISLNK(st))
		return (0);

	if (chown(target, uid, gid) != 0) {
#ifdef XPG4
		if (mve) {
			(void) fprintf(stderr, gettext("%s: cannot change"
			    " owner and group of %s: "), cmd, target);
			perror("");
		}
#endif
		if (mode & (S_ISUID | S_ISGID)) {
			/* try to clear S_ISUID and S_ISGID */
			mode &= ~S_ISUID & ~S_ISGID;
			++clearflg;
		}
	}
	if (chmod(target, mode) != 0) {
		if (clearflg) {
			(void) fprintf(stderr, gettext(
			    "%s: cannot clear S_ISUID and S_ISGID bits in"
			    " %s: "), cmd, target);
			perror("");
			/* cp -p should get non-zero exit; mv should not */
			if (pflg)
				return (1);
		}
#ifdef XPG4
		else {
			(void) fprintf(stderr, gettext(
			"%s: cannot set permissions for %s: "), cmd, target);
			perror("");
			/* cp -p should get non-zero exit; mv should not */
			if (pflg)
				return (1);
		}
#endif
	}
	return (0);

}

static void
Perror(char *s)
{
	char buf[PATH_MAX + 10];

	(void) snprintf(buf, sizeof (buf), "%s: %s", cmd, s);
	perror(buf);
}

static void
Perror2(char *s1, char *s2)
{
	char buf[PATH_MAX + 20];

	(void) snprintf(buf, sizeof (buf), "%s: %s: %s",
	    cmd, gettext(s1), gettext(s2));
	perror(buf);
}

/*
 * used for cp -R and for mv across file systems
 */
static int
copydir(char *source, char *target)
{
	int ret, attret = 0;
	int sattret = 0;
	int pret = 0;		/* need separate flag if -p is specified */
	mode_t	fixmode = (mode_t)0;	/* cleanup mode after copy */
	struct stat s1save;
	acl_t  *s1acl_save;
	int error = 0;

	s1acl_save = NULL;

	if (cpy && !rflg) {
		(void) fprintf(stderr,
		    gettext("%s: %s: is a directory\n"), cmd, source);
		return (1);
	}

	if (stat(target, &s2) < 0) {
		if (mkdir(target, (s1.st_mode & MODEBITS)) < 0) {
			(void) fprintf(stderr, "%s: ", cmd);
			perror(target);
			return (1);
		}
		if (stat(target, &s2) == 0) {
			fixmode = s2.st_mode;
		} else {
			fixmode = s1.st_mode;
		}
		(void) chmod(target, ((fixmode & MODEBITS) | S_IRWXU));
	} else if (!(ISDIR(s2))) {
		(void) fprintf(stderr,
		    gettext("%s: %s: not a directory.\n"), cmd, target);
		return (1);
	}
	if (pflg || mve) {
		/*
		 * Save s1 (stat information for source dir) and acl info,
		 * if any, so that ownership, modes, times, and acl's can
		 * be reserved during "cp -p" or mv.
		 * s1 gets overwritten when doing the recursive copy.
		 */
		s1save = s1;
		if (s1acl != NULL) {
			s1acl_save = acl_dup(s1acl);
			if (s1acl_save == NULL) {
				(void) fprintf(stderr, gettext("%s: "
				    "Insufficient memory to save acl"
				    " entry\n"), cmd);
				if (pflg)
					return (1);

			}
#ifdef XPG4
			else {
				(void) fprintf(stderr, gettext("%s: "
				    "Insufficient memory to save acl"
				    " entry\n"), cmd);
				if (pflg)
					return (1);
			}
#endif
		}
	}

	ret = rcopy(source, target);

	/*
	 * Once we created a directory, go ahead and set
	 * its attributes, e.g. acls and time. The info
	 * may get overwritten if we continue traversing
	 * down the tree.
	 *
	 * ACL for directory
	 */
	if (pflg || mve) {
		if ((pret = chg_mode(target, UID(s1save), GID(s1save),
		    FMODE(s1save))) == 0)
			pret = chg_time(target, s1save);
		ret += pret;
		if (s1acl_save != NULL) {
			if (acl_set(target, s1acl_save) < 0) {
				error++;
#ifdef XPG4
				if (pflg || mve) {
#else
				if (pflg) {
#endif
					(void) fprintf(stderr, gettext(
					    "%s: failed to set acl entries "
					    "on %s\n"), cmd, target);
					if (pflg) {
						acl_free(s1acl_save);
						s1acl_save = NULL;
						ret++;
					}
				}
				/* else: silent and continue */
			}
			acl_free(s1acl_save);
			s1acl_save = NULL;
		}
	} else if (fixmode != (mode_t)0)
		(void) chmod(target, fixmode & MODEBITS);

	if (pflg || atflg || mve || saflg) {
		attret = copyattributes(source, target);
		if (!attrsilent && attret != 0) {
			(void) fprintf(stderr, gettext("%s: Failed to preserve"
			    " extended attributes of directory"
			    " %s\n"), cmd, source);
		} else {
			/*
			 * Otherwise ignore failure.
			 */
			attret = 0;
		}
		/* Copy extended system attributes */
		if (pflg || mve || saflg) {
			sattret = copy_sysattr(source, target);
			if (sattret != 0) {
				(void) fprintf(stderr, gettext(
				    "%s: Failed to preserve "
				    "extended system attributes "
				    "of directory %s\n"), cmd, source);
			}
		}
	}
	if (attret != 0 || sattret != 0 || error != 0)
		return (1);
	return (ret);
}

static int
copyspecial(char *target)
{
	int ret = 0;

	if (mknod(target, s1.st_mode, s1.st_rdev) != 0) {
		(void) fprintf(stderr, gettext(
		    "cp: cannot create special file %s: "), target);
		perror("");
		return (1);
	}

	if (pflg) {
		if ((ret = chg_mode(target, UID(s1), GID(s1), FMODE(s1))) == 0)
			ret = chg_time(target, s1);
	}

	return (ret);
}

static int
use_stdin(void)
{
#ifdef XPG4
	return (1);
#else
	return (isatty(fileno(stdin)));
#endif
}

/* Copy non-system extended attributes */

static int
copyattributes(char *source, char *target)
{
	struct dirent *dp;
	int error = 0;
	int aclerror;
	mode_t mode;
	int clearflg = 0;
	acl_t *xacl = NULL;
	acl_t *attrdiracl = NULL;
	struct timespec times[2];


	if (pathconf(source,  _PC_XATTR_EXISTS) != 1)
		return (0);

	if (pathconf(target, _PC_XATTR_ENABLED) != 1) {
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext(
			    "%s: cannot preserve extended attributes, "
			    "operation not supported on file"
			    " %s\n"), cmd, target);
		}
		return (1);
	}
	if (open_source(source) != 0)
		return (1);
	if (open_target_srctarg_attrdirs(source, target) !=  0)
		return (1);
	if (open_attrdirp(source) != 0)
		return (1);

	if (pflg || mve) {
		if (fchmod(targetdirfd, attrdir.st_mode) == -1) {
			if (!attrsilent) {
				(void) fprintf(stderr,
				    gettext("%s: failed to set file mode"
				    " correctly on attribute directory of"
				    " file %s: "), cmd, target);
				perror("");
				++error;
			}
		}

		if (fchown(targetdirfd, attrdir.st_uid, attrdir.st_gid) == -1) {
			if (!attrsilent) {
				(void) fprintf(stderr,
				    gettext("%s: failed to set file"
				    " ownership correctly on attribute"
				    " directory of file %s: "), cmd, target);
				perror("");
				++error;
			}
		}
		/*
		 * Now that we are the owner we can update st_ctime by calling
		 * utimensat.
		 */
		times[0] = attrdir.st_atim;
		times[1] = attrdir.st_mtim;
		if (utimensat(targetdirfd, ".", times, 0) < 0) {
			if (!attrsilent) {
				(void) fprintf(stderr,
				    gettext("%s: cannot set attribute times"
				    " for %s: "), cmd, target);
				perror("");
				++error;
			}
		}

		/*
		 * Now set owner and group of attribute directory, implies
		 * changing the ACL of the hidden attribute directory first.
		 */
		if ((aclerror = facl_get(sourcedirfd,
		    ACL_NO_TRIVIAL, &attrdiracl)) != 0) {
			if (!attrsilent) {
				(void) fprintf(stderr, gettext(
				    "%s: failed to get acl entries of"
				    " attribute directory for"
				    " %s : %s\n"), cmd,
				    source, acl_strerror(aclerror));
				++error;
			}
		}

		if (attrdiracl) {
			if (facl_set(targetdirfd, attrdiracl) != 0) {
				if (!attrsilent) {
					(void) fprintf(stderr, gettext(
					"%s: failed to set acl entries"
					" on attribute directory "
					"for %s\n"), cmd, target);
					++error;
				}
				acl_free(attrdiracl);
				attrdiracl = NULL;
			}
		}
	}

	while ((dp = readdir(srcdirp)) != NULL) {
		int ret;

		if ((ret = traverse_attrfile(dp, source, target, 1)) == -1)
			continue;
		else if (ret > 0) {
			++error;
			goto out;
		}

		if (pflg || mve) {
			if ((aclerror = facl_get(srcattrfd,
			    ACL_NO_TRIVIAL, &xacl)) != 0) {
				if (!attrsilent) {
					(void) fprintf(stderr, gettext(
					    "%s: failed to get acl entries of"
					    " attribute %s for"
					    " %s: %s"), cmd, dp->d_name,
					    source, acl_strerror(aclerror));
					++error;
				}
			}
		}

		/*
		 * preserve ACL
		 */
		if ((pflg || mve) && xacl != NULL) {
			if ((facl_set(targattrfd, xacl)) < 0) {
				if (!attrsilent) {
					(void) fprintf(stderr, gettext(
					    "%s: failed to set acl entries on"
					    " attribute %s for"
					    "%s\n"), cmd, dp->d_name, target);
					++error;
				}
				acl_free(xacl);
				xacl = NULL;
			}
		}

		if (writefile(srcattrfd, targattrfd, source, target,
		    dp->d_name, dp->d_name, &s3, &s4) != 0) {
			if (!attrsilent) {
				++error;
			}
			goto next;
		}

		if (pflg || mve) {
			mode = FMODE(s3);

			if (fchown(targattrfd, UID(s3), GID(s3)) != 0) {
				if (!attrsilent) {
					(void) fprintf(stderr,
					    gettext("%s: cannot change"
					    " owner and group of"
					    " attribute %s for" " file"
					    " %s: "), cmd, dp->d_name, target);
					perror("");
					++error;
				}
				if (mode & (S_ISUID | S_ISGID)) {
					/* try to clear S_ISUID and S_ISGID */
					mode &= ~S_ISUID & ~S_ISGID;
					++clearflg;
				}
			}
			times[0] = s3.st_atim;
			times[1] = s3.st_mtim;
			if (utimensat(targetdirfd, dp->d_name, times, 0) < 0) {
				if (!attrsilent) {
					(void) fprintf(stderr,
					    gettext("%s: cannot set attribute"
					    " times for %s: "), cmd, target);
					perror("");
					++error;
				}
			}
			if (fchmod(targattrfd, mode) != 0) {
				if (clearflg) {
					(void) fprintf(stderr, gettext(
					    "%s: cannot clear S_ISUID and "
					    "S_ISGID bits in attribute %s"
					    " for file"
					    " %s: "), cmd, dp->d_name, target);
				} else {
					if (!attrsilent) {
						(void) fprintf(stderr,
						    gettext(
				"%s: cannot set permissions of attribute"
				" %s for %s: "), cmd, dp->d_name, target);
						perror("");
						++error;
					}
				}
			}
			if (xacl && ((facl_set(targattrfd, xacl)) < 0)) {
				if (!attrsilent) {
					(void) fprintf(stderr, gettext(
					    "%s: failed to set acl entries on"
					    " attribute %s for"
					    "%s\n"), cmd, dp->d_name, target);
					++error;
				}
				acl_free(xacl);
				xacl = NULL;
			}
		}
next:
		if (xacl != NULL) {
			acl_free(xacl);
			xacl = NULL;
		}
		if (srcattrfd != -1)
			(void) close(srcattrfd);
		if (targattrfd != -1)
			(void) close(targattrfd);
		srcattrfd = targattrfd = -1;
	}
out:
	if (xacl != NULL) {
		acl_free(xacl);
		xacl = NULL;
	}
	if (attrdiracl != NULL) {
		acl_free(attrdiracl);
		attrdiracl = NULL;
	}

	if (!saflg && !pflg && !mve)
		close_all();
	return (error == 0 ? 0 : 1);
}

/* Copy extended system attributes from source to target */

static int
copy_sysattr(char *source, char *target)
{
	struct dirent	*dp;
	nvlist_t	*response;
	int		error = 0;
	int		target_sa_support = 0;

	if (sysattr_support(source, _PC_SATTR_EXISTS) != 1)
		return (0);

	if (open_source(source) != 0)
		return (1);

	/*
	 * Gets non default extended system attributes from the
	 * source file to copy to the target. The target has
	 * the defaults set when its created and thus  no need
	 * to copy the defaults.
	 */
	response = sysattr_list(cmd, srcfd, source);

	if (sysattr_support(target, _PC_SATTR_ENABLED) != 1) {
		if (response != NULL) {
			(void) fprintf(stderr,
			    gettext(
			    "%s: cannot preserve extended system "
			    "attribute, operation not supported on file"
			    " %s\n"), cmd, target);
			error++;
			goto out;
		}
	} else {
		target_sa_support = 1;
	}

	if (target_sa_support) {
		if (srcdirp == NULL) {
			if (open_target_srctarg_attrdirs(source,
			    target) !=  0) {
				error++;
				goto out;
			}
			if (open_attrdirp(source) != 0) {
				error++;
				goto out;
			}
		} else {
			rewind_attrdir(srcdirp);
		}
		while ((dp = readdir(srcdirp)) != NULL) {
			nvlist_t	*res;
			int		ret;

			if ((ret = traverse_attrfile(dp, source, target,
			    0)) == -1)
				continue;
			else if (ret > 0) {
				++error;
				goto out;
			}
			/*
			 * Gets non default extended system attributes from the
			 * attribute file to copy to the target. The target has
			 * the defaults set when its created and thus  no need
			 * to copy the defaults.
			 */
			if (dp->d_name != NULL) {
				res = sysattr_list(cmd, srcattrfd, dp->d_name);
				if (res == NULL)
					goto next;

			/*
			 * Copy non default extended system attributes of named
			 * attribute file.
			 */
				if (fsetattr(targattrfd,
				    XATTR_VIEW_READWRITE, res) != 0) {
					++error;
					(void) fprintf(stderr, gettext("%s: "
					    "Failed to copy extended system "
					    "attributes from attribute file "
					    "%s of %s to %s\n"), cmd,
					    dp->d_name, source, target);
				}
			}
next:
			if (srcattrfd != -1)
				(void) close(srcattrfd);
			if (targattrfd != -1)
				(void) close(targattrfd);
			srcattrfd = targattrfd = -1;
			if (res != NULL)
				nvlist_free(res);
		}
	}
	/* Copy source file non default extended system attributes to target */
	if (target_sa_support && (response != NULL) &&
	    (fsetattr(targfd, XATTR_VIEW_READWRITE, response)) != 0) {
		++error;
		(void) fprintf(stderr, gettext("%s: Failed to "
		    "copy extended system attributes from "
		    "%s to %s\n"), cmd, source, target);
	}
out:
	if (response != NULL)
		nvlist_free(response);
	close_all();
	return (error == 0 ? 0 : 1);
}

/* Open the source file */

int
open_source(char  *src)
{
	int	error = 0;

	srcfd = -1;
	if ((srcfd = open(src, O_RDONLY)) == -1) {
		if (pflg && attrsilent) {
			error++;
			goto out;
		}
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext("%s: cannot open file"
			    " %s: "), cmd, src);
			perror("");
		}
		++error;
	}
out:
	if (error)
		close_all();
	return (error == 0 ? 0 : 1);
}

/* Open source attribute dir, target and target attribute dir. */

int
open_target_srctarg_attrdirs(char  *src, char *targ)
{
	int		error = 0;

	targfd = sourcedirfd = targetdirfd = -1;

	if ((targfd = open(targ, O_RDONLY)) == -1) {
		if (pflg && attrsilent) {
			error++;
			goto out;
		}
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext("%s: cannot open file"
			    " %s: "), cmd, targ);
			perror("");
		}
		++error;
		goto out;
	}

	if ((sourcedirfd = openat(srcfd, ".", O_RDONLY|O_XATTR)) == -1) {
		if (pflg && attrsilent) {
			error++;
			goto out;
		}
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext("%s: cannot open attribute"
			    " directory for %s: "), cmd, src);
			perror("");
		}
		++error;
		goto out;
	}

	if (fstat(sourcedirfd, &attrdir) == -1) {
		if (pflg && attrsilent) {
			error++;
			goto out;
		}

		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext("%s: could not retrieve stat"
			    " information for attribute directory"
			    "of file %s: "), cmd, src);
			perror("");
		}
		++error;
		goto out;
	}
	if ((targetdirfd = openat(targfd, ".", O_RDONLY|O_XATTR)) == -1) {
		if (pflg && attrsilent) {
			error++;
			goto out;
		}
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext("%s: cannot open attribute"
			    " directory for %s: "), cmd, targ);
			perror("");
		}
		++error;
	}
out:
	if (error)
		close_all();
	return (error == 0 ? 0 : 1);
}

int
open_attrdirp(char *source)
{
	int tmpfd = -1;
	int error = 0;

	/*
	 * dup sourcedirfd for use by fdopendir().
	 * fdopendir will take ownership of given fd and will close
	 * it when closedir() is called.
	 */

	if ((tmpfd = dup(sourcedirfd)) == -1) {
		if (pflg && attrsilent) {
			error++;
			goto out;
		}
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext(
			    "%s: unable to dup attribute directory"
			    " file descriptor for %s: "), cmd, source);
			perror("");
			++error;
		}
		goto out;
	}
	if ((srcdirp = fdopendir(tmpfd)) == NULL) {
		if (pflg && attrsilent) {
			error++;
			goto out;
		}
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext("%s: failed to open attribute"
			    " directory for %s: "), cmd, source);
			perror("");
			++error;
		}
	}
out:
	if (error)
		close_all();
	return (error == 0 ? 0 : 1);
}

/* Skips through ., .., and system attribute 'view' files */
int
traverse_attrfile(struct dirent *dp, char *source, char *target, int  first)
{
	int		error = 0;

	srcattrfd = targattrfd = -1;

	if ((dp->d_name[0] == '.' && dp->d_name[1] == '\0') ||
	    (dp->d_name[0] == '.' && dp->d_name[1] == '.' &&
	    dp->d_name[2] == '\0') ||
	    (sysattr_type(dp->d_name) == _RO_SATTR) ||
	    (sysattr_type(dp->d_name) == _RW_SATTR))
		return (-1);

	if ((srcattrfd = openat(sourcedirfd, dp->d_name,
	    O_RDONLY)) == -1) {
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext("%s: cannot open attribute %s on"
			    " file %s: "), cmd, dp->d_name, source);
			perror("");
			++error;
			goto out;
		}
	}

	if (fstat(srcattrfd, &s3) < 0) {
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext("%s: could not stat attribute"
			    " %s on file"
			    " %s: "), cmd, dp->d_name, source);
			perror("");
			++error;
		}
		goto out;
	}

	if (first) {
		(void) unlinkat(targetdirfd, dp->d_name, 0);
		if ((targattrfd = openat(targetdirfd, dp->d_name,
		    O_RDWR|O_CREAT|O_TRUNC, s3.st_mode & MODEBITS)) == -1) {
			if (!attrsilent) {
				(void) fprintf(stderr,
				    gettext("%s: could not create attribute"
				    " %s on file %s: "), cmd, dp->d_name,
				    target);
				perror("");
				++error;
			}
			goto out;
		}
	} else {
		if ((targattrfd = openat(targetdirfd, dp->d_name,
		    O_RDONLY)) == -1) {
			if (!attrsilent) {
				(void) fprintf(stderr,
				    gettext("%s: could not open attribute"
				    " %s on file %s: "), cmd, dp->d_name,
				    target);
				perror("");
				++error;
			}
			goto out;
		}
	}


	if (fstat(targattrfd, &s4) < 0) {
		if (!attrsilent) {
			(void) fprintf(stderr,
			    gettext("%s: could not stat attribute"
			    " %s on file"
			    " %s: "), cmd, dp->d_name, target);
			perror("");
			++error;
		}
	}

out:
	if (error) {
		if (srcattrfd != -1)
			(void) close(srcattrfd);
		if (targattrfd != -1)
			(void) close(targattrfd);
		srcattrfd = targattrfd = -1;
	}
	return (error == 0 ? 0 :1);
}

void
rewind_attrdir(DIR * sdp)
{
	int pwdfd;

	pwdfd = open(".", O_RDONLY);
	if ((pwdfd != -1) && (fchdir(sourcedirfd) == 0)) {
		rewinddir(sdp);
		(void) fchdir(pwdfd);
		(void) close(pwdfd);
	} else {
		if (!attrsilent) {
			(void) fprintf(stderr, gettext("%s: "
			    "failed to rewind attribute dir\n"),
			    cmd);
		}
	}
}

void
close_all()
{
	if (srcattrfd != -1)
		(void) close(srcattrfd);
	if (targattrfd != -1)
		(void) close(targattrfd);
	if (sourcedirfd != -1)
		(void) close(sourcedirfd);
	if (targetdirfd != -1)
		(void) close(targetdirfd);
	if (srcdirp != NULL) {
		(void) closedir(srcdirp);
		srcdirp = NULL;
	}
	if (srcfd != -1)
		(void) close(srcfd);
	if (targfd != -1)
		(void) close(targfd);
}
