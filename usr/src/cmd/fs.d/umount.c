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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include	<stdio.h>
#include	<stdio_ext.h>
#include	<limits.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/signal.h>
#include	<sys/mnttab.h>
#include	<errno.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/wait.h>
#include	<sys/vfstab.h>
#include	<sys/fcntl.h>
#include	<sys/resource.h>
#include	<sys/mntent.h>
#include	<sys/ctfs.h>
#include	<locale.h>
#include	<stdarg.h>
#include	<sys/mount.h>
#include	<sys/objfs.h>
#include	"fslib.h"
#include	<sharefs/share.h>

#define	FS_PATH		"/usr/lib/fs"
#define	ALT_PATH	"/etc/fs"
#define	FULLPATH_MAX	32
#define	FSTYPE_MAX	8
#define	ARGV_MAX	16

int	aflg, oflg, Vflg, dashflg, dflg, fflg;

extern void	rpterr(), usage(), mnterror();

extern	char	*optarg;	/* used by getopt */
extern	int	optind, opterr;

static char	*myname;
char	fs_path[] = FS_PATH;
char	alt_path[] = ALT_PATH;
char	mnttab[MAXPATHLEN + 1];
char	*oarg, *farg;
int	maxrun, nrun;
int	no_mnttab;
int	lofscnt;		/* presence of lofs prohibits parallel */
				/* umounting */
int	exitcode;
char	resolve[MAXPATHLEN];
static  char ibuf[BUFSIZ];

/*
 * The basic mount struct that describes an mnttab entry.
 * It is used both in an array and as a linked list elem.
 */

typedef struct mountent {
	struct mnttab	ment;		/* the mnttab data */
	int		mlevel;		/* mount level of the mount pt */
	pid_t		pid;		/* the pid of this mount process */
#define	RDPIPE		0
#define	WRPIPE		1
	int		sopipe[2];	/* pipe attached to child's stdout */
	int		sepipe[2];	/* pipe attached to child's stderr */
	struct mountent *link;		/* used when in linked list */
} mountent_t;

static mountent_t	*mntll;		/* head of global linked list of */
					/* mountents */
int			listlength;	/* # of elems in this list */

/*
 * If the automatic flag (-a) is given and mount points are not specified
 * on the command line, then do not attempt to umount these.  These
 * generally need to be kept mounted until system shutdown.
 */
static const char   *keeplist[] = {
	"/",
	"/dev",
	"/dev/fd",
	"/devices",
	"/etc/mnttab",
	"/etc/svc/volatile",
	"/lib",
	"/proc",
	"/sbin",
	CTFS_ROOT,
	OBJFS_ROOT,
	"/tmp",
	"/usr",
	"/var",
	"/var/adm",
	"/var/run",
	SHARETAB,
	NULL
};

static void	nomem();
static void	doexec(struct mnttab *);
static int	setup_iopipe(mountent_t *);
static void	setup_output(mountent_t *);
static void	doio(mountent_t *);
static void	do_umounts(mountent_t **);
static int	dowait();
static int	parumount();
static int	mcompar(const void *, const void *);
static void	cleanup(int);

static mountent_t	**make_mntarray(char **, int);
static mountent_t	*getmntall();
static mountent_t 	*new_mountent(struct mnttab *);
static mountent_t	*getmntlast(mountent_t *, char *, char *);

int
main(int argc, char **argv)
{
	int 	cc;
	struct mnttab  mget;
	char 	*mname, *is_special;
	int	fscnt;
	mountent_t	*mp;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	if (myname)
		myname++;
	else
		myname = argv[0];

	/*
	 * Process the args.
	 * "-d" for compatibility
	 */
	while ((cc = getopt(argc, argv, "ado:Vf?")) != -1)
		switch (cc) {
		case 'a':
			aflg++;
			break;
#ifdef DEBUG
		case 'd':
			dflg++;
			break;
#endif

		case '?':
			usage();
			break;
		case 'o':
			if (oflg)
				usage();
			else {
				oflg++;
				oarg = optarg;
			}
			break;
		case 'f':
			fflg++;
			break;
		case 'V':
			if (Vflg)
				usage();
			else
				Vflg++;
			break;
		default:
			usage();
			break;
		}

	fscnt = argc - optind;
	if (!aflg && fscnt != 1)
		usage();

	/* copy '--' to specific */
	if (strcmp(argv[optind-1], "--") == 0)
		dashflg++;

	/*
	 * mnttab may be a symlink to a file in another file system.
	 * This happens during install when / is mounted read-only
	 * and /etc/mnttab is symlinked to a file in /tmp.
	 * If this is the case, we need to follow the symlink to the
	 * read-write file itself so that the subsequent mnttab.temp
	 * open and rename will work.
	 */
	if (realpath(MNTTAB, mnttab) == NULL) {
		strcpy(mnttab, MNTTAB);
	}

	/*
	 * bugid 1205242
	 * call the realpath() here, so that if the user is
	 * trying to umount an autofs directory, the directory
	 * is forced to mount.
	 */

	mname = argv[optind];
	is_special = realpath(mname, resolve);

	/*
	 * Read the whole mnttab into memory.
	 */
	mntll = getmntall();

	if (aflg && fscnt != 1)
		exit(parumount(argv + optind, fscnt));

	aflg = 0;

	mntnull(&mget);
	if (listlength == 0) {
		fprintf(stderr, gettext(
		    "%s: warning: no entries found in %s\n"),
		    myname, mnttab);
		mget.mnt_mountp = mname;	/* assume mount point */
		no_mnttab++;
		doexec(&mget);
		exit(0);
	}

	mp = NULL;

	/*
	 * if realpath fails, it can't be a mount point, so we'll
	 * go straight to the code that treats the arg as a special.
	 * if realpath succeeds, it could be a special or a mount point;
	 * we'll start by assuming it's a mount point, and if it's not,
	 * try to treat it as a special.
	 */
	if (is_special != NULL) {
		/*
		 * if this succeeds,
		 * we'll have the appropriate record; if it fails
		 * we'll assume the arg is a special of some sort
		 */
		mp = getmntlast(mntll, NULL, resolve);
	}
	/*
	 * Since stackable mount is allowed (RFE 2001535),
	 * we will un-mount the last entry in the MNTTAB that matches.
	 */
	if (mp == NULL) {
		/*
		 * Perhaps there is a bogus mnttab entry that
		 * can't be resolved:
		 */
		if ((mp = getmntlast(mntll, NULL, mname)) == NULL)
			/*
			 * assume it's a device (special) now
			 */
			mp = getmntlast(mntll, mname, NULL);
		if (mp) {
			/*
			 * Found it.
			 * This is a device. Now we want to know if
			 * it stackmounted on by something else.
			 * The original fix for bug 1103850 has a
			 * problem with lockfs (bug 1119731). This
			 * is a revised method.
			 */
			mountent_t *lmp;
			lmp = getmntlast(mntll, NULL, mp->ment.mnt_mountp);

			if (lmp && strcmp(lmp->ment.mnt_special,
			    mp->ment.mnt_special)) {
				errno = EBUSY;
				rpterr(mname);
				exit(1);
			}
		} else {
			fprintf(stderr, gettext(
			    "%s: warning: %s not in mnttab\n"),
			    myname, mname);
			if (Vflg)
				exit(1);
				/*
				 * same error as mount -V
				 * would give for unknown
				 * mount point
				 */
			mget.mnt_special = mget.mnt_mountp = mname;
		}
	}

	if (mp)
		doexec(&mp->ment);
	else
		doexec(&mget);

	return (0);
}

void
doexec(struct mnttab *ment)
{
	int 	ret;

#ifdef DEBUG
	if (dflg)
		fprintf(stderr, "%d: umounting %s\n",
		    getpid(), ment->mnt_mountp);
#endif

	/* try to exec the dependent portion */
	if ((ment->mnt_fstype != NULL) || Vflg) {
		char	full_path[FULLPATH_MAX];
		char	alter_path[FULLPATH_MAX];
		char	*newargv[ARGV_MAX];
		int 	ii;

		if (strlen(ment->mnt_fstype) > (size_t)FSTYPE_MAX) {
			fprintf(stderr, gettext(
			    "%s: FSType %s exceeds %d characters\n"),
			    myname, ment->mnt_fstype, FSTYPE_MAX);
			exit(1);
		}

		/* build the full pathname of the fstype dependent command. */
		sprintf(full_path, "%s/%s/%s", fs_path, ment->mnt_fstype,
		    myname);
		sprintf(alter_path, "%s/%s/%s", alt_path, ment->mnt_fstype,
		    myname);

		/*
		 * create the new arg list, and end the list with a
		 * null pointer
		 */
		ii = 2;
		if (oflg) {
			newargv[ii++] = "-o";
			newargv[ii++] = oarg;
		}
		if (dashflg) {
			newargv[ii++] = "--";
		}
		if (fflg) {
			newargv[ii++] = "-f";
		}
		newargv[ii++] = (ment->mnt_mountp)
		    ? ment->mnt_mountp : ment->mnt_special;
		newargv[ii] = NULL;

		/* set the new argv[0] to the filename */
		newargv[1] = myname;

		if (Vflg) {
			printf("%s", myname);
			for (ii = 2; newargv[ii]; ii++)
				printf(" %s", newargv[ii]);
			printf("\n");
			fflush(stdout);
			exit(0);
		}

		/* Try to exec the fstype dependent umount. */
		execv(full_path, &newargv[1]);
		if (errno == ENOEXEC) {
			newargv[0] = "sh";
			newargv[1] = full_path;
			execv("/sbin/sh", &newargv[0]);
		}
		newargv[1] = myname;
		execv(alter_path, &newargv[1]);
		if (errno == ENOEXEC) {
			newargv[0] = "sh";
			newargv[1] = alter_path;
			execv("/sbin/sh", &newargv[0]);
		}
		/* exec failed */
		if (errno != ENOENT) {
			fprintf(stderr, gettext("umount: cannot execute %s\n"),
			    full_path);
			exit(1);
		}
	}
	/*
	 * No fstype independent executable then.  We'll go generic
	 * from here.
	 */

	/* don't use -o with generic */
	if (oflg) {
		fprintf(stderr, gettext(
		    "%s: %s specific umount does not exist;"
		    " -o suboption ignored\n"),
		    myname, ment->mnt_fstype ? ment->mnt_fstype : "<null>");
	}

	signal(SIGHUP,  SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT,  SIG_IGN);
	/*
	 * Try to umount the mountpoint.
	 * If that fails, try the corresponding special.
	 * (This ordering is necessary for nfs umounts.)
	 * (for remote resources:  if the first umount returns EBUSY
	 * don't call umount again - umount() with a resource name
	 * will return a misleading error to the user
	 */
	if (fflg) {
		if (((ret = umount2(ment->mnt_mountp, MS_FORCE)) < 0) &&
		    (errno != EBUSY && errno != ENOTSUP &&
		    errno != EPERM))
			ret = umount2(ment->mnt_special, MS_FORCE);
	} else {
		if (((ret = umount2(ment->mnt_mountp, 0)) < 0) &&
		    (errno != EBUSY) && (errno != EPERM))
			ret = umount2(ment->mnt_special, 0);
	}

	if (ret < 0) {
		rpterr(ment->mnt_mountp);
		if (errno != EINVAL && errno != EFAULT)
			exit(1);

		exitcode = 1;
	}

	exit(exitcode);
}

void
rpterr(char *sp)
{
	switch (errno) {
	case EPERM:
		fprintf(stderr, gettext("%s: permission denied\n"), myname);
		break;
	case ENXIO:
		fprintf(stderr, gettext("%s: %s no device\n"), myname, sp);
		break;
	case ENOENT:
		fprintf(stderr,
		    gettext("%s: %s no such file or directory\n"),
		    myname, sp);
		break;
	case EINVAL:
		fprintf(stderr, gettext("%s: %s not mounted\n"), myname, sp);
		break;
	case EBUSY:
		fprintf(stderr, gettext("%s: %s busy\n"), myname, sp);
		break;
	case ENOTBLK:
		fprintf(stderr,
		    gettext("%s: %s block device required\n"), myname, sp);
		break;
	case ECOMM:
		fprintf(stderr,
		    gettext("%s: warning: broken link detected\n"), myname);
		break;
	default:
		perror(myname);
		fprintf(stderr, gettext("%s: cannot unmount %s\n"), myname, sp);
	}
}

void
usage(void)
{
	fprintf(stderr, gettext(
"Usage:\n%s [-f] [-V] [-o specific_options] {special | mount-point}\n"),
	    myname);
	fprintf(stderr, gettext(
"%s -a [-f] [-V] [-o specific_options] [mount_point ...]\n"), myname);
	exit(1);
}

void
mnterror(int flag)
{
	switch (flag) {
	case MNT_TOOLONG:
		fprintf(stderr,
		    gettext("%s: line in mnttab exceeds %d characters\n"),
		    myname, MNT_LINE_MAX-2);
		break;
	case MNT_TOOFEW:
		fprintf(stderr,
		    gettext("%s: line in mnttab has too few entries\n"),
		    myname);
		break;
	default:
		break;
	}
}

/*
 * Search the mlist linked list for the
 * first match of specp or mntp.  The list is expected to be in reverse
 * order of /etc/mnttab.
 * If both are specified, then both have to match.
 * Returns the (mountent_t *) of the match, otherwise returns NULL.
 */
mountent_t *
getmntlast(mountent_t *mlist, char *specp, char *mntp)
{
	int		mfound, sfound;

	for (/* */; mlist; mlist = mlist->link) {
		mfound = sfound = 0;
		if (mntp && (strcmp(mlist->ment.mnt_mountp, mntp) == 0)) {
			if (specp == NULL)
				return (mlist);
			mfound++;
		}
		if (specp && (strcmp(mlist->ment.mnt_special, specp) == 0)) {
			if (mntp == NULL)
				return (mlist);
			sfound++;
		}
		if (mfound && sfound)
			return (mlist);
	}
	return (NULL);
}



/*
 * Perform the parallel version of umount.  Returns 0 if no errors occurred,
 * non zero otherwise.
 */
int
parumount(char **mntlist, int count)
{
	int 		maxfd = OPEN_MAX;
	struct rlimit 	rl;
	mountent_t	**mntarray, **ml, *mp;

	/*
	 * If no mount points are specified and none were found in mnttab,
	 * then end it all here.
	 */
	if (count == 0 && mntll == NULL)
		return (0);

	/*
	 * This is the process scaling section.  After running a series
	 * of tests based on the number of simultaneous processes and
	 * processors available, optimum performance was achieved near or
	 * at (PROCN * 2).
	 */
	if ((maxrun = sysconf(_SC_NPROCESSORS_ONLN)) == -1)
		maxrun = 4;
	else
		maxrun = maxrun * 2 + 1;

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) == 0)
			maxfd = (int)rl.rlim_cur;
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	/*
	 * The parent needs to maintain 3 of its own fd's, plus 2 for
	 * each child (the stdout and stderr pipes).
	 */
	maxfd = (maxfd / 2) - 6;	/* 6 takes care of temporary  */
					/* periods of open fds */
	if (maxfd < maxrun)
		maxrun = maxfd;
	if (maxrun < 4)
		maxrun = 4;		/* sanity check */

	mntarray = make_mntarray(mntlist, count);

	if (listlength == 0) {
		if (count == 0)		/* not an error, just none found */
			return (0);
		fprintf(stderr, gettext("%s: no valid entries found in %s\n"),
		    myname, mnttab);
		return (1);
	}

	/*
	 * Sort the entries based on their mount level only if lofs's are
	 * not present.
	 */
	if (lofscnt == 0) {
		qsort((void *)mntarray, listlength, sizeof (mountent_t *),
		    mcompar);
		/*
		 * If we do not detect a lofs by now, we never will.
		 */
		lofscnt = -1;
	}
	/*
	 * Now link them up so that a given pid is easier to find when
	 * we go to clean up after they are done.
	 */
	mntll = mntarray[0];
	for (ml = mntarray; mp = *ml; /* */)
		mp->link = *++ml;

	/*
	 * Try to handle interrupts in a reasonable way.
	 */
	sigset(SIGHUP, cleanup);
	sigset(SIGQUIT, cleanup);
	sigset(SIGINT, cleanup);

	do_umounts(mntarray);	/* do the umounts */
	return (exitcode);
}

/*
 * Returns a mountent_t array based on mntlist.  If mntlist is NULL, then
 * it returns all mnttab entries with a few exceptions.  Sets the global
 * variable listlength to the number of entries in the array.
 */
mountent_t **
make_mntarray(char **mntlist, int count)
{
	mountent_t 	*mp, **mpp;
	int 		ndx;
	char		*cp;

	if (count > 0)
		listlength = count;

	mpp = (mountent_t **)malloc(sizeof (*mp) * (listlength + 1));
	if (mpp == NULL)
		nomem();

	if (count == 0) {
		if (mntll == NULL) {	/* no entries? */
			listlength = 0;
			return (NULL);
		}
		/*
		 * No mount list specified: take all mnttab mount points
		 * except for a few cases.
		 */
		for (ndx = 0, mp = mntll; mp; mp = mp->link) {
			if (fsstrinlist(mp->ment.mnt_mountp, keeplist))
				continue;
			mp->mlevel = fsgetmlevel(mp->ment.mnt_mountp);
			if (mp->ment.mnt_fstype &&
			    (strcmp(mp->ment.mnt_fstype, MNTTYPE_LOFS) == 0))
				lofscnt++;

			mpp[ndx++] = mp;
		}
		mpp[ndx] = NULL;
		listlength = ndx;
		return (mpp);
	}

	/*
	 * A list of mount points was specified on the command line.
	 * Build an array out of these.
	 */
	for (ndx = 0; count--; ) {
		cp = *mntlist++;
		if (realpath(cp, resolve) == NULL) {
			fprintf(stderr,
			    gettext("%s: warning: can't resolve %s\n"),
			    myname, cp);
			exitcode = 1;
			mp = getmntlast(mntll, NULL, cp); /* try anyways */
		} else
			mp = getmntlast(mntll, NULL, resolve);
		if (mp == NULL) {
			struct mnttab mnew;
			/*
			 * Then we've reached the end without finding
			 * what we are looking for, but we still have to
			 * try to umount it: append it to mntarray.
			 */
			fprintf(stderr, gettext(
			    "%s: warning: %s not found in %s\n"),
			    myname, resolve, mnttab);
			exitcode = 1;
			mntnull(&mnew);
			mnew.mnt_special = mnew.mnt_mountp = strdup(resolve);
			if (mnew.mnt_special == NULL)
				nomem();
			mp = new_mountent(&mnew);
		}
		if (mp->ment.mnt_fstype &&
		    (strcmp(mp->ment.mnt_fstype, MNTTYPE_LOFS) == 0))
			lofscnt++;

		mp->mlevel = fsgetmlevel(mp->ment.mnt_mountp);
		mpp[ndx++] = mp;
	}
	mpp[ndx] = NULL;
	listlength = ndx;
	return (mpp);
}

/*
 * Returns the tail of a linked list of all mnttab entries.  I.e, it's faster
 * to return the mnttab in reverse order.
 * Sets listlength to the number of entries in the list.
 * Returns NULL if none are found.
 */
mountent_t *
getmntall(void)
{
	FILE		*fp;
	mountent_t	*mtail;
	int		cnt = 0, ret;
	struct mnttab	mget;

	if ((fp = fopen(mnttab, "r")) == NULL) {
		fprintf(stderr, gettext("%s: warning cannot open %s\n"),
		    myname, mnttab);
		return (0);
	}
	mtail = NULL;

	while ((ret = getmntent(fp, &mget)) != -1) {
		mountent_t	*mp;

		if (ret > 0) {
			mnterror(ret);
			continue;
		}

		mp = new_mountent(&mget);
		mp->link = mtail;
		mtail = mp;
		cnt++;
	}
	fclose(fp);
	if (mtail == NULL) {
		listlength = 0;
		return (NULL);
	}
	listlength = cnt;
	return (mtail);
}

void
do_umounts(mountent_t **mntarray)
{
	mountent_t *mp, *mpprev, **ml = mntarray;
	int	cnt = listlength;

	/*
	 * Main loop for the forked children:
	 */
	for (mpprev = *ml; mp = *ml; mpprev = mp, ml++, cnt--) {
		pid_t	pid;

		/*
		 * Check to see if we cross a mount level: e.g.,
		 * /a/b/c -> /a/b.  If so, we need to wait for all current
		 * umounts to finish before umounting the rest.
		 *
		 * Also, we unmount serially as long as there are lofs's
		 * to mount to avoid improper umount ordering.
		 */
		if (mp->mlevel < mpprev->mlevel || lofscnt > 0)
			while (nrun > 0 && (dowait() != -1))
				;

		if (lofscnt == 0) {
			/*
			 * We can now go to parallel umounting.
			 */
			qsort((void *)ml, cnt, sizeof (mountent_t *), mcompar);
			mp = *ml;	/* possible first entry */
			lofscnt--;	/* so we don't do this again */
		}

		while (setup_iopipe(mp) == -1 && (dowait() != -1))
			;

		while (nrun >= maxrun && (dowait() != -1))	/* throttle */
			;

		if ((pid = fork()) == -1) {
			perror("fork");
			cleanup(-1);
			/* not reached */
		}
#ifdef DEBUG
		if (dflg && pid > 0) {
			fprintf(stderr, "parent %d: umounting %d %s\n",
			    getpid(), pid, mp->ment.mnt_mountp);
		}
#endif
		if (pid == 0) {		/* child */
			signal(SIGHUP, SIG_IGN);
			signal(SIGQUIT, SIG_IGN);
			signal(SIGINT, SIG_IGN);
			setup_output(mp);
			doexec(&mp->ment);
			perror("exec");
			exit(1);
		}

		/* parent */
		(void) close(mp->sopipe[WRPIPE]);
		(void) close(mp->sepipe[WRPIPE]);
		mp->pid = pid;
		nrun++;
	}
	cleanup(0);
}

/*
 * cleanup the existing children and exit with an error
 * if asig != 0.
 */
void
cleanup(int asig)
{
	/*
	 * Let the stragglers finish.
	 */
	while (nrun > 0 && (dowait() != -1))
		;
	if (asig != 0)
		exit(1);
}


/*
 * Waits for 1 child to die.
 *
 * Returns -1 if no children are left to wait for.
 * Returns 0 if a child died without an error.
 * Returns 1 if a child died with an error.
 * Sets the global exitcode if an error occurred.
 */
int
dowait(void)
{
	int		wstat, child, ret;
	mountent_t 	*mp, *prevp;

	if ((child = wait(&wstat)) == -1)
		return (-1);

	if (WIFEXITED(wstat))		/* this should always be true */
		ret = WEXITSTATUS(wstat);
	else
		ret = 1;		/* assume some kind of error */
	nrun--;
	if (ret)
		exitcode = 1;

	/*
	 * Find our child so we can process its std output, if any.
	 * This search gets smaller and smaller as children are cleaned
	 * up.
	 */
	for (prevp = NULL, mp = mntll; mp; mp = mp->link) {
		if (mp->pid != child) {
			prevp = mp;
			continue;
		}
		/*
		 * Found: let's remove it from this list.
		 */
		if (prevp) {
			prevp->link = mp->link;
			mp->link = NULL;
		}
		break;
	}

	if (mp == NULL) {
		/*
		 * This should never happen.
		 */
#ifdef DEBUG
		fprintf(stderr, gettext(
		    "%s: unknown child %d\n"), myname, child);
#endif
		exitcode = 1;
		return (1);
	}
	doio(mp);	/* Any output? */

	if (mp->ment.mnt_fstype &&
	    (strcmp(mp->ment.mnt_fstype, MNTTYPE_LOFS) == 0))
		lofscnt--;

	return (ret);
}

static const mountent_t zmount = { 0 };

mountent_t *
new_mountent(struct mnttab *ment)
{
	mountent_t *new;

	new = (mountent_t *)malloc(sizeof (*new));
	if (new == NULL)
		nomem();

	*new = zmount;
	if (ment->mnt_special &&
	    (new->ment.mnt_special = strdup(ment->mnt_special)) == NULL)
		nomem();
	if (ment->mnt_mountp &&
	    (new->ment.mnt_mountp = strdup(ment->mnt_mountp)) == NULL)
		nomem();
	if (ment->mnt_fstype &&
	    (new->ment.mnt_fstype = strdup(ment->mnt_fstype)) == NULL)
		nomem();
	return (new);
}


/*
 * Sort in descending order of "mount level".  For example, /a/b/c is
 * placed before /a/b .
 */
int
mcompar(const void *a, const void *b)
{
	mountent_t *a1, *b1;

	a1 = *(mountent_t **)a;
	b1 = *(mountent_t **)b;
	return (b1->mlevel - a1->mlevel);
}

/*
 * The purpose of this routine is to form stdout and stderr
 * pipes for the children's output.  The parent then reads and writes it
 * out it serially in order to ensure that the output is
 * not garbled.
 */

int
setup_iopipe(mountent_t *mp)
{
	/*
	 * Make a stdout and stderr pipe.  This should never fail.
	 */
	if (pipe(mp->sopipe) == -1)
		return (-1);
	if (pipe(mp->sepipe) == -1) {
		(void) close(mp->sopipe[RDPIPE]);
		(void) close(mp->sopipe[WRPIPE]);
		return (-1);
	}
	/*
	 * Don't block on an empty pipe.
	 */
	(void) fcntl(mp->sopipe[RDPIPE], F_SETFL, O_NDELAY|O_NONBLOCK);
	(void) fcntl(mp->sepipe[RDPIPE], F_SETFL, O_NDELAY|O_NONBLOCK);
	return (0);
}

/*
 * Called by a child to attach its stdout and stderr to the write side of
 * the pipes.
 */
void
setup_output(mountent_t *mp)
{
	(void) close(fileno(stdout));
	(void) dup(mp->sopipe[WRPIPE]);
	(void) close(mp->sopipe[WRPIPE]);

	(void) close(fileno(stderr));
	(void) dup(mp->sepipe[WRPIPE]);
	(void) close(mp->sepipe[WRPIPE]);
}

/*
 * Parent uses this to print any stdout or stderr output issued by
 * the child.
 */
static void
doio(mountent_t *mp)
{
	int bytes;

	while ((bytes = read(mp->sepipe[RDPIPE], ibuf, sizeof (ibuf))) > 0)
		write(fileno(stderr), ibuf, bytes);
	while ((bytes = read(mp->sopipe[RDPIPE], ibuf, sizeof (ibuf))) > 0)
		write(fileno(stdout), ibuf, bytes);

	(void) close(mp->sopipe[RDPIPE]);
	(void) close(mp->sepipe[RDPIPE]);
}

void
nomem(void)
{
	fprintf(stderr, gettext("%s: out of memory\n"), myname);
	/*
	 * Let the stragglers finish.
	 */
	while (nrun > 0 && (dowait() != -1))
		;
	exit(1);
}
