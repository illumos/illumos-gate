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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lockfs
 *	user interface to lockfs functionality
 */
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <errno.h>
#include <sys/lockfs.h>
#include <sys/filio.h>

#define	bzero(s, n)	memset(s, 0, n);

/*
 * command line processing
 */
extern char	*optarg;
extern int	optind;
extern int	opterr;

extern void exit();

static void exitusage();
static void printstatusline(char *, char *, char *);
static void printstatus(char *);
static void flushfs(char *);
static void lockfs(char *);
static void getmntnames();
static void getcmdnames(int, char **, int);

/*
 * -a = all
 * -v = verbose
 */
int all		= 0;
int verbose	= 0;

/*
 * exitstatus
 *	0 all ok
 *	1 internal error
 *	2 system call error
 */
int exitstatus	= 0;

/*
 * list of filenames
 */
struct filename {
	struct filename	*fn_next;
	char		*fn_name;
};
struct filename	*fnanchor	= 0;

/*
 * default request is `file system lock status'
 * default lock type is `unlock'
 * -wnduhfe changes them
 */
int request	= _FIOLFSS;
ushort_t	lock	= LOCKFS_ULOCK;

/*
 * default comment is null
 *	-c changes it
 */
caddr_t comment	= 0;
ulong_t	comlen	= 0;

/*
 * for prettyprint
 */
int firsttime	= 0;

/*
 * no unlocks printed
 */
int no_unlocks_printed	= 0;

/*
 * file system was modified during hlock/wlock/elock
 */
#define	LOCKWARN(FN, S)	\
{ \
	if (verbose) \
		printf("WARNING: %s was modified while %s locked\n", FN, S); \
	exitstatus = 2; \
}

/*
 * forward reference
 */
char	*malloc();

int
main(int argc, char *argv[])
{
	int		c;
	struct filename	*fnp;

	exitstatus = 0;

	/*
	 * process command line
	 */
	opterr = 0;
	optarg = 0;

	while ((c = getopt(argc, argv, "vfwnduheac:")) != -1)
		switch (c) {
		case 'v':
			verbose = 1;
			break;
		case 'f':
			request = _FIOFFS;
			break;
		case 'w':
			lock    = LOCKFS_WLOCK;
			request = _FIOLFS;
			break;
		case 'n':
			lock    = LOCKFS_NLOCK;
			request = _FIOLFS;
			break;
		case 'd':
			lock    = LOCKFS_DLOCK;
			request = _FIOLFS;
			break;
		case 'h':
			lock    = LOCKFS_HLOCK;
			request = _FIOLFS;
			break;
		case 'e':
			lock	= LOCKFS_ELOCK;
			request = _FIOLFS;
			break;
		case 'u':
			lock    = LOCKFS_ULOCK;
			request = _FIOLFS;
			break;
		case 'a':
			all = 1;
			break;
		case 'c':
			comment = optarg;
			comlen  = strlen(optarg)+1;
			request = _FIOLFS;
			break;
		default:
			exitusage();
			break;
		}

	if (argc == 1) {
		no_unlocks_printed = 1;
		all = 1;
	}

	if (all)
		/*
		 * use /etc/mtab
		 */
		getmntnames();
	else
		/*
		 * use command line
		 */
		getcmdnames(argc, argv, optind);

	/*
	 * for each filename, doit
	 */
	for (fnp = fnanchor; fnp; fnp = fnp->fn_next) {
		switch (request) {
		case _FIOLFSS:
			printstatus(fnp->fn_name);
			break;
		case _FIOLFS:
			lockfs(fnp->fn_name);
			break;
		case _FIOFFS:
			flushfs(fnp->fn_name);
			break;
		default:
			break;
		}
	}

	/*
	 * all done
	 */
	return (exitstatus);
}
/*
 * exitusage
 *	bad command line, give hint
 */
void
exitusage()
{
	printf("usage: lockfs [-dfhnuw] [-c string] [-a] [file system ...]\n");
	exit(1);
}
/*
 * printstatusline
 * 	prettyprint the status line
 */
void
printstatusline(char *fn, char *locktype, char *comment)
{
	if (firsttime++ == 0)
		printf("%-20s %-10s %s\n", "Filesystem", "Locktype", "Comment");
	printf("%-20s %-10s %s\n", fn, locktype, comment);
}
/*
 * printstatus
 *	get and prettyprint file system lock status
 */
void
printstatus(char *fn)
{
	int		fd;
	int		fsmod	= 0;
	char		*locktype;
	char		commentbuffer[LOCKFS_MAXCOMMENTLEN+1];
	struct lockfs	lf;

	fd = open64(fn, O_RDONLY);
	if (fd == -1) {
		if (errno == EIO)
			printstatusline(fn, "EIO", "May be hard locked");
		else
			perror(fn);
		exitstatus = 2;
		return;
	}

	bzero((caddr_t)&lf, sizeof (struct lockfs));

	lf.lf_flags   = LOCKFS_MOD;
	lf.lf_comlen  = LOCKFS_MAXCOMMENTLEN;
	lf.lf_comment = commentbuffer;

	if (ioctl(fd, _FIOLFSS, &lf) == -1) {
		perror(fn);
		close(fd);
		exitstatus = 2;
		return;
	}
	switch (lf.lf_lock) {
	case LOCKFS_ULOCK:
		if (no_unlocks_printed)
			goto out;
		if (LOCKFS_IS_BUSY(&lf))
			locktype = "(unlock)";
		else
			locktype = "unlock";
		break;
	case LOCKFS_WLOCK:
		if (LOCKFS_IS_BUSY(&lf))
			locktype = "(write)";
		else {
			locktype = "write";
			fsmod = LOCKFS_IS_MOD(&lf);
		}
		break;
	case LOCKFS_NLOCK:
		if (LOCKFS_IS_BUSY(&lf))
			locktype = "(name)";
		else
			locktype = "name";
		break;
	case LOCKFS_DLOCK:
		locktype = "delete";
		if (LOCKFS_IS_BUSY(&lf))
			locktype = "(delete)";
		else
			locktype = "delete";
		break;
	case LOCKFS_HLOCK:
		if (LOCKFS_IS_BUSY(&lf))
			locktype = "(hard)";
		else {
			locktype = "hard";
			fsmod = LOCKFS_IS_MOD(&lf);
		}
		break;
	case LOCKFS_ELOCK:
		if (LOCKFS_IS_BUSY(&lf))
			locktype = "(error)";
		else {
			locktype = "error";
			fsmod = LOCKFS_IS_MOD(&lf);
		}
		break;
	default:
		if (LOCKFS_IS_BUSY(&lf))
			locktype = "(unknown)";
		else
			locktype = "unknown";
		break;
	}
	lf.lf_comment[lf.lf_comlen] = '\0';
	printstatusline(fn, locktype, lf.lf_comment);
	if (fsmod)
		LOCKWARN(fn, locktype);
out:
	close(fd);
}
/*
 * flushfs
 *	push and invalidate at least the data that is *currently* dirty
 */
void
flushfs(char *fn)
{
	int		fd;

	fd = open64(fn, O_RDONLY);
	if (fd == -1) {
		perror(fn);
		exitstatus = 2;
		return;
	}

	if (ioctl(fd, _FIOFFS, NULL) == -1) {
		perror(fn);
		close(fd);
		exitstatus = 2;
		return;
	}
	close(fd);
}
/*
 * lockfs
 *	lock the file system
 */
void
lockfs(char *fn)
{
	int		fd;
	struct lockfs	lf;

	fd = open64(fn, O_RDONLY);
	if (fd == -1) {
		perror(fn);
		exitstatus = 2;
		return;
	}

	bzero((caddr_t)&lf, sizeof (struct lockfs));

	lf.lf_flags = LOCKFS_MOD;
	if (ioctl(fd, _FIOLFSS, &lf) == -1) {
		perror(fn);
		close(fd);
		exitstatus = 2;
		return;
	}

	if (!LOCKFS_IS_BUSY(&lf) && LOCKFS_IS_MOD(&lf)) {
		if (LOCKFS_IS_HLOCK(&lf))
			LOCKWARN(fn, "hard");
		if (LOCKFS_IS_ELOCK(&lf))
			LOCKWARN(fn, "error");
		if (LOCKFS_IS_WLOCK(&lf))
			LOCKWARN(fn, "write");
	}

	lf.lf_lock	= lock;
	lf.lf_flags	= 0;
	lf.lf_key	= lf.lf_key;
	lf.lf_comment	= comment;
	lf.lf_comlen	= (comment) ? strlen(comment)+1 : 0;

	if (ioctl(fd, _FIOLFS, &lf) == -1) {
		perror(fn);
		close(fd);
		exitstatus = 2;
		return;
	}
	close(fd);
}
/*
 * getmntnames
 *	file names from /etc/mtab
 */
void
getmntnames()
{
	int		fnlen;
	struct filename	*fnp;
	struct filename	*fnpc;
	FILE		*mnttab;
	struct mnttab	mnt, *mntp = &mnt;

	fnpc = fnanchor;

	if ((mnttab = fopen(MNTTAB, "r")) == NULL) {
		fprintf(stderr, "Can't open %s\n", MNTTAB);
		perror(MNTTAB);
		exit(32);
	}
	while ((getmntent(mnttab, mntp)) == 0) {
		if (strcmp(mntp->mnt_fstype, MNTTYPE_UFS) != 0)
			continue;
		fnlen = strlen(mntp->mnt_mountp) + 1;
		fnp = (struct filename *)malloc(sizeof (struct filename));
		fnp->fn_name = malloc((uint_t)fnlen);
		strcpy(fnp->fn_name, mntp->mnt_mountp);
		fnp->fn_next = NULL;
		if (fnpc)
			fnpc->fn_next = fnp;
		else
			fnanchor = fnp;
		fnpc = fnp;
	}
	fclose(mnttab);
}
/*
 * getcmdnames
 *	file names from command line
 */
void
getcmdnames(int argc, char **argv, int i)
{
	struct filename	*fnp;
	struct filename	*fnpc;

	for (fnpc = fnanchor; i < argc; ++i) {
		fnp = (struct filename *)malloc(sizeof (struct filename));
		fnp->fn_name = *(argv+i);
		fnp->fn_next = NULL;
		if (fnpc)
			fnpc->fn_next = fnp;
		else
			fnanchor = fnp;
		fnpc = fnp;
	}
}
