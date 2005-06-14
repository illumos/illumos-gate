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

/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fastfs
 *	user interface to dio (delayed IO) functionality
 */
#include <stdio.h>
#include <locale.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/filio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/*
 * make vfstab look like fstab
 */
#include <sys/mnttab.h>

#define	fstab		vfstab
#define	FSTAB		VFSTAB
#define	fs_spec		vfs_special
#define	fs_file		vfs_mountp
#define	setmntent	fopen
#define	endmntent	fclose
#define	mntent		mnttab
#define	mnt_fsname	mnt_special
#define	mnt_dir		mnt_mountp
#define	mnt_type	mnt_fstype
#define	MNTTYPE_42	"ufs"
#define	MNTINFO_DEV	"dev"
#define	MOUNTED		MNTTAB

static struct mntent *
mygetmntent(f, name)
	FILE *f;
	char *name;
{
	static struct mntent mt;
	int status;

	if ((status = getmntent(f, &mt)) == 0)
		return (&mt);

	switch (status) {
	case EOF:	break;		/* normal exit condition */
	case MNT_TOOLONG:
		(void) fprintf(stderr, "%s has a line that is too long\n",
		    name);
		break;
	case MNT_TOOMANY:
		(void) fprintf(stderr, "%s has a line with too many entries\n",
		    name);
		break;
	case MNT_TOOFEW:
		(void) fprintf(stderr, "%s has a line with too few entries\n",
		    name);
		break;
	default:
		(void) fprintf(stderr,
		    "Unknown return code, %d, from getmntent() on %s\n",
		    status, name);
		break;
	}

	return (NULL);
}

/*
 * -a = all
 * -f = fast
 * -s = safe
 */
static int all	= 0;
static int fast	= 0;
static int safe	= 0;

/*
 * exitstatus
 *	0 all ok
 *	1 internal error
 *	2 system call error
 */
static int exitstatus	= 0;

/*
 * list of filenames
 */
struct filename {
	struct filename	*fn_next;
	char		*fn_name;
};
static struct filename	*fnanchor	= 0;

/*
 * for prettyprint
 */
static int firsttime	= 0;

/*
 * no safe's printed
 */
static int no_safes_printed	= 0;

static void exitusage(void);
static void printstatusline(char *, char *);
static void printstatus(char *);
static void getmntnames(void);
static void getcmdnames(int, char **, int);
static void setdio(char *);

int
main(int argc, char **argv)
{
	int		c;
	struct filename	*fnp;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	exitstatus = 0;

	/*
	 * process command line
	 */
	opterr = 0;
	optarg = 0;

	while ((c = getopt(argc, argv, "afs")) != -1)
		switch (c) {
		case 'a':
			all = 1;
			break;
		case 'f':
			fast = 1;
			break;
		case 's':
			safe = 1;
			break;
		default:
			exitusage();
			break;
		}

	if (argc == 1) {
		no_safes_printed = 1;
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
		if (fast || safe)
			setdio(fnp->fn_name);
		else
			printstatus(fnp->fn_name);
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
static void
exitusage(void)
{
	(void) fprintf(stderr, "usage: fastfs [-vfs] [-a] [file system ...]\n");
	exit(1);
}
/*
 * printstatusline
 * 	prettyprint the status line
 */
static void
printstatusline(fn, mode)
	char	*fn;
	char	*mode;
{
	if (firsttime++ == 0)
		(void) printf("%-20s %-10s\n", "Filesystem", "Mode");
	(void) printf("%-20s %-10s\n", fn, mode);
}
/*
 * printstatus
 *	get and prettyprint file system lock status
 */
static void
printstatus(fn)
	char		*fn;
{
	int		fd;
	int		dioval;

	fd = open(fn, O_RDONLY);
	if (fd == -1) {
		perror(fn);
		exitstatus = 2;
		return;
	}
	if (ioctl(fd, _FIOGDIO, &dioval) == -1) {
		perror(fn);
		(void) close(fd);
		exitstatus = 2;
		return;
	}
	if (dioval)
		printstatusline(fn, "fast");
	else
		if (no_safes_printed == 0)
			printstatusline(fn, "safe");
	(void) close(fd);
}
/*
 * getmntnames
 *	file names from /etc/mtab
 */
static void
getmntnames(void)
{
	int		fnlen;
	struct filename	*fnp;
	struct filename	*fnpc;
	FILE		*mnttab;
	struct mntent	*mntp;

	fnpc = fnanchor;

	mnttab = setmntent(MOUNTED, "r");
	while ((mntp = mygetmntent(mnttab, MOUNTED)) != NULL) {
		if (mntp->mnt_type == (char *)0 ||
		    strcmp(mntp->mnt_type, MNTTYPE_42) != 0)
			continue;
		if (mntp->mnt_dir == (char *)0)
			mntp->mnt_dir = "";
		fnlen = strlen(mntp->mnt_dir) + 1;
		fnp = (struct filename *)malloc(sizeof (struct filename));
		fnp->fn_name = malloc((u_int)fnlen);
		(void) strcpy(fnp->fn_name, mntp->mnt_dir);
		fnp->fn_next = NULL;
		if (fnpc)
			fnpc->fn_next = fnp;
		else
			fnanchor = fnp;
		fnpc = fnp;
	}
	(void) endmntent(mnttab);
}
/*
 * getcmdnames
 *	file names from command line
 */
static void
getcmdnames(argc, argv, i)
	int	argc;
	char	**argv;
	int	i;
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
/*
 * setdio
 *	set the dio mode
 */
static void
setdio(fn)
	char		*fn;
{
	int		fd;
	int		dioval;

	fd = open(fn, O_RDONLY);
	if (fd == -1) {
		perror(fn);
		exitstatus = 2;
		return;
	}

	if (fast)
		dioval = 1;
	if (safe)
		dioval = 0;

	if (ioctl(fd, _FIOSDIO, &dioval) == -1) {
		perror(fn);
		exitstatus = 2;
	}
	(void) close(fd);
}
