/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980, 1986, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <ctype.h>	/* use isdigit macro rather than 4.1 libc routine */
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <malloc.h>
#include <ustat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mnttab.h>
#include <sys/signal.h>
#include <sys/vfstab.h>
#include <sys/fs/udf_volume.h>
#include "fsck.h"
#include <locale.h>

extern int32_t	writable(char *);
extern void	pfatal(char *, ...);
extern void	printfree();
extern void	pwarn(char *, ...);

extern void	pass1();
extern void	dofreemap();
extern void	dolvint();
extern char	*getfullblkname();
extern char	*getfullrawname();

static int	mflag = 0;		/* sanity check only */

char	*mntopt();
void	catch(), catchquit(), voidquit();
int	returntosingle;
static void	checkfilesys();
static void	check_sanity();
static void	usage();

static char *subopts [] = {
#define	PREEN		0
	"p",
#define	DEBUG		1
	"d",
#define	READ_ONLY	2
	"r",
#define	ONLY_WRITES	3
	"w",
#define	FORCE		4	/* force checking, even if clean */
	"f",
#define	STATS		5	/* print time and busy stats */
	"s",
	NULL
};

uint32_t ecma_version = 2;

int
main(int argc, char *argv[])
{
	int	c;
	char	*suboptions,	*value;
	int	suboption;

	(void) setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "mnNo:VyYz")) != EOF) {
		switch (c) {

		case 'm':
			mflag++;
			break;

		case 'n':	/* default no answer flag */
		case 'N':
			nflag++;
			yflag = 0;
			break;

		case 'o':
			/*
			 * udfs specific options.
			 */
			suboptions = optarg;
			while (*suboptions != '\0') {
				suboption = getsubopt(&suboptions,
						subopts, &value);
				switch (suboption) {

				case PREEN:
					preen++;
					break;

				case DEBUG:
					debug++;
					break;

				case READ_ONLY:
					break;

				case ONLY_WRITES:
					/* check only writable filesystems */
					wflag++;
					break;

				case FORCE:
					fflag++;
					break;

				case STATS:
					sflag++;
					break;

				default:
					usage();
				}
			}
			break;

		case 'V':
			{
				int	opt_count;
				char	*opt_text;

				(void) fprintf(stdout, "fsck -F udfs ");
				for (opt_count = 1; opt_count < argc;
								opt_count++) {
					opt_text = argv[opt_count];
					if (opt_text)
						(void) fprintf(stdout, " %s ",
								opt_text);
				}
				(void) fprintf(stdout, "\n");
			}
			break;

		case 'y':	/* default yes answer flag */
		case 'Y':
			yflag++;
			nflag = 0;
			break;

		case '?':
			usage();
		}
	}
	argc -= optind;
	argv = &argv[optind];
	rflag++; /* check raw devices */
	if (signal(SIGINT, SIG_IGN) != SIG_IGN) {
		(void) signal(SIGINT, catch);
	}

	if (preen) {
		(void) signal(SIGQUIT, catchquit);
	}

	if (argc) {
		while (argc-- > 0) {
			if (wflag && !writable(*argv)) {
				(void) fprintf(stderr,
					gettext("not writeable '%s'\n"), *argv);
				argv++;
			} else
				checkfilesys(*argv++);
		}
		exit(exitstat);
	}
	return (0);
}


static void
checkfilesys(char *filesys)
{
	char *devstr;

	mountfd = -1;
	mountedfs = 0;
	iscorrupt = 1;

	if ((devstr = setup(filesys)) == 0) {
		if (iscorrupt == 0)
			return;
		if (preen)
			pfatal(gettext("CAN'T CHECK FILE SYSTEM."));
		if ((exitstat == 0) && (mflag))
			exitstat = 32;
		exit(exitstat);
	}
	else
		devname = devstr;
	if (mflag)
		check_sanity(filesys);	/* this never returns */
	iscorrupt = 0;
	/*
	 * 1: scan inodes tallying blocks used
	 */
	if (preen == 0) {
		if (mountedfs)
			(void) printf(gettext("** Currently Mounted on %s\n"),
				mountpoint);
		if (mflag) {
			(void) printf(
				gettext("** Phase 1 - Sanity Check only\n"));
			return;
		} else
			(void) printf(
				gettext("** Phase 1 - Check Directories "
				"and Blocks\n"));
	}
	pass1();
	if (sflag) {
		if (preen)
			(void) printf("%s: ", devname);
		else
			(void) printf("** ");
	}
	if (debug)
		(void) printf("pass1 isdirty %d\n", isdirty);
	if (debug)
		printfree();
	dofreemap();
	dolvint();

	/*
	 * print out summary statistics
	 */
	pwarn(gettext("%d files, %d dirs, %d used, %d free\n"), n_files, n_dirs,
		n_blks, part_len - n_blks);
	if (iscorrupt)
		exitstat = 36;
	if (!fsmodified)
		return;
	if (!preen)
		(void) printf(
			gettext("\n***** FILE SYSTEM WAS MODIFIED *****\n"));

	if (mountedfs) {
		exitstat = 40;
	}
}


/*
 * exit 0 - file system is unmounted and okay
 * exit 32 - file system is unmounted and needs checking
 * exit 33 - file system is mounted
 *	for root file system
 * exit 34 - cannot stat device
 */

static void
check_sanity(char *filename)
{
	struct stat stbd, stbr;
	struct ustat usb;
	char *devname;
	struct vfstab vfsbuf;
	FILE *vfstab;
	int is_root = 0;
	int is_usr = 0;
	int is_block = 0;

	if (stat(filename, &stbd) < 0) {
		(void) fprintf(stderr,
			gettext("udfs fsck: sanity check failed : cannot stat "
			"%s\n"), filename);
		exit(34);
	}

	if ((stbd.st_mode & S_IFMT) == S_IFBLK)
		is_block = 1;
	else if ((stbd.st_mode & S_IFMT) == S_IFCHR)
		is_block = 0;
	else {
		(void) fprintf(stderr,
			gettext("udfs fsck: sanity check failed: %s not "
			"block or character device\n"), filename);
		exit(34);
	}

	/*
	 * Determine if this is the root file system via vfstab. Give up
	 * silently on failures. The whole point of this is not to care
	 * if the root file system is already mounted.
	 *
	 * XXX - similar for /usr. This should be fixed to simply return
	 * a new code indicating, mounted and needs to be checked.
	 */
	if ((vfstab = fopen(VFSTAB, "r")) != 0) {
		if (getvfsfile(vfstab, &vfsbuf, "/") == 0) {
			if (is_block)
				devname = vfsbuf.vfs_special;
			else
				devname = vfsbuf.vfs_fsckdev;
			if (stat(devname, &stbr) == 0)
				if (stbr.st_rdev == stbd.st_rdev)
					is_root = 1;
		}
		if (getvfsfile(vfstab, &vfsbuf, "/usr") == 0) {
			if (is_block)
				devname = vfsbuf.vfs_special;
			else
				devname = vfsbuf.vfs_fsckdev;
			if (stat(devname, &stbr) == 0)
				if (stbr.st_rdev == stbd.st_rdev)
					is_usr = 1;
		}
	}


	/*
	 * XXX - only works if filename is a block device or if
	 * character and block device has the same dev_t value
	 */
	if (is_root == 0 && is_usr == 0 && ustat(stbd.st_rdev, &usb) == 0) {
		(void) fprintf(stderr,
			gettext("udfs fsck: sanity check: %s "
			"already mounted\n"), filename);
		exit(33);
	}

	if (lvintp->lvid_int_type == LVI_CLOSE) {
		(void) fprintf(stderr,
			gettext("udfs fsck: sanity check: %s okay\n"),
			filename);
	} else {
		(void) fprintf(stderr,
			gettext("udfs fsck: sanity check: %s needs checking\n"),
			filename);
		exit(32);
	}
	exit(0);
}

char *
unrawname(char *name)
{
	char *dp;


	if ((dp = getfullblkname(name)) == NULL)
		return ("");
	return (dp);
}

char *
rawname(char *name)
{
	char *dp;

	if ((dp = getfullrawname(name)) == NULL)
		return ("");
	return (dp);
}

char *
hasvfsopt(struct vfstab *vfs, char *opt)
{
	char *f, *opts;
	static char *tmpopts;

	if (vfs->vfs_mntopts == NULL)
		return (NULL);
	if (tmpopts == 0) {
		tmpopts = (char *)calloc(256, sizeof (char));
		if (tmpopts == 0)
			return (0);
	}
	(void) strncpy(tmpopts, vfs->vfs_mntopts, (sizeof (tmpopts) - 1));
	opts = tmpopts;
	f = mntopt(&opts);
	for (; *f; f = mntopt(&opts)) {
		if (strncmp(opt, f, strlen(opt)) == 0)
			return (f - tmpopts + vfs->vfs_mntopts);
	}
	return (NULL);
}

static void
usage()
{
	(void) fprintf(stderr, gettext("udfs usage: fsck [-F udfs] "
		"[generic options] [-o p,w,s] [special ....]\n"));
	exit(31+1);
}
