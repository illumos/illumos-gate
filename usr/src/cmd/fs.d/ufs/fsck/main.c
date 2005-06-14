/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/int_types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>

#define	bcopy(f, t, n)    memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mnttab.h>
#include <sys/signal.h>
#include <string.h>
#include <ctype.h>	/* use isdigit macro rather than 4.1 libc routine */
#include "fsck.h"
#include <sys/vfstab.h>
#include <sys/ustat.h>
#include <sys/statvfs.h>
#include <errno.h>

int	mflag = 0;		/* sanity check only */
char	hotroot;

uint_t largefile_count = 0;	/* global largefile counter */

extern int	optind;
extern char	*optarg;

char	*mntopt();
char	*malloc();
void	catch(), catchquit(), voidquit();
int	returntosingle;
void	checkfilesys();
void	update_lf();
void	main();
void	check_sanity();
void	usage();
struct dinode *getnextinode();

char *subopts [] = {
#define	PREEN		0
	"p",
#define	BLOCK		1
	"b",
#define	DEBUG		2
	"d",
#define	READ_ONLY	3
	"r",
#define	ONLY_WRITES	4
	"w",
#define	CONVERT		5	/* setup.c convert between fffs and ffs */
	"c",
#define	FORCE		6	/* force checking, even if clean */
	"f",
	NULL
};

char **sargv;
void
main(argc, argv)
	int	argc;
	char	*argv[];
{
	int	c;
	char	*suboptions,	*value;
	int	suboption;

	/*
	 * Save argv pointer to be used if a hole in a directory's block list
	 * is found.
	 */
	sargv = argv;
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
			 * ufs specific options.
			 */
			suboptions = optarg;
			while (*suboptions != '\0') {
				switch ((suboption = getsubopt(&suboptions,
							subopts, &value))) {

				case PREEN:
					preen++;
					break;

				case BLOCK:
					if (value == NULL) {
						usage();
					} else {
						bflag = atoi(value);
					}
				printf("Alternate super block location: %d.\n",
					    bflag);
					break;

				case CONVERT:
					cvtflag++;
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

				default:
					usage();
				}
			}
			break;

		case 'V':
			{
				int	opt_count;
				char	*opt_text;

				(void) fprintf(stdout, "fsck -F ufs ");
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
	if (signal(SIGINT, SIG_IGN) != (int)SIG_IGN)
		(void) signal(SIGINT, catch);
	if (preen)
		(void) signal(SIGQUIT, catchquit);

	if (argc) {
		while (argc-- > 0) {
			if (wflag && !writable(*argv)) {
				(void) fprintf(stderr, "not writeable '%s'\n",
									*argv);
				argv++;
			} else
				checkfilesys(*argv++);
		}
		exit(exitstat);
	}
}


void
checkfilesys(filesys)
	char *filesys;
{
	daddr32_t n_ffree, n_bfree;
	struct dups *dp;
	struct zlncnt *zlnp;
	char *devstr;

	mountfd = -1;
	hotroot = 0;
	mountedfs = 0;
	iscorrupt = 1;
	isconvert = 0;
	ismdd = 0;
	islog = 0;
	islogok = 0;
	dirholes = 0;
	needs_reclaim = 0;
	errorlocked = is_errorlocked(filesys);

	if ((devstr = setup(filesys)) == 0) {
		if (iscorrupt == 0)
			return;
		if (preen)
			pfatal("CAN'T CHECK FILE SYSTEM.");
		if ((exitstat == 0) && (mflag))
			exitstat = 32;
		exit(exitstat);
	}
	else
		devname = devstr;
	if (mflag)
		check_sanity(filesys);	/* this never returns */
	if (debug)
		printclean();
	iscorrupt = 0;
	/*
	 * 1: scan inodes tallying blocks used
	 */
	if (preen == 0) {
		if (mountedfs)
			printf("** Currently Mounted on %s\n", sblock.fs_fsmnt);
		else
			printf("** Last Mounted on %s\n", sblock.fs_fsmnt);
		if (mflag) {
			printf("** Phase 1 - Sanity Check only\n");
			return;
		} else {
			printf("** Phase 1 - Check Blocks and Sizes\n");
		}
	}
	pass1();

	/*
	 * 1b: locate first references to duplicates, if any
	 */
	if (duplist) {
		if (preen)
			pfatal("INTERNAL ERROR: dups with -p");
		printf("** Phase 1b - Rescan For More DUPS\n");
		pass1b();
	}

	/*
	 * 2: traverse directories from root to mark all connected directories
	 */
	if (preen == 0) {
		printf("** Phase 2 - Check Pathnames\n");
	}
	pass2();

	/*
	 * 3: scan inodes looking for disconnected directories
	 */
	if (preen == 0) {
		printf("** Phase 3 - Check Connectivity\n");
	}
	pass3();

	/*
	 * 3b: check acls
	 */
	pass3b();

	/*
	 * 4: scan inodes looking for disconnected files; check reference counts
	 */
	if (preen == 0) {
		printf("** Phase 4 - Check Reference Counts\n");
	}
	pass4();

	/*
	 * 5: check and repair resource counts in cylinder groups
	 */
	if (preen == 0) {
		printf("** Phase 5 - Check Cyl groups\n");
	}
	pass5();

	updateclean();
	if (debug)
		printclean();

	/*
	 * print out summary statistics
	 */
	n_ffree = sblock.fs_cstotal.cs_nffree;
	n_bfree = sblock.fs_cstotal.cs_nbfree;
	pwarn("%d files, %d used, %d free ",
	    n_files, n_blks, n_ffree + sblock.fs_frag * n_bfree);
	if (preen)
		printf("\n");
	pwarn("(%d frags, %d blocks, %.1f%% fragmentation)\n",
	    n_ffree, n_bfree, (float)(n_ffree * 100) / sblock.fs_dsize);
	if (debug &&
	    (n_files -= maxino - UFSROOTINO - sblock.fs_cstotal.cs_nifree))
		printf("%d files missing\n", n_files);
	if (debug) {
		n_blks += sblock.fs_ncg *
			(cgdmin(&sblock, 0) - cgsblock(&sblock, 0));
		n_blks += cgsblock(&sblock, 0) - cgbase(&sblock, 0);
		n_blks += howmany(sblock.fs_cssize, sblock.fs_fsize);
		if (n_blks -= maxfsblock - (n_ffree + sblock.fs_frag * n_bfree))
			printf("%d blocks missing\n", n_blks);
		if (duplist != NULL) {
			printf("The following duplicate blocks remain:");
			for (dp = duplist; dp; dp = dp->next)
				printf(" %d,", dp->dup);
			printf("\n");
		}
		if (zlnhead != NULL) {
			printf("The following zero link count inodes remain:");
			for (zlnp = zlnhead; zlnp; zlnp = zlnp->next)
				printf(" %d,", zlnp->zlncnt);
			printf("\n");
		}
	}
	zlnhead = (struct zlncnt *)0;
	duplist = muldup = (struct dups *)0;
	inocleanup();
	ckfini();
	free(blockmap);
	free(statemap);
	free((char *)lncntp);
	lncntp = NULL;
	blockmap = statemap = NULL;
	if (iscorrupt)
		exitstat = 36;
	if (!fsmodified)
		return;
	if (!preen)
		printf("\n***** FILE SYSTEM WAS MODIFIED *****\n");

	if (dirholes) {

		if (preen) {
			printf("\nFixed directory holes, Re-checking %s\n",
				devname);
			execv("/usr/sbin/fsck", sargv);
			printf("Exec failed %s\n", strerror(errno));
		}

		printf("\nFixed directories with holes, Run fsck once again\n");
		exitstat = 36;
	} else {
		if ((mountedfs && !errorlocked) || hotroot) {
			exitstat = 40;
		}
	}
}


/*
 * exit 0 - file system is unmounted and okay
 * exit 32 - file system is unmounted and needs checking
 * exit 33 - file system is mounted
 *          for root file system
 * exit 34 - cannot stat device
 */

void
check_sanity(filename)
char	*filename;
{
	struct stat64 stbd, stbr;
	struct ustat usb;
	char *devname;
	char vfsfilename[MAXPATHLEN];
	struct vfstab vfsbuf;
	FILE *vfstab;
	struct statvfs vfs_stat;
	int is_root = 0;
	int is_usr = 0;
	int is_block = 0;

	if (stat64(filename, &stbd) < 0) {
		fprintf(stderr,
		"ufs fsck: sanity check failed : cannot stat %s\n", filename);
		exit(34);
	}

	if ((stbd.st_mode & S_IFMT) == S_IFBLK)
		is_block = 1;
	else if ((stbd.st_mode & S_IFMT) == S_IFCHR)
		is_block = 0;
	else {
		fprintf(stderr,
	"ufs fsck: sanity check failed: %s not block or character device\n",
		filename);
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
			if (stat64(devname, &stbr) == 0)
				if (stbr.st_rdev == stbd.st_rdev)
					is_root = 1;
		}
		if (getvfsfile(vfstab, &vfsbuf, "/usr") == 0) {
			if (is_block)
				devname = vfsbuf.vfs_special;
			else
				devname = vfsbuf.vfs_fsckdev;
			if (stat64(devname, &stbr) == 0)
				if (stbr.st_rdev == stbd.st_rdev)
					is_usr = 1;
		}
	}


	/*
	 * XXX - only works if filename is a block device or if
	 * character and block device has the same dev_t value
	 */
	if (is_root == 0 && is_usr == 0 && ustat(stbd.st_rdev, &usb) == 0) {
		fprintf(stderr, "ufs fsck: sanity check: %s already mounted\n",
		filename);
		exit(33);
	}

	if (is_root || is_usr) {
		if (is_root)
			strcpy(vfsfilename, "/");
		else
			strcpy(vfsfilename, "/usr");
		if (statvfs(vfsfilename, &vfs_stat) != 0) {
			fprintf(stderr,
				"ufs fsck: Cannot stat %s\n",
				vfsfilename);
			exit(34);
		}

		if (!(vfs_stat.f_flag & ST_RDONLY)) {
			/*
			 * The file system is mounted read/write
			 * We need to exit saying that / or /usr is
			 * already mounted read/write. If it's only
			 * mounted readonly, we can continue.
			 */

			fprintf(stderr,
				"ufs fsck: sanity check:"
				"%s already mounted read/write\n",
				filename);
			exit(33);
		}
	}

	/*
	 * We mount the ufs root file system read-only first.  After fsck
	 * runs, we remount the root as read-write.  Therefore, we no longer
	 * check for different values for fs_state between the root file
	 * system and the rest of file systems.
	 */
	if (islog && !islogok) {
		fprintf(stderr, "ufs fsck: sanity check: %s needs checking\n",
			filename);
		exit(32);
	}
	if ((sblock.fs_state + (long)sblock.fs_time == FSOKAY) &&
		(sblock.fs_clean == FSCLEAN || sblock.fs_clean == FSSTABLE ||
		(sblock.fs_clean == FSLOG && islog))) {
		fprintf(stderr, "ufs fsck: sanity check: %s okay\n", filename);
	} else {
		fprintf(stderr, "ufs fsck: sanity check: %s needs checking\n",
			filename);
		exit(32);
	}
	exit(0);
}

char *
unrawname(name)
	char *name;
{
	char *dp;

	extern char *getfullblkname();

	if ((dp = getfullblkname(name)) == NULL)
		return ("");
	return (dp);
}

char *
rawname(name)
	char *name;
{
	char *dp;

	extern char *getfullrawname();

	if ((dp = getfullrawname(name)) == NULL)
		return ("");
	return (dp);
}

char *
hasvfsopt(vfs, opt)
	struct vfstab *vfs;
	char *opt;
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
	strncpy(tmpopts, vfs->vfs_mntopts, (sizeof (tmpopts) - 1));
	opts = tmpopts;
	f = mntopt(&opts);
	for (; *f; f = mntopt(&opts)) {
		if (strncmp(opt, f, strlen(opt)) == 0)
			return (f - tmpopts + vfs->vfs_mntopts);
	}
	return (NULL);
}


void
usage()
{
	(void) fprintf(stderr,
"ufs usage: fsck [-F ufs] [generic options] [-o p,b=#,c,w] [special ....]\n");
	exit(31+1);
}
