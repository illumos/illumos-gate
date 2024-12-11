/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


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
 * THIS SOFTWARE IS PROVIDED '`AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * In-core structures:
 * blockmap[]
 *	A bitmap of block usage very similar to what's on disk, but
 *	for the entire filesystem rather than just a cylinder group.
 *	Zero indicates free, one indicates allocated.  Note that this
 *	is opposite the interpretation of a cylinder group's free block
 *	bitmap.
 *
 * statemap[]
 *	Tracks what is known about each inode in the filesystem.
 *	The fundamental state value is one of USTATE, FSTATE, DSTATE,
 *	or SSTATE (unallocated, file, directory, shadow/acl).
 *
 *	There are optional modifying attributes as well: INZLINK,
 *	INFOUND, INCLEAR, INORPHAN, and INDELAYD.  The IN prefix
 *	stands for inode.  INZLINK declares that no links (di_nlink ==
 *	0) to the inode have been found.  It is used instead of
 *	examining di_nlink because we've always got the statemap[] in
 *	memory, and on average the odds are against having any given
 *	inode in the cache.  INFOUND flags that an inode was
 *	encountered during the descent of the filesystem.  In other
 *	words, it's reachable, either by name or by being an acl or
 *	attribute.  INCLEAR declares an intent to call clri() on an
 *	inode. The INCLEAR and INZLINK attributes are treated in a
 *	mutually exclusive manner with INCLEAR taking higher precedence
 *	as the intent is to clear the inode.
 *
 *	INORPHAN indicates that the inode has already been seen once
 *	in pass3 and determined to be an orphan, so any additional
 *	encounters don't need to waste cycles redetermining that status.
 *	It also means we don't ask the user about doing something to the
 *	inode N times.
 *
 *	INDELAYD marks inodes that pass1 determined needed to be truncated.
 *	They can't be truncated during that pass, because it depends on
 *	having a stable world for building the block and inode tables from.
 *
 *	The IN flags rarely used directly, but instead are
 *	pre-combined through the {D,F,S}ZLINK, DFOUND, and
 *	{D,F,S}CLEAR convenience macros.  This mainly matters when
 *	trying to use grep on the source.
 *
 *	Three state-test macros are provided: S_IS_DUNFOUND(),
 *	S_IS_DVALID(), and S_IS_ZLINK().  The first is true when an
 *	inode's state indicates that it is either a simple directory
 *	(DSTATE without the INFOUND or INCLEAR modifiers) or a
 *	directory with the INZLINK modifier set.  By definition, if a
 *	directory has zero links, then it can't be found.  As for
 *	S_IS_DVALID(), it decides if a directory inode is alive.
 *	Effectively, this translates to whether or not it's been
 *	flagged for clearing.  If not, then it's valid for current
 *	purposes.  This is true even if INZLINK is set, as we may find
 *	a reference to it later.  Finally, S_IS_ZLINK() just picks out
 *	the INZLINK flag from the state.
 *
 *	The S_*() macros all work on a state value.  To simplify a
 *	bit, the INO_IS_{DUNFOUND,DVALID}() macros take an inode
 *	number argument.  The inode is looked up in the statemap[] and
 *	the result handed off to the corresponding S_*() macro.  This
 *	is partly a holdover from working with different data
 *	structures (with the same net intent) in the BSD fsck.
 *
 * lncntp
 *	Each entry is initialized to the di_link from the on-disk
 *	inode.  Each time we find one of those links, we decrement it.
 *	Once all the traversing is done, we should have a zero.  If we
 *	have a positive value, then some reference disappeared
 *	(probably from a directory that got nuked); deal with it by
 *	fixing the count.  If we have a negative value, then we found
 *	an extra reference.  This is a can't-happen, except in the
 *	special case of when we reconnect a directory to its parent or
 *	to lost+found.  An exact match between lncntp[] and the on-disk
 *      inode means it's completely unreferenced.
 *
 * aclphead
 *	This is a hash table of the acl inodes in the filesystem.
 *
 * aclpsort
 *	The same acls as in aclphead, but as a simple linear array.
 *	It is used to hold the acl pointers for sorting and scanning
 *	in pass3b.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/int_types.h>
#include <sys/mntent.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mnttab.h>
#include <signal.h>
#include <string.h>
#include <sys/vfstab.h>
#include <sys/statvfs.h>
#include <sys/filio.h>
#include <ustat.h>
#include <errno.h>
#include "fsck.h"

static void usage(void) __NORETURN;
static long argtol(int, char *, char *, int);
static void checkfilesys(char *);
static void check_sanity(char *);
static void report_limbo(const void *, VISIT, int);

#define	QUICK_CHECK	'm'	/* are things ok according to superblock? */
#define	ALL_no		'n'	/* auto-answer interactive questions `no' */
#define	ALL_NO		'N'	/* auto-answer interactive questions `no' */
#define	UFS_OPTS	'o'	/* ufs-specific options, see subopts[] */
#define	ECHO_CMD	'V'	/* echo the command line */
#define	ALL_yes		'y'	/* auto-answer interactive questions `yes' */
#define	ALL_YES		'Y'	/* auto-answer interactive questions `yes' */
#define	VERBOSE		'v'	/* be chatty */

static char *subopts[] = {
#define	PREEN		0	/* non-interactive mode (parent is parallel) */
	"p",
#define	BLOCK		1	/* alternate superblock */
	"b",
#define	DEBUG		2	/* yammer */
	"d",
#define	ONLY_WRITES	3	/* check all writable filesystems */
	"w",
#define	FORCE		4	/* force checking, even if clean */
	"f",
	NULL
};

/*
 * Filesystems that are `magical' - if they exist in vfstab,
 * then they have to be mounted for the system to have gotten
 * far enough to be able to run fsck.  Thus, don't get all
 * bent out of shape if we're asked to check it and it is mounted.
 */
char *magic_fs[] = {
	"",			/* MAGIC_NONE, for normal filesystems */
	"/",			/* MAGIC_ROOT */
	"/usr",			/* MAGIC_USR */
	NULL			/* MAGIC_LIMIT */
};

daddr32_t bflag;
daddr32_t n_blks;
daddr32_t maxfsblock;
int debug;
int errorlocked;
int exitstat;
int fflag;
int fsmodified;
int fswritefd;
int iscorrupt;
int islog;
int islogok;
int interrupted;
int mflag;
int mountfd;
int overflowed_lf;
int rflag;
int reattached_dir;
int broke_dir_link;
int verbose;
char hotroot;
char mountedfs;
char nflag;
char preen;
char rerun;
char *blockmap;
char *devname;
char yflag;
short *lncntp;
ushort_t *statemap;
fsck_ino_t maxino;
fsck_ino_t countdirs;
fsck_ino_t n_files;
void *limbo_dirs;

int
main(int argc, char *argv[])
{
	int c;
	int wflag = 0;
	char *suboptions, *value;
	struct rlimit rlimit;
	extern int optind;
	extern char *optarg;

	while ((c = getopt(argc, argv, "mnNo:VvyY")) != EOF) {
		switch (c) {

		case QUICK_CHECK:
			mflag++;
			break;

		case ALL_no:
		case ALL_NO:
			nflag++;
			yflag = 0;
			break;

		case VERBOSE:
			verbose++;
			break;

		case UFS_OPTS:
			/*
			 * ufs specific options.
			 */
			if (optarg == NULL) {
				usage();
			}
			suboptions = optarg;
			while (*suboptions != '\0') {
				switch (getsubopt(&suboptions, subopts,
				    &value)) {

				case PREEN:
					preen++;
					break;

				case BLOCK:
					bflag = argtol(BLOCK, "block",
					    value, 10);
					(void) printf("Alternate super block "
					    "location: %ld.\n",
					    (long)bflag);
					break;

				case DEBUG:
					debug++;
					verbose++;
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

		case ECHO_CMD:
			{
				int	opt_count;
				char	*opt_text;

				(void) printf("fsck -F ufs ");
				for (opt_count = 1; opt_count < argc;
				    opt_count++) {
					opt_text = argv[opt_count];
					if (opt_text)
						(void) printf("%s ", opt_text);
				}
				(void) printf("\n");
			}
			break;

		case ALL_yes:
		case ALL_YES:
			yflag++;
			nflag = 0;
			break;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	rflag++; /* check raw devices where we can */
	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
		(void) signal(SIGINT, catch);
	if (preen)
		(void) signal(SIGQUIT, catchquit);

	/*
	 * Push up our allowed memory limit so we can cope
	 * with huge file systems.
	 */
	if (getrlimit(RLIMIT_DATA, &rlimit) == 0) {
		rlimit.rlim_cur = rlimit.rlim_max;
		(void) setrlimit(RLIMIT_DATA, &rlimit);
	}

	/*
	 * There are a lot of places where we just exit if a problem is
	 * found.  This means that we won't necessarily check everything
	 * we were asked to.  It would be nice to do everything, and
	 * then provide a summary when we're done.  However, the
	 * interface doesn't really allow us to do that in any useful
	 * way.  So, we'll just bail on the first unrecoverable
	 * problem encountered.  If we've been run by the generic
	 * wrapper, we were only given one filesystem to check, so the
	 * multi-fs case implies being run manually; that means the
	 * user can rerun us on the remaining filesystems when it's
	 * convenient for them.
	 */
	while (argc-- > 0) {
		if (wflag && !writable(*argv)) {
			(void) fprintf(stderr, "not writeable '%s'\n", *argv);
			argv++;
			if (exitstat == 0)
				exitstat = EXBADPARM;
		} else {
			checkfilesys(*argv++);
		}
	}
	if (interrupted)
		exitstat = EXSIGNAL;
	exit(exitstat);
}

/*
 * A relatively intelligent strtol().  Note that if str is NULL, we'll
 * exit, so ret does not actually need to be pre-initialized.  Lint
 * doesn't believe this, and it's harmless enough to make lint happy here.
 */
static long
argtol(int flag, char *req, char *str, int base)
{
	char *cp = str;
	long ret = -1;

	errno = 0;
	if (str != NULL)
		ret = strtol(str, &cp, base);
	if (cp == str || *cp) {
		(void) fprintf(stderr, "-%c flag requires a %s\n", flag, req);
		exit(EXBADPARM);
	}
	if (errno != 0) {
		(void) fprintf(stderr, "-%c %s value out of range\n",
		    flag, req);
	}

	return (ret);
}

/*
 * Check the specified file system.
 */
static void
checkfilesys(char *filesys)
{
	daddr32_t n_ffree, n_bfree;
	char *devstr;
	fsck_ino_t files;
	daddr32_t blks;
	fsck_ino_t inumber;
	int zlinks_printed;
	fsck_ino_t limbo_victim;
	double dbl_nffree, dbl_dsize;
	int quiet_dups;

	mountfd = -1;
	hotroot = 0;
	mountedfs = M_NOMNT;
	reattached_dir = 0;
	broke_dir_link = 0;
	iscorrupt = 1;		/* assume failure in setup() */
	islog = 0;
	islogok = 0;
	overflowed_lf = 0;
	errorlocked = is_errorlocked(filesys);
	limbo_dirs = NULL;

	if ((devstr = setup(filesys)) == NULL) {
		if (!iscorrupt) {
			return;
		}

		if (preen)
			pfatal("CAN'T CHECK FILE SYSTEM.");
		if (exitstat == 0)
			exitstat = mflag ? EXUMNTCHK : EXERRFATAL;
		exit(exitstat);
	} else {
		devname = devstr;
	}

	if (mflag) {
		check_sanity(filesys);
		/* NOTREACHED */
	}

	if (debug)
		printclean();

	iscorrupt = 0;		/* setup() succeeded, assume good filesystem */

	/*
	 * 1: scan inodes tallying blocks used
	 */
	if (!preen) {
		/* hotroot is reported as such in setup() if debug is on */
		if (mountedfs != M_NOMNT)
			(void) printf("** Currently Mounted on %s\n",
			    sblock.fs_fsmnt);
		else
			(void) printf("** Last Mounted on %s\n",
			    sblock.fs_fsmnt);
		(void) printf("** Phase 1 - Check Blocks and Sizes\n");
	}
	pass1();

	/*
	 * 1b: locate first references to duplicates, if any
	 */
	if (have_dups()) {
		if (preen)
			pfatal("INTERNAL ERROR: dups with -o p");
		(void) printf("** Phase 1b - Rescan For More DUPS\n");
		pass1b();
	}

	/*
	 * 2: traverse directories from root to mark all connected directories
	 */
	if (!preen)
		(void) printf("** Phase 2 - Check Pathnames\n");
	pass2();

	/*
	 * 3a: scan inodes looking for disconnected directories.
	 */
	if (!preen)
		(void) printf("** Phase 3a - Check Connectivity\n");
	pass3a();

	/*
	 * 3b: check acls
	 */
	if (!preen)
		(void) printf("** Phase 3b - Verify Shadows/ACLs\n");
	pass3b();

	/*
	 * 4: scan inodes looking for disconnected files; check reference counts
	 */
	if (!preen)
		(void) printf("** Phase 4 - Check Reference Counts\n");
	pass4();

	/*
	 * 5: check and repair resource counts in cylinder groups
	 */
	if (!preen)
		(void) printf("** Phase 5 - Check Cylinder Groups\n");
recount:
	pass5();

	if (overflowed_lf) {
		iscorrupt = 1;
	}

	if (!nflag && mountedfs == M_RW) {
		(void) printf("FILESYSTEM MAY STILL BE INCONSISTENT.\n");
		rerun = 1;
	}

	if (have_dups()) {
		quiet_dups = (reply("LIST REMAINING DUPS") == 0);
		if (report_dups(quiet_dups) > 0)
			iscorrupt = 1;

		(void) printf("WARNING: DATA LOSS MAY HAVE OCCURRED DUE TO "
		    "DUP BLOCKS.\nVERIFY FILE CONTENTS BEFORE USING.\n");
	}

	if (limbo_dirs != NULL) {
		/*
		 * Don't force iscorrupt, as this is sufficiently
		 * harmless that the filesystem can be mounted and
		 * used.  We just leak some inodes and/or blocks.
		 */
		pwarn("Orphan directories not cleared or reconnected:\n");

		twalk(limbo_dirs, report_limbo);

		while (limbo_dirs != NULL) {
			limbo_victim = *(fsck_ino_t *)limbo_dirs;
			if (limbo_victim != 0) {
				(void) tdelete((void *)limbo_victim,
				    &limbo_dirs,
				    ino_t_cmp);
			}
		}

		rerun = 1;
	}

	if (iscorrupt) {
		if (mountedfs == M_RW)
			(void) printf("FS IS MOUNTED R/W AND"
			    " FSCK DID ITS BEST TO FIX"
			    " INCONSISTENCIES.\n");
		else
			(void) printf("FILESYSTEM MAY STILL BE"
			    " INCONSISTENT.\n");
		rerun = 1;
	}

	/*
	 * iscorrupt must be stable at this point.
	 * updateclean() returns true when it had to discard the log.
	 * This can only happen once, since sblock.fs_logbno gets
	 * cleared as part of that operation.
	 */
	if (updateclean()) {
		if (!preen)
			(void) printf(
			    "Log was discarded, updating cyl groups\n");
		goto recount;
	}

	if (debug)
		printclean();

	ckfini();

	/*
	 * print out summary statistics
	 */
	n_ffree = sblock.fs_cstotal.cs_nffree;
	n_bfree = sblock.fs_cstotal.cs_nbfree;
	files = maxino - UFSROOTINO - sblock.fs_cstotal.cs_nifree - n_files;
	blks = n_blks +
	    sblock.fs_ncg * (cgdmin(&sblock, 0) - cgsblock(&sblock, 0));
	blks += cgsblock(&sblock, 0) - cgbase(&sblock, 0);
	blks += howmany(sblock.fs_cssize, sblock.fs_fsize);
	blks = maxfsblock - (n_ffree + sblock.fs_frag * n_bfree) - blks;
	if (debug && (files > 0 || blks > 0)) {
		countdirs = sblock.fs_cstotal.cs_ndir - countdirs;
		pwarn("Reclaimed: %d directories, %d files, %lld fragments\n",
		    countdirs, files - countdirs,
		    (longlong_t)blks);
	}

	dbl_nffree = (double)n_ffree;
	dbl_dsize = (double)sblock.fs_dsize;

	if (!verbose) {
		/*
		 * Done as one big string to try for a single write,
		 * so the output doesn't get interleaved with other
		 * preening fscks.
		 */
		pwarn("%ld files, %lld used, %lld free "
		    "(%lld frags, %lld blocks, %.1f%% fragmentation)\n",
		    (long)n_files, (longlong_t)n_blks,
		    (longlong_t)n_ffree + sblock.fs_frag * n_bfree,
		    (longlong_t)n_ffree, (longlong_t)n_bfree,
		    (dbl_nffree * 100.0) / dbl_dsize);
	} else {
		pwarn("\nFilesystem summary:\n");
		pwarn("Inodes in use: %ld\n", (long)n_files);
		pwarn("Blocks in use: %lld\n", (longlong_t)n_blks);
		pwarn("Total free fragments: %lld\n",
		    (longlong_t)n_ffree + sblock.fs_frag * n_bfree);
		pwarn("Free fragments not in blocks: %lld\n",
		    (longlong_t)n_ffree);
		pwarn("Total free blocks: %lld\n", (longlong_t)n_bfree);
		pwarn("Fragment/block fragmentation: %.1f%%\n",
		    (dbl_nffree * 100.0) / dbl_dsize);
		pwarn("");

		if (files < 0)
			pwarn("%d inodes missing\n", -files);
		if (blks < 0)
			pwarn("%lld blocks missing\n", -(longlong_t)blks);

		zlinks_printed = 0;
		for (inumber = UFSROOTINO; inumber < maxino; inumber++) {
			if (S_IS_ZLINK(statemap[inumber])) {
				if (zlinks_printed == 0) {
					pwarn("The following zero "
					    "link count inodes remain:");
				}
				if (zlinks_printed) {
					if ((zlinks_printed % 9) == 0)
						(void) puts(",\n");
					else
						(void) puts(", ");
				}
				(void) printf("%u", inumber);
				zlinks_printed++;
			}
		}
		if ((zlinks_printed != 0) && ((zlinks_printed % 9) != 0))
			(void) putchar('\n');
	}

	/*
	 * Clean up after ourselves, so we can do the next filesystem.
	 */
	free_dup_state();
	inocleanup();
	free(blockmap);
	free(statemap);
	free((void *)lncntp);
	lncntp = NULL;
	blockmap = NULL;
	statemap = NULL;
	if (iscorrupt && exitstat == 0)
		exitstat = EXFNDERRS;
	if (fsmodified)
		(void) printf("\n***** FILE SYSTEM WAS MODIFIED *****\n");
	if (overflowed_lf)
		(void) printf("\n***** %s FULL, MUST REMOVE ENTRIES *****\n",
		    lfname);
	if (reattached_dir) {
		(void) printf("ORPHANED DIRECTORIES REATTACHED; DIR LINK "
		    "COUNTS MAY NOT BE CORRECT.\n");
		rerun = 1;
	}
	if (broke_dir_link) {
		(void) printf(
		    "DIRECTORY HARDLINK BROKEN; LOOPS MAY STILL EXIST.\n");
		rerun = 1;
	}
	if (iscorrupt)
		(void) printf("***** FILE SYSTEM IS BAD *****\n");

	if (rerun) {
		if (mountedfs == M_RW)
			(void) printf("\n***** PLEASE RERUN FSCK ON UNMOUNTED"
			    " FILE SYSTEM *****\n");
		else
			(void) printf("\n***** PLEASE RERUN FSCK *****\n");
	}

	if ((exitstat == 0) &&
	    (((mountedfs != M_NOMNT) && !errorlocked) || hotroot)) {
		exitstat = EXROOTOKAY;
	}

	if ((exitstat == 0) && rerun)
		exitstat = EXFNDERRS;

	if (mountedfs != M_NOMNT) {
		if (!fsmodified)
			return;
		/*
		 * _FIOFFS is much more effective than a simple sync().
		 * Note that the original fswritefd was discarded in
		 * ckfini().
		 */
		fswritefd = open(devstr, O_RDWR, 0);
		if (fswritefd != -1) {
			(void) ioctl(fswritefd, _FIOFFS, NULL);
			(void) close(fswritefd);
		}

		if (!preen)
			(void) printf("\n***** REBOOT NOW *****\n");

		exitstat = EXREBOOTNOW;
	}
}

/*
 * fsck -m: does the filesystem pass cursory examination
 *
 * XXX This is very redundant with setup().  The right thing would be
 *     for setup() to modify its behaviour when mflag is set (less
 *     chatty, exit instead of return, etc).
 */
void
check_sanity(char *filename)
{
	struct stat64 stbd, stbr;
	char *devname;
	struct ustat usb;
	char vfsfilename[MAXPATHLEN];
	struct vfstab vfsbuf;
	FILE *vfstab;
	struct statvfs vfs_stat;
	int found_magic[MAGIC_LIMIT];
	int magic_cnt;
	int is_magic = 0;
	int is_block = 0;
	int is_file = 0;

	(void) memset((void *)found_magic, 0, sizeof (found_magic));

	if (stat64(filename, &stbd) < 0) {
		(void) fprintf(stderr,
		"ufs fsck: sanity check failed : cannot stat %s\n", filename);
		exit(EXNOSTAT);
	}

	if (S_ISBLK(stbd.st_mode)) {
		is_block = 1;
	} else if (S_ISCHR(stbd.st_mode)) {
		is_block = 0;
	} else if (S_ISREG(stbd.st_mode)) {
		is_file = 1;
	}

	/*
	 * Determine if this is the root file system via vfstab. Give up
	 * silently on failures. The whole point of this is to be tolerant
	 * of the magic file systems being already mounted.
	 */
	if (!is_file && (vfstab = fopen(VFSTAB, "r")) != NULL) {
		for (magic_cnt = 0; magic_cnt < MAGIC_LIMIT; magic_cnt++) {
			if (magic_cnt == MAGIC_NONE)
				continue;
			if (getvfsfile(vfstab, &vfsbuf,
			    magic_fs[magic_cnt]) == 0) {
				if (is_block)
					devname = vfsbuf.vfs_special;
				else
					devname = vfsbuf.vfs_fsckdev;
				if (stat64(devname, &stbr) == 0) {
					if (stbr.st_rdev == stbd.st_rdev) {
						found_magic[magic_cnt] = 1;
						is_magic = magic_cnt;
						break;
					}
				}
			}
		}
	}

	/*
	 * Only works if filename is a block device or if
	 * character and block device has the same dev_t value.
	 * This is currently true, but nothing really forces it.
	 */
	if (!is_magic && (ustat(stbd.st_rdev, &usb) == 0)) {
		(void) fprintf(stderr,
		    "ufs fsck: sanity check: %s already mounted\n", filename);
		exit(EXMOUNTED);
	}

	if (is_magic) {
		(void) strcpy(vfsfilename, magic_fs[is_magic]);
		if (statvfs(vfsfilename, &vfs_stat) != 0) {
			(void) fprintf(stderr, "ufs fsck: Cannot stat %s\n",
			    vfsfilename);
			exit(EXNOSTAT);
		}

		if (!(vfs_stat.f_flag & ST_RDONLY)) {
			/*
			 * The file system is mounted read/write
			 * We need to exit saying this. If it's only
			 * mounted readonly, we can continue.
			 */

			(void) fprintf(stderr,
			    "ufs fsck: sanity check:"
			    "%s already mounted read/write\n", filename);
			exit(EXMOUNTED);
		}
	}

	/*
	 * We know that at boot, the ufs root file system is mounted
	 * read-only first.  After fsck runs, it is remounted as
	 * read-write.  Therefore, we do not need to check for different
	 * values for fs_state between the root file system and the
	 * rest of the file systems.
	 */
	if (islog && !islogok) {
		(void) fprintf(stderr,
		    "ufs fsck: sanity check: %s needs checking\n", filename);
		exit(EXUMNTCHK);
	}
	if ((sblock.fs_state + (long)sblock.fs_time == FSOKAY) &&
	    (sblock.fs_clean == FSCLEAN || sblock.fs_clean == FSSTABLE ||
	    (sblock.fs_clean == FSLOG && islog))) {
		(void) fprintf(stderr,
		    "ufs fsck: sanity check: %s okay\n", filename);
	} else {
		(void) fprintf(stderr,
		    "ufs fsck: sanity check: %s needs checking\n", filename);
		exit(EXUMNTCHK);
	}
	exit(EXOKAY);
}

caddr_t
hasvfsopt(struct vfstab *vfs, char *opt)
{
	struct mnttab mtab;

	if (vfs->vfs_mntopts == NULL)
		return (NULL);
	mtab.mnt_mntopts = vfs->vfs_mntopts;
	return (hasmntopt(&mtab, opt));
}

static void __NORETURN
usage(void)
{
	(void) fprintf(stderr,
	    "ufs usage: fsck [-F ufs] [-m] [-n] [-V] [-v] [-y] "
	    "[-o p,b=#,w,f] [special ....]\n");

	exit(EXBADPARM);
}

/*ARGSUSED*/
static void
report_limbo(const void *node, VISIT order, int level)
{
	fsck_ino_t ino = *(fsck_ino_t *)node;

	if ((order == postorder) || (order == leaf)) {
		(void) printf("    Inode %d\n", ino);
	}
}
