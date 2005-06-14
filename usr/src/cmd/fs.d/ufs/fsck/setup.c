/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

#define	DKTYPENAMES
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/dkio.h>
#include <sys/filio.h>
#include <sys/isa_defs.h>	/* for ENDIAN defines */

#define	bcopy(f, t, n)    memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <sys/int_const.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_log.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <string.h>
#include <unistd.h>
#include <ustat.h>
#include <fcntl.h>

#include "fsck.h"
#include <sys/vfstab.h>
#include <sys/ustat.h>
#include "roll_log.h"

struct bufarea asblk;
#define	altsblock (*asblk.b_un.b_fs)
#define	POWEROF2(num)	(((num) & ((num) - 1)) == 0)

static void badsb(int, char *);
static int checksb(int);

struct shadowclientinfo *shadowclientinfo = NULL;
struct shadowclientinfo *attrclientinfo = NULL;
int maxshadowclients = 1024;

/*
 * The size of a cylinder group is calculated by CGSIZE. The maximum size
 * is limited by the fact that cylinder groups are at most one block.
 * Its size is derived from the size of the maps maintained in the
 * cylinder group and the (struct cg) size.
 */
#define	CGSIZE(fs) \
	/* base cg */	  (sizeof (struct cg) + \
	/* blktot size */ (fs)->fs_cpg * sizeof (long) + \
	/* blks size */	  (fs)->fs_cpg * (fs)->fs_nrpos * sizeof (short) + \
	/* inode map */	  howmany((fs)->fs_ipg, NBBY) + \
	/* block map */	  howmany((fs)->fs_cpg * (fs)->fs_spc / NSPF(fs), NBBY))

extern int	mflag;
extern char 	hotroot;
extern char	*mount_point;

static int
read_super_block()
{
	int fd;

	if (mount_point) {
		fd = open(mount_point, O_RDONLY);
		if (fd == -1) {
			perror("fsck: open mount point error");
			exit(39);
		}
		/* get the latest super block */
		if (ioctl(fd, _FIOGETSUPERBLOCK, &sblock)) {
			perror("fsck: ioctl _FIOGETSUPERBLOCK error");
			exit(39);
		}
		close(fd);
	} else {
		(void) bread(fsreadfd, (char *)&sblock,
			bflag != 0 ? (diskaddr_t)bflag : (diskaddr_t)SBLOCK,
			(long)SBSIZE);
	}

	/*
	 * rudimental consistency checks
	 */
	if ((sblock.fs_magic != FS_MAGIC) &&
		(sblock.fs_magic != MTB_UFS_MAGIC)) {
		badsb(1, "MAGIC NUMBER WRONG");
		return (0);
	}
	if (sblock.fs_magic == MTB_UFS_MAGIC &&
		(sblock.fs_version > MTB_UFS_VERSION_1 ||
		sblock.fs_version < MTB_UFS_VERSION_MIN)) {
		badsb(1, "UNRECOGNIZED VERSION");
		return (0);
	}
	if (sblock.fs_ncg < 1) {
		badsb(1, "NCG OUT OF RANGE");
		return (0);
	}
	if (sblock.fs_cpg < 1) {
		badsb(1, "CPG OUT OF RANGE");
		return (0);
	}
	if (sblock.fs_ncg * sblock.fs_cpg < sblock.fs_ncyl ||
		(sblock.fs_ncg - 1) * sblock.fs_cpg >= sblock.fs_ncyl) {
		badsb(1, "NCYL IS INCONSISTENT WITH NCG*CPG");
		return (0);
	}
	if (sblock.fs_sbsize < 0 || sblock.fs_sbsize > SBSIZE) {
		badsb(1, "SIZE TOO LARGE");
		return (0);
	}

	return (1);
}

void
flush_fs()
{
	int fd;

	if (mount_point) {
		fd = open(mount_point, O_RDONLY);
		if (fd == -1) {
			perror("fsck: open mount point error");
			exit(39);
		}
		if (ioctl(fd, _FIOFFS, NULL)) { /* flush file system */
			perror("fsck: ioctl _FIOFFS error");
			exit(39);
		}
		close(fd);
	}
}

/*
 * Roll the embedded log, if any, and set up the global variables
 * islog, islogok, and ismdd.
 */
static int
logsetup(char *devstr)
{
	void		*buf;
	struct dk_cinfo	dkcinfo;
	extent_block_t	*ebp;
	ml_unit_t	*ul;
	ml_odunit_t	*ud;
	void		*ud_buf;
	int		badlog;

	ismdd = islog = islogok = 0;
	if (bflag)
		return (1); /* can't roll log while alternate sb specified */

	/* Roll the log, if any */
	sblock.fs_logbno = 0;
	badlog = 0;
	if (!read_super_block())
		return (0);

	/*
	 * Roll the log in 3 cases:
	 * 1. If it's unmounted (mount_point == NULL) and it's not marked
	 *    as fully rolled (sblock.fs_rolled != FS_ALL_ROLLED)
	 * 2. If it's mounted and anything other than a sanity
	 *    check fsck (mflag) is being done, as we have the current
	 *    super block. Note, only a sanity check is done for
	 *    root/usr at boot. If a roll were done then the expensive
	 *    ufs_flush() gets called, leading to a slower boot.
	 * 3. If anything other then a sanity check (mflag) is being done
	 *    to a mounted filesystem while it is in read-only state
	 *    (e.g. root during early boot stages) we have to detect this
	 *    and have to roll the log as well. NB. the read-only mount
	 *    will flip fs_clean from FSLOG to FSSTABLE and marks the
	 *    log as FS_NEED_ROLL.
	 */
	if (sblock.fs_logbno &&
	    (((mount_point == NULL) && (sblock.fs_rolled != FS_ALL_ROLLED)) ||
	    (mount_point && !mflag))) {
		int roll_log_err = 0;

		if (sblock.fs_ronly && (sblock.fs_clean == FSSTABLE) &&
			(sblock.fs_state + sblock.fs_time == FSOKAY)) {
			/*
			 * roll the log without a mount
			 */
			flush_fs();
		}
		if (sblock.fs_clean == FSLOG &&
			(sblock.fs_state + sblock.fs_time == FSOKAY)) {
			if (rl_roll_log(devstr) != RL_SUCCESS)
				roll_log_err = 1;
		}
		if (roll_log_err) {
			(void) printf("Can't roll the log for %s.\n", devstr);
			/*
			 * There are two cases where we want to set
			 * an error code and return:
			 *  - We're preening
			 *  - We're not on a live root and the user
			 *    chose *not* to ignore the log
			 * Otherwise, we want to mark the log as bad
			 * and continue to check the filesystem.  This
			 * has the side effect of destroying the log.
			 */
			if (preen || (!hotroot &&
			    reply(
			"DISCARDING THE LOG MAY DISCARD PENDING TRANSACTIONS.\n"
					"DISCARD THE LOG AND CONTINUE") == 0)) {
				exitstat = 39;
				return (0);
			}
			++badlog;
		}
	}

	/* MDD (disksuite) device */
	if (ioctl(fsreadfd, DKIOCINFO, &dkcinfo) == 0)
		if (dkcinfo.dki_ctype == DKC_MD)
			++ismdd;

	/* Logging UFS may be enabled */
	if (sblock.fs_logbno) {
		++islog;

		/* log is not okay; check the fs */
		if (FSOKAY != (sblock.fs_state + sblock.fs_time))
			return (1);

		/*
		 * If logging or (stable and mounted) then continue
		 */
		if ((sblock.fs_clean != FSLOG) &&
		    ((sblock.fs_clean != FSSTABLE) || !(mount_point)))
			return (1);

		/* get the log allocation block */
		buf = malloc((size_t)dev_bsize);
		if (buf == (void *) NULL) {
			return (1);
		}
		ud_buf = malloc((size_t)dev_bsize);
		if (ud_buf == (void *) NULL) {
			free(buf);
			return (1);
		}
		(void) bread(fsreadfd, buf,
		    logbtodb(&sblock, sblock.fs_logbno),
		    (long)dev_bsize);
		ebp = (extent_block_t *)buf;

		/* log allocation block is not okay; check the fs */
		if (ebp->type != LUFS_EXTENTS) {
			free(buf);
			free(ud_buf);
			return (1);
		}

		/* get the log state block(s) */
		if (bread(fsreadfd, ud_buf,
		    (logbtodb(&sblock, ebp->extents[0].pbno)),
		    (long)dev_bsize)) {
			(void) bread(fsreadfd, ud_buf,
			(logbtodb(&sblock, ebp->extents[0].pbno)) + 1,
			(long)dev_bsize);
		}
		ud = (ml_odunit_t *)ud_buf;
		ul = (ml_unit_t *)malloc(sizeof (*ul));
		if (ul == NULL) {
			free(buf);
			free(ud_buf);
			return (1);
		}
		ul->un_ondisk = *ud;

		/* log state is okay; don't need to check the fs */
		if ((ul->un_chksum == ul->un_head_ident + ul->un_tail_ident) &&
		    (ul->un_version == LUFS_VERSION_LATEST) &&
		    (ul->un_badlog == 0) && (!badlog))
			++islogok;
		free(ud_buf);
		free(buf);
		free(ul);
	} else if (ismdd) {
		/* if it is a logging device and there are no errors */
		if (ioctl(fsreadfd, _FIOISLOG, NULL) == 0) {
			islog++;
			if (ioctl(fsreadfd, _FIOISLOGOK, NULL) == 0)
				islogok++;
		}
	}

	return (1);
}

char *
setup(char *dev)
{
	dev_t rootdev;
	int size, i, j;
	int64_t bmapsize;
	struct stat64 statb;
	static char devstr[MAXPATHLEN];
	char *raw, *rawname(), *unrawname();
	void write_altsb();
	struct ustat ustatb;
	caddr_t sip;
	int mountchk;

	havesb = 0;
	if (stat64("/", &statb) < 0)
		errexit("Can't stat root\n");
	rootdev = statb.st_dev;

	devname = devstr;
	strncpy(devstr, dev, sizeof (devstr));
restat:
	if (stat64(devstr, &statb) < 0) {
		printf("Can't stat %s\n", devstr);
		exitstat = 34;
		return (0);
	}
	/*
	 * A mount point is specified. But the mount point doesn't
	 * match entries in the /etc/vfstab.
	 * Search mnttab, because if the fs is error locked, it is
	 * allowed to be fsck'd while mounted.
	 */
	if ((statb.st_mode & S_IFMT) == S_IFDIR) {
		if (errorlocked) {
			FILE		*mnttab;
			struct mnttab	 mnt, mntpref,
					*mntp = &mnt,
					*mpref = &mntpref;

			if ((mnttab = fopen(MNTTAB, "r")) == NULL) {
				printf("Can't open %s\n", MNTTAB);
				perror(MNTTAB);
				return (0);
			}

			mntnull(mpref);
			mpref->mnt_fstype = malloc(strlen(MNTTYPE_UFS)+1);
			mpref->mnt_mountp = malloc(strlen(devstr)+1);
			strcpy(mpref->mnt_fstype, MNTTYPE_UFS);
			strcpy(mpref->mnt_mountp, devstr);
			mntnull(mntp);

			if (getmntany(mnttab, mntp, mpref) == 0) {
				raw = rawname(unrawname(mntp->mnt_special));
				strcpy(devstr, raw);
				fclose(mnttab);
				goto restat;
			}
			fclose(mnttab);
		}
		printf("%s is not a block or character device\n", dev);
		return (0);
	}

	if ((statb.st_mode & S_IFMT) == S_IFBLK) {
		if (rootdev == statb.st_rdev) {
			mount_point = "/";
			hotroot++;
		} else if (ustat(statb.st_rdev, &ustatb) == 0 && !errorlocked) {
			printf("%s is a mounted file system, ignored\n", dev);
			exitstat = 33;
			return (0);
		}
	}
	if ((statb.st_mode & S_IFMT) == S_IFDIR) {
		FILE *vfstab;
		struct vfstab vfsbuf;
		/*
		 * Check vfstab for a mount point with this name
		 */
		if ((vfstab = fopen(VFSTAB, "r")) == NULL) {
			errexit("Can't open checklist file: %s\n", VFSTAB);
		}
		while (getvfsent(vfstab, &vfsbuf) == NULL) {
			if (strcmp(devstr, vfsbuf.vfs_mountp) == 0) {
				if (strcmp(vfsbuf.vfs_fstype,
				    MNTTYPE_UFS) != 0) {
					/*
					 * found the entry but it is not a
					 * ufs filesystem, don't check it
					 */
					fclose(vfstab);
					return (0);
				}
				strcpy(devstr, vfsbuf.vfs_special);
				if (rflag) {
					raw = rawname(
					    unrawname(vfsbuf.vfs_special));
					strcpy(devstr, raw);
				}
				goto restat;
			}
		}
		fclose(vfstab);

	} else if (((statb.st_mode & S_IFMT) != S_IFBLK) &&
	    ((statb.st_mode & S_IFMT) != S_IFCHR)) {
		if (preen)
			pwarn("file is not a block or character device.\n");
		else if (reply("file is not a block or character device; OK")
		    == 0)
			return (0);
		/*
		 * To fsck regular files (fs images)
		 * we need to clear the rflag since
		 * regular files don't have raw names.  --CW
		 */
		rflag = 0;
	}

	if (mountchk = mounted(devstr)) {
		if (rflag) {
			mountedfs++;
			/*
			 * Get confirmation we should continue UNLESS:
			 * this is the root (since that is always
			 * mounted), we are running in preen mode, we
			 * are running in "just say no" mode, the fs is
			 * mounted read-only, or we are running in check
			 * only mode.
			 */
			if (rootdev != statb.st_rdev &&	!preen && !nflag &&
			    !mflag && mountchk != 2) {
				if (reply("FILE SYSTEM IS CURRENTLY MOUNTED."
				    "  CONTINUE") == 0) {
					exitstat = 33;
					return (0);
				}
			}
		} else {
			printf("%s is mounted, fsck on BLOCK device ignored\n",
				devstr);
			exit(33);
		}
		if (!errorlocked)
			sync();	/* call sync, only when devstr's mounted */
	}
	if (rflag) {
		char blockname[MAXPATHLEN];
		/*
		 * For root device check, must check
		 * block devices.
		 */
		strcpy(blockname, devstr);
		if (stat64(unrawname(blockname), &statb) < 0) {
			printf("Can't stat %s\n", blockname);
			exitstat = 34;
			return (0);
		}
	}
	if (rootdev == statb.st_rdev) {
		hotroot++;
		mount_point = "/";
	}
	if ((fsreadfd = open64(devstr, O_RDONLY)) < 0) {
		printf("Can't open %s\n", devstr);
		exitstat = 34;
		return (0);
	}
	if (preen == 0 || debug != 0)
		printf("** %s", devstr);

	if (errorlocked) {
		if (debug && elock_combuf)
			printf(" error-lock comment: \"%s\" ", elock_combuf);
		fflag = 1;
	}
	pid = getpid();
	if (nflag || (fswritefd = open64(devstr, O_WRONLY)) < 0) {
		fswritefd = -1;
		if (preen && !debug)
			pfatal("(NO WRITE ACCESS)\n");
		printf(" (NO WRITE)");
	}
	if (preen == 0)
		printf("\n");
	else if (debug)
		printf(" pid %d\n", pid);
	if (debug && (hotroot || mountedfs)) {
		printf("** %s", devstr);
		if (hotroot)
			printf(" is root fs%s",
				mountedfs || errorlocked? " and": "");
		if (mountedfs)
			printf(" is mounted%s", errorlocked? " and": "");
		if (errorlocked)
			printf(" is error-locked");

		printf(".\n");
	}
	fsmodified = 0;
	if (errorlocked)
		isdirty = 1;
	lfdir = 0;
	initbarea(&sblk);
	initbarea(&asblk);
	sblk.b_un.b_buf = malloc(SBSIZE);
	asblk.b_un.b_buf = malloc(SBSIZE);
	if (sblk.b_un.b_buf == NULL || asblk.b_un.b_buf == NULL)
		errexit("cannot allocate space for superblock\n");
	dev_bsize = secsize = DEV_BSIZE;

	/* Check log state (embedded and SDS) */
	if (!logsetup(devstr))
		return (0);

	/*
	 * Flush fs if we're going to do anything other than a sanity check.
	 * Note, if logging then the fs was flushed if needed in logsetup().
	 */
	if (!islog && !mflag)
		flush_fs();

	if (!read_super_block()) /* re-read sb after possibly rolling the log */
		return (0);
	/*
	 * Check the superblock, looking for alternates if necessary
	 */
	if (checksb(1) == 0)
		return (0);
	maxfsblock = sblock.fs_size;
	maxino = sblock.fs_ncg * sblock.fs_ipg;
	/*
	 * Check and potentially fix certain fields in the super block.
	 */
	if (sblock.fs_optim != FS_OPTTIME && sblock.fs_optim != FS_OPTSPACE) {
		pfatal("UNDEFINED OPTIMIZATION IN SUPERBLOCK");
		if (reply("SET TO DEFAULT") == 1) {
			sblock.fs_optim = FS_OPTTIME;
			sbdirty();
		}
	}
	if ((sblock.fs_minfree < 0 || sblock.fs_minfree > 99)) {
		pfatal("IMPOSSIBLE MINFREE=%d IN SUPERBLOCK",
			sblock.fs_minfree);
		if (reply("SET TO DEFAULT") == 1) {
			sblock.fs_minfree = 10;
			sbdirty();
		}
	}
	if (cvtflag) {
		if (sblock.fs_postblformat == FS_42POSTBLFMT) {
			/*
			 * Requested to convert from old format to new format
			 */
			if (preen)
				pwarn("CONVERTING TO NEW FILE SYSTEM FORMAT\n");
			else if (!reply("CONVERT TO NEW FILE SYSTEM FORMAT"))
				return (0);
			isconvert = 1;
			sblock.fs_postblformat = FS_DYNAMICPOSTBLFMT;
			sblock.fs_nrpos = 8;
			sblock.fs_npsect = sblock.fs_nsect;
			sblock.fs_postbloff =
			    (char *)(&sblock.fs_opostbl[0][0]) -
			    (char *)(&sblock.fs_link);
			sblock.fs_rotbloff = &sblock.fs_space[0] -
			    (uchar_t *)(&sblock.fs_link);
			sblock.fs_cgsize =
				fragroundup(&sblock, CGSIZE(&sblock));
			/*
			 * Planning now for future expansion.
			 */
#if defined(_BIG_ENDIAN)
				sblock.fs_qbmask.val[0] = 0;
				sblock.fs_qbmask.val[1] = ~sblock.fs_bmask;
				sblock.fs_qfmask.val[0] = 0;
				sblock.fs_qfmask.val[1] = ~sblock.fs_fmask;
#endif
#if defined(_LITTLE_ENDIAN)
				sblock.fs_qbmask.val[0] = ~sblock.fs_bmask;
				sblock.fs_qbmask.val[1] = 0;
				sblock.fs_qfmask.val[0] = ~sblock.fs_fmask;
				sblock.fs_qfmask.val[1] = 0;
#endif
			/* make mountable */
			sblock.fs_state = FSOKAY - sblock.fs_time;
			sblock.fs_clean = FSCLEAN;
			sbdirty();
			write_altsb(fswritefd);
		} else if (sblock.fs_postblformat == FS_DYNAMICPOSTBLFMT) {
			/*
			 * Requested to convert from new format to old format
			 */
			if (sblock.fs_nrpos != 8 || sblock.fs_ipg > 2048 ||
			    sblock.fs_cpg > 32 || sblock.fs_cpc > 16) {
				printf(
				"PARAMETERS OF CURRENT FILE SYSTEM DO NOT\n\t");
				errexit(
				"ALLOW CONVERSION TO OLD FILE SYSTEM FORMAT\n");
			}
			if (preen)
				pwarn("CONVERTING TO OLD FILE SYSTEM FORMAT\n");
			else if (!reply("CONVERT TO OLD FILE SYSTEM FORMAT"))
				return (0);
			isconvert = 1;
			sblock.fs_postblformat = FS_42POSTBLFMT;
			sblock.fs_cgsize = fragroundup(&sblock,
			    sizeof (struct ocg) + howmany(sblock.fs_fpg, NBBY));
			sblock.fs_npsect = 0;
			/* make mountable */
			sblock.fs_state = FSOKAY - sblock.fs_time;
			sblock.fs_clean = FSCLEAN;
			sbdirty();
			write_altsb(fswritefd);
		} else {
			errexit("UNKNOWN FILE SYSTEM FORMAT\n");
		}
	}
	if (errorlocked) {
		/* do this right away to prevent any other fscks on this fs */
		switch (sblock.fs_clean) {
		case FSBAD:
			break;
		case FSFIX:
			if (preen)
				errexit("ERROR-LOCKED; MARKED \"FSFIX\"\n");
			if (reply("marked FSFIX, CONTINUE") == 0)
				return (0);
			break;
		case FSCLEAN:
			if (preen)
				errexit("ERROR-LOCKED; MARKED \"FSCLEAN\"\n");
			if (reply("marked FSCLEAN, CONTINUE") == 0)
				return (0);
			break;
		default:
			if (preen) {
				if (debug)
				pwarn("ERRORLOCKED; NOT MARKED \"FSBAD\"\n");
				else
				errexit("ERRORLOCKED; NOT MARKED \"FSBAD\"\n");
			} else {
	if (reply("error-locked, but not marked \"FSBAD\"; CONTINUE") == 0)
					return (0);
			}
			break;
		}

		if (!do_errorlock(LOCKFS_ELOCK)) {
			if (preen)
				return (0);
			if (reply("error-lock reset failed; CONTINUE") == 0)
				return (0);
		}

		sblock.fs_state = FSOKAY - (long)sblock.fs_time;
		sblock.fs_clean = FSFIX;
		sbdirty();
		write_altsb(fswritefd);
	}
	/*
	 * read in the summary info.
	 */
	sip = calloc(1, sblock.fs_cssize);
	if (sip == NULL)
		errexit("cannot allocate space for cylinder group summary\n");
	sblock.fs_u.fs_csp = (struct csum *)((void *)sip);
	for (i = 0, j = 0; i < sblock.fs_cssize; i += sblock.fs_bsize, j++) {
		size = sblock.fs_cssize - i < sblock.fs_bsize ?
		    sblock.fs_cssize - i : sblock.fs_bsize;
		if (bread(fsreadfd, sip,
		    fsbtodb(&sblock, sblock.fs_csaddr + j * sblock.fs_frag),
		    (long)size) != 0)
			return (0);
		sip += size;
	}
	/*
	 * if not error-locked,
	 *   not bad log, not forced, preening, not converting, and is clean;
	 *   stop checking
	 */
	if (!errorlocked &&
	    ((!islog || islogok) &&
	    (fflag == 0) && preen && (isconvert == 0) &&
	    (FSOKAY == (sblock.fs_state + sblock.fs_time)) &&
	    ((sblock.fs_clean == FSLOG && islog) ||
	    ((sblock.fs_clean == FSCLEAN) || (sblock.fs_clean == FSSTABLE))))) {
		iscorrupt = 0;
		printclean();
		return (0);
	}
	/*
	 * allocate and initialize the necessary maps
	 */
	bmapsize = roundup(howmany((uint64_t)maxfsblock, NBBY),
	    sizeof (short));
	blockmap = calloc((size_t)bmapsize, sizeof (char));
	if (blockmap == NULL) {
		printf("cannot alloc %lld bytes for blockmap\n", bmapsize);
		goto badsb;
	}
	statemap = calloc((size_t)(maxino + 1), sizeof (char));
	if (statemap == NULL) {
		printf("cannot alloc %d bytes for statemap\n", maxino + 1);
		goto badsb;
	}
	lncntp = (short *)calloc((unsigned)(maxino + 1), sizeof (short));
	if (lncntp == NULL) {
		printf("cannot alloc %d bytes for lncntp\n",
		    (maxino + 1) * sizeof (short));
		goto badsb;
	}
	numdirs = sblock.fs_cstotal.cs_ndir;
	listmax = numdirs + 10;
	inpsort = (struct inoinfo **)calloc((unsigned)listmax,
	    sizeof (struct inoinfo *));
	inphead = (struct inoinfo **)calloc((unsigned)numdirs,
	    sizeof (struct inoinfo *));
	if (inpsort == NULL || inphead == NULL) {
		printf("cannot alloc %d bytes for inphead\n",
		    numdirs * sizeof (struct inoinfo *));
		goto badsb;
	}
	numacls = numdirs;
	aclmax = numdirs + 10;
	aclpsort = (struct aclinfo **)calloc((unsigned)aclmax,
	    sizeof (struct aclinfo *));
	aclphead = (struct aclinfo **)calloc((unsigned)numacls,
	    sizeof (struct aclinfo *));
	if (aclpsort == NULL || aclphead == NULL) {
		printf("cannot alloc %d bytes for aclphead\n",
		    numacls * sizeof (struct inoinfo *));
		goto badsb;
	}
	aclplast = 0L;
	inplast = 0L;
	bufinit();
	return (devstr);

badsb:
	ckfini();
	exitstat = 39;
	return (0);
}

/*
 *  mkfs limits the size of the inode map to be no more than a third of
 *  the cylinder group space.  We'll use that value for sanity checking
 *  the superblock's inode per group value.
 */
#define	MAXIpG	(roundup(sblock.fs_bsize * NBBY / 3, sblock.fs_inopb))

/*
 * Check the super block and its summary info.
 */
static int
checksb(int listerr)
{
	/*
	 * When the fs check is successfully completed, the alternate super
	 * block at sblk.b_bno will be overwritten by ckfini() with the
	 * repaired super block.
	 */
	sblk.b_bno = bflag ? bflag : SBOFF / dev_bsize;
	sblk.b_size = SBSIZE;

	/*
	 *  Add some extra hardening checks per bug 1253090. Also sanity
	 *  check some of the values we are going to use later in allocation
	 *  requests.
	 */
	if (sblock.fs_cstotal.cs_ndir < 1 ||
	    sblock.fs_cstotal.cs_ndir > sblock.fs_ncg * sblock.fs_ipg) {
		badsb(listerr, "NUMBER OF DIRECTORIES OUT OF RANGE");
		return (0);
	}

	if (sblock.fs_nrpos <= 0 || sblock.fs_postbloff < 0 ||
	    sblock.fs_cpc < 0 ||
	    (sblock.fs_postbloff +
		(sblock.fs_nrpos * sblock.fs_cpc * sizeof (short))) >
	    sblock.fs_sbsize) {
		badsb(listerr, "ROTATIONAL POSITION TABLE SIZE OUT OF RANGE");
		return (0);
	}

	if (sblock.fs_cssize !=
		fragroundup(&sblock, sblock.fs_ncg * sizeof (struct csum))) {
		badsb(listerr, "SIZE OF CYLINDER GROUP SUMMARY AREA WRONG");
		return (0);
	}

	if (sblock.fs_inopb != (sblock.fs_bsize / sizeof (struct dinode))) {
		badsb(listerr, "INOPB NONSENSICAL RELATIVE TO BSIZE");
		return (0);
	}

	if (sblock.fs_bsize != (sblock.fs_frag * sblock.fs_fsize)) {
		badsb(listerr, "FRAGS PER BLOCK OR FRAG SIZE WRONG");
		return (0);
	}

	if (sblock.fs_dsize >= sblock.fs_size) {
		badsb(listerr, "NUMBER OF DATA BLOCKS OUT OF RANGE");
		return (0);
	}

	/*
	 *  Check that the number of inodes per group isn't less than or
	 *  equal to zero.  Also makes sure it isn't more than the
	 *  maximum number mkfs enforces.
	 */
	if (sblock.fs_ipg <= 0 || sblock.fs_ipg > MAXIpG) {
		badsb(listerr, "INODES PER GROUP OUT OF RANGE");
		return (0);
	}

	/*
	 * Set all possible fields that could differ, then do check
	 * of whole super block against an alternate super block.
	 * When an alternate super-block is specified this check is skipped.
	 */
	getblk(&asblk, cgsblock(&sblock, sblock.fs_ncg - 1),
	    sblock.fs_sbsize);
	if (asblk.b_errs)
		return (0);
	if (bflag) {
		/*
		 * Invalidate clean flag and state information
		 */
		sblock.fs_clean = FSACTIVE;
		sblock.fs_state = (long)sblock.fs_time;
		sblock.fs_reclaim = 0;
		sbdirty();
		havesb = 1;
		return (1);
	}
	/*
	 * fsck should ignore deleted files because the reclaim thread
	 * will run at mount and reclaim them
	 */
	isreclaim = (sblock.fs_reclaim & (FS_RECLAIMING | FS_RECLAIM));
	willreclaim = (isreclaim && islog && islogok && !fflag);

	altsblock.fs_link = sblock.fs_link;
	altsblock.fs_rolled = sblock.fs_rolled;
	altsblock.fs_time = sblock.fs_time;
	altsblock.fs_state = sblock.fs_state;
	altsblock.fs_cstotal = sblock.fs_cstotal;
	altsblock.fs_cgrotor = sblock.fs_cgrotor;
	altsblock.fs_fmod = sblock.fs_fmod;
	altsblock.fs_clean = sblock.fs_clean;
	altsblock.fs_ronly = sblock.fs_ronly;
	altsblock.fs_flags = sblock.fs_flags;
	altsblock.fs_maxcontig = sblock.fs_maxcontig;
	altsblock.fs_minfree = sblock.fs_minfree;
	altsblock.fs_optim = sblock.fs_optim;
	altsblock.fs_rotdelay = sblock.fs_rotdelay;
	altsblock.fs_maxbpg = sblock.fs_maxbpg;
	altsblock.fs_logbno = sblock.fs_logbno;
	altsblock.fs_reclaim = sblock.fs_reclaim;
	altsblock.fs_si = sblock.fs_si;
	bcopy((char *)sblock.fs_fsmnt, (char *)altsblock.fs_fsmnt,
		sizeof (sblock.fs_fsmnt));
	bcopy((char *)sblock.fs_u.fs_csp_pad, (char *)altsblock.fs_u.fs_csp_pad,
		sizeof (sblock.fs_u.fs_csp_pad));
	/*
	 * The following should not have to be copied.
	 */
	altsblock.fs_fsbtodb = sblock.fs_fsbtodb;
	altsblock.fs_npsect = sblock.fs_npsect;
	altsblock.fs_nrpos = sblock.fs_nrpos;
	if (bcmp((char *)&sblock, (char *)&altsblock,
	    (size_t)sblock.fs_sbsize)) {
		badsb(listerr, "BAD VALUES IN SUPER BLOCK"); return (0);
	}
	havesb = 1;
	return (1);
}

static void
badsb(int listerr, char *s)
{
	if (!listerr)
		return;
	if (preen)
		printf("%s: ", devname);
	printf("BAD SUPER BLOCK: %s\n", s);
	pwarn("USE AN ALTERNATE SUPER-BLOCK TO SUPPLY NEEDED INFORMATION;\n");
	pwarn("eg. fsck [-F ufs] -o b=# [special ...] \n");
	pfatal("where # is the alternate super block. SEE fsck_ufs(1M). \n");
	exitstat = 39;
}

/*
 * Write out the super block into each of the alternate super blocks.
 */
void
write_altsb(int fd)
{
	int cylno;

	for (cylno = 0; cylno < sblock.fs_ncg; cylno++)
		bwrite(fd, (char *)&sblock, fsbtodb(&sblock,
			cgsblock(&sblock, cylno)), sblock.fs_sbsize);
}
