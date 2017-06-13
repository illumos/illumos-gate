/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

#define	DKTYPENAMES
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <malloc.h>
#include <limits.h>
#include <wait.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <sys/dkio.h>
#include <sys/filio.h>
#include <sys/isa_defs.h>	/* for ENDIAN defines */
#include <sys/int_const.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_log.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/vfstab.h>
#include "roll_log.h"
#include "fsck.h"

/*
 * The size of a cylinder group is calculated by CGSIZE. The maximum size
 * is limited by the fact that cylinder groups are at most one block.
 * Its size is derived from the size of the maps maintained in the
 * cylinder group and the (struct cg) size.
 */
#define	CGSIZE(fs) \
	/* base cg */	  (sizeof (struct cg) + \
	/* blktot size */ (fs)->fs_cpg * sizeof (int32_t) + \
	/* blks size */	  (fs)->fs_cpg * (fs)->fs_nrpos * sizeof (short) + \
	/* inode map */	  howmany((fs)->fs_ipg, NBBY) + \
	/* block map */	  howmany((fs)->fs_cpg * (fs)->fs_spc / NSPF(fs), NBBY))

#define	altsblock (*asblk.b_un.b_fs)
#define	POWEROF2(num)	(((num) & ((num) - 1)) == 0)

/*
 * Methods of determining where alternate superblocks should
 * be.  MAX_SB_STYLES must be the last one, and the others need
 * to be positive.
 */
typedef enum {
	MKFS_STYLE = 1, NEWFS_STYLE, MAX_SB_STYLES
} calcsb_t;

static caddr_t calcsb_names[] = {
	"<UNKNOWN>", "MKFS", "NEWFS", "<OUT OF RANGE>"
};

struct shadowclientinfo *shadowclientinfo = NULL;
struct shadowclientinfo *attrclientinfo = NULL;
int maxshadowclients = 1024;	/* allocation size, not limit  */

static void badsb(int, caddr_t);
static int calcsb(calcsb_t, caddr_t, int, struct fs *);
static int checksb(int);
static void flush_fs(void);
static void sblock_init(void);
static void uncreate_maps(void);

static int
read_super_block(int listerr)
{
	int fd;
	caddr_t err;

	if (mount_point != NULL) {
		fd = open(mount_point, O_RDONLY);
		if (fd == -1) {
			errexit("fsck: open mount point error: %s",
			    strerror(errno));
			/* NOTREACHED */
		}
		/* get the latest super block */
		if (ioctl(fd, _FIOGETSUPERBLOCK, &sblock)) {
			errexit("fsck: ioctl _FIOGETSUPERBLOCK error: %s",
			    strerror(errno));
			/* NOTREACHED */
		}
		(void) close(fd);
	} else {
		(void) fsck_bread(fsreadfd, (caddr_t)&sblock,
			bflag != 0 ? (diskaddr_t)bflag : (diskaddr_t)SBLOCK,
			SBSIZE);
	}

	/*
	 * Don't let trash from the disk trip us up later
	 * in ungetsummaryinfo().
	 */
	sblock.fs_u.fs_csp = NULL;

	/*
	 * Rudimentary consistency checks.  Can't really call
	 * checksb() here, because there may be outstanding
	 * deltas that still need to be applied.
	 */
	if ((sblock.fs_magic != FS_MAGIC) &&
	    (sblock.fs_magic != MTB_UFS_MAGIC)) {
		err = "MAGIC NUMBER WRONG";
		goto fail;
	}
	if (sblock.fs_magic == FS_MAGIC &&
		(sblock.fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
		sblock.fs_version != UFS_VERSION_MIN)) {
		err = "UNRECOGNIZED VERSION";
		goto fail;
	}
	if (sblock.fs_magic == MTB_UFS_MAGIC &&
		(sblock.fs_version > MTB_UFS_VERSION_1 ||
		sblock.fs_version < MTB_UFS_VERSION_MIN)) {
		err = "UNRECOGNIZED VERSION";
		goto fail;
	}
	if (sblock.fs_ncg < 1) {
		err = "NCG OUT OF RANGE";
		goto fail;
	}
	if (sblock.fs_cpg < 1) {
		err = "CPG OUT OF RANGE";
		goto fail;
	}
	if (sblock.fs_ncg * sblock.fs_cpg < sblock.fs_ncyl ||
		(sblock.fs_ncg - 1) * sblock.fs_cpg >= sblock.fs_ncyl) {
		err = "NCYL IS INCONSISTENT WITH NCG*CPG";
		goto fail;
	}
	if (sblock.fs_sbsize < 0 || sblock.fs_sbsize > SBSIZE) {
		err = "SIZE OUT OF RANGE";
		goto fail;
	}

	return (1);

fail:
	badsb(listerr, err);
	return (0);
}

static void
flush_fs()
{
	int fd;

	if (mount_point != NULL) {
		fd = open(mount_point, O_RDONLY);
		if (fd == -1) {
			errexit("fsck: open mount point error: %s",
			    strerror(errno));
			/* NOTREACHED */
		}
		if (ioctl(fd, _FIOFFS, NULL)) { /* flush file system */
			errexit("fsck: ioctl _FIOFFS error: %s",
			    strerror(errno));
			/* NOTREACHED */
		}
		(void) close(fd);
	}
}

/*
 * Roll the embedded log, if any, and set up the global variables
 * islog and islogok.
 */
static int
logsetup(caddr_t devstr)
{
	void		*buf;
	extent_block_t	*ebp;
	ml_unit_t	*ul;
	ml_odunit_t	*ud;
	void		*ud_buf;
	int		badlog;

	islog = islogok = 0;
	if (bflag != 0)
		return (1); /* can't roll log while alternate sb specified */

	/*
	 * Roll the log, if any.  A bad sb implies we'll be using
	 * an alternate sb as far as logging goes, so just fail back
	 * to the caller if we can't read the default sb.  Suppress
	 * complaints, because the caller will be reading the same
	 * superblock again and running full verification on it, so
	 * whatever is bad will be reported then.
	 */
	sblock.fs_logbno = 0;
	badlog = 0;
	if (!read_super_block(0))
		return (1);

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
	    ((mount_point != NULL) && !mflag))) {
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
				exitstat = EXERRFATAL;
				return (0);
			}
			++badlog;
		}
	}

	/* Logging UFS may be enabled */
	if (sblock.fs_logbno) {
		++islog;

		/* log is not okay; check the fs */
		if (FSOKAY != (sblock.fs_state + sblock.fs_time))
			return (1);

		/*
		 * If logging or (stable and mounted) then continue
		 */
		if (!((sblock.fs_clean == FSLOG) ||
		    (sblock.fs_clean == FSSTABLE) && (mount_point != NULL)))
			return (1);

		/* get the log allocation block */
		buf = malloc(dev_bsize);
		if (buf == NULL) {
			return (1);
		}
		ud_buf = malloc(dev_bsize);
		if (ud_buf == NULL) {
			free(buf);
			return (1);
		}
		(void) fsck_bread(fsreadfd, buf,
		    logbtodb(&sblock, sblock.fs_logbno),
		    dev_bsize);
		ebp = (extent_block_t *)buf;

		/* log allocation block is not okay; check the fs */
		if (ebp->type != LUFS_EXTENTS) {
			free(buf);
			free(ud_buf);
			return (1);
		}

		/* get the log state block(s) */
		if (fsck_bread(fsreadfd, ud_buf,
		    (logbtodb(&sblock, ebp->extents[0].pbno)),
		    dev_bsize)) {
			(void) fsck_bread(fsreadfd, ud_buf,
			    (logbtodb(&sblock, ebp->extents[0].pbno)) + 1,
			    dev_bsize);
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
		    (ul->un_badlog == 0) && (!badlog)) {
			++islogok;
		}
		free(ud_buf);
		free(buf);
		free(ul);
	}

	return (1);
}

/*
 * - given a pathname, determine the pathname to actually check
 * - if a directory
 *   - if it is in mnttab, set devstr to the special (block) name
 *   - if it is in vfstab, set devstr to the special (block) name
 *   - if it has not been found, bail
 * - a file is used as-is, clear rflag
 * - a device is converted to block version (so can search mnttab)
 */
static void
derive_devstr(const caddr_t dev, caddr_t devstr, size_t str_size)
{
	mode_t mode;
	struct stat statb;

	if (stat(dev, &statb) < 0) {
		exitstat = EXNOSTAT;
		errexit("fsck: could not stat %s: %s", dev, strerror(errno));
	}

	mode = statb.st_mode & S_IFMT;
	switch (mode) {
	case S_IFDIR:
		/*
		 * The check_*() routines update devstr with the name.
		 */
		devstr[0] = '\0';
		if (!(check_mnttab(dev, devstr, str_size) ||
		    check_vfstab(dev, devstr, str_size))) {
			exitstat = EXBADPARM;
			errexit(
		    "fsck: could not find mountpoint %s in mnttab nor vfstab",
			    dev);
		}
		break;
	case S_IFREG:
		rflag = 0;
		(void) strlcpy(devstr, dev, str_size);
		break;
	case S_IFCHR:
	case S_IFBLK:
		(void) strlcpy(devstr, unrawname(dev), str_size);
		break;
	default:
		exitstat = EXBADPARM;
		errexit("fsck: %s must be a mountpoint, device, or file", dev);
		/* NOTREACHED */
	}
}

/*
 * Reports the index of the magic filesystem that mntp names.
 * If it does not correspond any of them, returns zero (hence
 * the backwards loop).
 */
static int
which_corefs(const caddr_t mntp)
{
	int corefs;

	for (corefs = MAGIC_LIMIT - 1; corefs > 0; corefs--)
		if (strcmp(mntp, magic_fs[corefs]) == 0)
			break;

	return (corefs);
}

/*
 * - set mount_point to NULL
 * - if name is mounted (search mnttab)
 *   - if it is a device, clear rflag
 *   - if mounted on /, /usr, or /var, set corefs
 *   - if corefs and read-only, set hotroot and continue
 *   - if errorlocked, continue
 *   - if preening, bail
 *   - ask user whether to continue, bail if not
 * - if it is a device and not mounted and rflag, convert
 *   name to raw version
 */
static int
check_mount_state(caddr_t devstr, size_t str_size)
{
	int corefs = 0;
	int is_dev = 0;
	struct stat statb;

	if (stat(devstr, &statb) < 0) {
		exitstat = EXNOSTAT;
		errexit("fsck: could not stat %s: %s", devstr, strerror(errno));
	}
	if (S_ISCHR(statb.st_mode) || S_ISBLK(statb.st_mode))
		is_dev = 1;

	/*
	 * mounted() will update mount_point when returning true.
	 */
	mount_point = NULL;
	if ((mountedfs = mounted(devstr, devstr, str_size)) != M_NOMNT) {
		if (is_dev)
			rflag = 0;
		corefs = which_corefs(mount_point);
		if (corefs && (mountedfs == M_RO)) {
			hotroot++;
		} else if (errorlocked) {
			goto carry_on;
		} else if (preen) {
			exitstat = EXMOUNTED;
			pfatal("%s IS CURRENTLY MOUNTED%s.",
			    devstr, mountedfs == M_RW ? " READ/WRITE" : "");
		} else {
			if (!nflag && !mflag) {
				pwarn("%s IS CURRENTLY MOUNTED READ/%s.",
				    devstr, mountedfs == M_RW ? "WRITE" :
				    "ONLY");
				if (reply("CONTINUE") == 0) {
					exitstat = EXMOUNTED;
					errexit("Program terminated");
				}
			}
		}
	} else if (is_dev && rflag) {
		(void) strlcpy(devstr, rawname(devstr), str_size);
	}

carry_on:
	return (corefs);
}

static int
open_and_intro(caddr_t devstr, int corefs)
{
	int retval = 0;

	if ((fsreadfd = open64(devstr, O_RDONLY)) < 0) {
		(void) printf("Can't open %s: %s\n", devstr, strerror(errno));
		exitstat = EXNOSTAT;
		retval = -1;
		goto finish;
	}
	if (!preen || debug != 0)
		(void) printf("** %s", devstr);

	if (errorlocked) {
		if (debug && elock_combuf != NULL)
			(void) printf(" error-lock comment: \"%s\" ",
			    elock_combuf);
		fflag = 1;
	}
	pid = getpid();
	if (nflag || roflag || (fswritefd = open64(devstr, O_WRONLY)) < 0) {
		fswritefd = -1;
		if (preen && !debug)
			pfatal("(NO WRITE ACCESS)\n");
		(void) printf(" (NO WRITE)");
	}
	if (!preen)
		(void) printf("\n");
	else if (debug)
		(void) printf(" pid %d\n", pid);
	if (debug && (hotroot || (mountedfs != M_NOMNT))) {
		(void) printf("** %s", devstr);
		if (hotroot)
			(void) printf(" is %s fs", magic_fs[corefs]);
		if (mountedfs != M_NOMNT)
			(void) printf(" and is mounted read-%s",
			    (mountedfs == M_RO) ? "only" : "write");
		if (errorlocked)
			(void) printf(" and is error-locked");

		(void) printf(".\n");
	}

finish:
	return (retval);
}

static int
find_superblock(caddr_t devstr)
{
	int cg = 0;
	int retval = 0;
	int first;
	int found;
	calcsb_t style;
	struct fs proto;

	/*
	 * Check the superblock, looking for alternates if necessary.
	 * In more-recent times, some UFS instances get created with
	 * only the first ten and last ten superblock backups.  Since
	 * if we can't get the necessary information from any of those,
	 * the odds are also against us for the ones in between, we'll
	 * just look at those twenty to save time.
	 */
	if (!read_super_block(1) || !checksb(1)) {
		if (bflag || preen) {
			retval = -1;
			goto finish;
		}
		for (style = MKFS_STYLE; style < MAX_SB_STYLES; style++) {
			if (reply("LOOK FOR ALTERNATE SUPERBLOCKS WITH %s",
			    calcsb_names[style]) == 0)
				continue;
			first = 1;
			found = 0;
			if (!calcsb(style, devstr, fsreadfd, &proto)) {
				cg = proto.fs_ncg;
				continue;
			}
			if (debug) {
				(void) printf(
			    "debug: calcsb(%s) gave fpg %d, cgoffset %d, ",
				    calcsb_names[style],
				    proto.fs_fpg, proto.fs_cgoffset);
				(void) printf("cgmask 0x%x, sblk %d, ncg %d\n",
				    proto.fs_cgmask, proto.fs_sblkno,
				    proto.fs_ncg);
			}
			for (cg = 0; cg < proto.fs_ncg; cg++) {
				bflag = fsbtodb(&proto, cgsblock(&proto, cg));
				if (debug)
					(void) printf(
					    "debug: trying block %lld\n",
					    (longlong_t)bflag);
				if (read_super_block(0) && checksb(0)) {
					(void) printf(
				    "FOUND ALTERNATE SUPERBLOCK %d WITH %s\n",
					    bflag, calcsb_names[style]);
					if (reply(
					    "USE ALTERNATE SUPERBLOCK") == 1) {
						found = 1;
						break;
					}
				}
				if (first && (cg >= 9)) {
					first = 0;
					if (proto.fs_ncg <= 9)
						cg = proto.fs_ncg;
					else if (proto.fs_ncg <= 19)
						cg = 9;
					else
						cg = proto.fs_ncg - 10;
				}
			}

			if (found)
				break;
		}

		/*
		 * Didn't find one?  Try to fake it.
		 */
		if (style >= MAX_SB_STYLES) {
			pwarn("SEARCH FOR ALTERNATE SUPERBLOCKS FAILED.\n");
			for (style = MKFS_STYLE; style < MAX_SB_STYLES;
			    style++) {
				if (reply("USE GENERIC SUPERBLOCK FROM %s",
				    calcsb_names[style]) == 1 &&
				    calcsb(style, devstr, fsreadfd, &sblock)) {
					break;
				}
			}
			/*
			 * We got something from mkfs/newfs, so use it.
			 */
			if (style < MAX_SB_STYLES) {
				proto.fs_ncg = sblock.fs_ncg;
				bflag = 0;
			}
		}

		/*
		 * Still no luck?  Tell the user they're on their own.
		 */
		if (style >= MAX_SB_STYLES) {
			pwarn("SEARCH FOR ALTERNATE SUPERBLOCKS FAILED. "
			    "YOU MUST USE THE -o b OPTION\n"
			    "TO FSCK TO SPECIFY THE LOCATION OF A VALID "
			    "ALTERNATE SUPERBLOCK TO\n"
			    "SUPPLY NEEDED INFORMATION; SEE fsck(1M).\n");
			bflag = 0;
			retval = -1;
			goto finish;
		}

		/*
		 * Need to make sure a human really wants us to use
		 * this.  -y mode could've gotten us this far, so
		 * we need to ask something that has to be answered
		 * in the negative.
		 *
		 * Note that we can't get here when preening.
		 */
		if (!found) {
			pwarn("CALCULATED GENERIC SUPERBLOCK WITH %s\n",
			    calcsb_names[style]);
		} else {
			pwarn("FOUND ALTERNATE SUPERBLOCK AT %d USING %s\n",
			    bflag, calcsb_names[style]);
		}
		pwarn("If filesystem was created with manually-specified ");
		pwarn("geometry, using\nauto-discovered superblock may ");
		pwarn("result in irrecoverable damage to\nfilesystem and ");
		pwarn("user data.\n");
		if (reply("CANCEL FILESYSTEM CHECK") == 1) {
			if (cg >= 0) {
				pwarn("Please verify that the indicated block "
				    "contains a proper\nsuperblock for the "
				    "filesystem (see fsdb(1M)).\n");
				if (yflag)
					pwarn("\nFSCK was running in YES "
					    "mode.  If you wish to run in "
					    "that mode using\nthe alternate "
					    "superblock, run "
					    "`fsck -y -o b=%d %s'.\n",
					    bflag, devstr);
			}
			retval = -1;
			goto finish;
		}

		/*
		 * Pretend we found it as an alternate, so everything
		 * gets updated when we clean up at the end.
		 */
		if (!found) {
			havesb = 1;
			sblk.b_bno = fsbtodb(&sblock, cgsblock(&sblock, 0));
			bwrite(fswritefd, (caddr_t)&sblock, SBLOCK, SBSIZE);
			write_altsb(fswritefd);
		}
	}

finish:
	return (retval);
}

/*
 * Check and potentially fix certain fields in the super block.
 */
static void
fixup_superblock(void)
{
	/*
	 * Kernel looks for FS_OPTTIME, and assumes that if that's not
	 * what's there, it must be FS_OPTSPACE, so not fixing does not
	 * require setting iscorrupt.
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
		} else if (sblock.fs_minfree < 0) {
			/*
			 * Kernel uses minfree without verification,
			 * and a negative value would do bad things.
			 */
			iscorrupt = 1;
		}
	}
}

static int
initial_error_state_adjust(void)
{
	int retval = 0;

	/* do this right away to prevent any other fscks on this fs */
	switch (sblock.fs_clean) {
	case FSBAD:
		break;
	case FSFIX:
		if (preen)
			errexit("ERROR-LOCKED; MARKED \"FSFIX\"\n");
		if (reply("marked FSFIX, CONTINUE") == 0) {
			retval = -1;
			goto finish;
		}
		break;
	case FSCLEAN:
		if (preen)
			errexit("ERROR-LOCKED; MARKED \"FSCLEAN\"\n");
		if (reply("marked FSCLEAN, CONTINUE") == 0) {
			retval = -1;
			goto finish;
		}
		break;
	default:
		if (preen) {
			if (debug)
				pwarn("ERRORLOCKED; NOT MARKED \"FSBAD\"\n");
			else
				errexit("ERRORLOCKED; NOT MARKED \"FSBAD\"\n");
		} else {
			(void) printf("error-locked but not marked \"FSBAD\";");
			if (reply(" CONTINUE") == 0) {
				retval = -1;
				goto finish;
			}
		}
		break;
	}

	if (!do_errorlock(LOCKFS_ELOCK)) {
		if (preen) {
			retval = -1;
			goto finish;
		}
		if (reply("error-lock reset failed; CONTINUE") == 0) {
			retval = -1;
			goto finish;
		}
	}

	sblock.fs_state = FSOKAY - (long)sblock.fs_time;
	sblock.fs_clean = FSFIX;
	sbdirty();
	write_altsb(fswritefd);

finish:
	return (retval);
}

static void
getsummaryinfo(void)
{
	size_t size;
	int failed;
	int asked;
	int i, j;
	caddr_t sip;

	/*
	 * read in the summary info.
	 */
	sblock.fs_u.fs_csp = calloc(1, sblock.fs_cssize);
	if (sblock.fs_u.fs_csp == NULL)
		errexit(
	    "cannot allocate %u bytes for cylinder group summary info\n",
		    (unsigned)sblock.fs_cssize);
	sip = (caddr_t)sblock.fs_u.fs_csp;
	asked = 0;
	for (i = 0, j = 0; i < sblock.fs_cssize; i += sblock.fs_bsize, j++) {
		size = sblock.fs_cssize - i < sblock.fs_bsize ?
			sblock.fs_cssize - i : sblock.fs_bsize;
		failed = fsck_bread(fsreadfd, sip,
		    fsbtodb(&sblock, sblock.fs_csaddr + j * sblock.fs_frag),
		    size);
		if (failed && !asked) {
			pfatal("BAD SUMMARY INFORMATION");
			if (reply("CONTINUE") == 0) {
				ckfini();
				exit(EXFNDERRS);
			}
			asked = 1;
		}
		sip += size;
	}
}

/*
 * Reverses the effects of getsummaryinfo().
 */
static void
ungetsummaryinfo(void)
{
	if ((sblk.b_un.b_fs != NULL) &&
	    (sblk.b_un.b_fs->fs_u.fs_csp != NULL)) {
		free(sblk.b_un.b_fs->fs_u.fs_csp);
		sblk.b_un.b_fs->fs_u.fs_csp = NULL;
	}
}

/*
 * Allocate and initialize the global tables.
 * It is the responsibility of the caller to clean up and allocations
 * if an error is returned.
 */
static int
create_and_init_maps(void)
{
	int64_t bmapsize;
	int retval = 0;

	maxfsblock = sblock.fs_size;
	maxino = sblock.fs_ncg * sblock.fs_ipg;

	bmapsize = roundup(howmany((uint64_t)maxfsblock, NBBY),
	    sizeof (short));
	blockmap = calloc((size_t)bmapsize, sizeof (char));
	if (blockmap == NULL) {
		(void) printf("cannot alloc %lld bytes for blockmap\n",
		    (longlong_t)bmapsize);
		retval = -1;
		goto finish;
	}
	statemap = calloc((size_t)(maxino + 1), sizeof (*statemap));
	if (statemap == NULL) {
		(void) printf("cannot alloc %lld bytes for statemap\n",
		    (longlong_t)(maxino + 1) * sizeof (*statemap));
		retval = -1;
		goto finish;
	}
	lncntp = (short *)calloc((size_t)(maxino + 1), sizeof (short));
	if (lncntp == NULL) {
		(void) printf("cannot alloc %lld bytes for lncntp\n",
		    (longlong_t)(maxino + 1) * sizeof (short));
		retval = -1;
		goto finish;
	}

	/*
	 * If we had to fake up a superblock, it won't show that there
	 * are any directories at all.  This causes problems when we
	 * use numdirs to calculate hash keys, so use something at least
	 * vaguely plausible.
	 */
	numdirs = sblock.fs_cstotal.cs_ndir;
	if (numdirs == 0)
		numdirs = sblock.fs_ipg * sblock.fs_ncg / 2;
	listmax = numdirs + 10;
	inpsort = (struct inoinfo **)calloc((unsigned)listmax,
	    sizeof (struct inoinfo *));
	inphead = (struct inoinfo **)calloc((unsigned)numdirs,
	    sizeof (struct inoinfo *));
	if (inpsort == NULL || inphead == NULL) {
		(void) printf("cannot alloc %lld bytes for inphead\n",
		    (longlong_t)numdirs * sizeof (struct inoinfo *));
		retval = -1;
		goto finish;
	}
	if (debug) {
		if (listmax > ULONG_MAX)
			errexit("create_and_init_maps: listmax overflowed\n");
		if (numdirs > ULONG_MAX)
			errexit("create_and_init_maps: numdirs overflowed\n");
	}

	numacls = numdirs;
	aclmax = numdirs + 10;
	aclpsort = (struct inoinfo **)calloc((unsigned)aclmax,
	    sizeof (struct inoinfo *));
	aclphead = (struct inoinfo **)calloc((unsigned)numacls,
	    sizeof (struct inoinfo *));
	if (aclpsort == NULL || aclphead == NULL) {
		(void) printf("cannot alloc %lld bytes for aclphead\n",
		    (longlong_t)numacls * sizeof (struct inoinfo *));
		retval = -1;
		goto finish;
	}
	if (debug) {
		if (aclmax > ULONG_MAX)
			errexit("create_and_init_maps: aclmax overflowed\n");
		if (numacls > ULONG_MAX)
			errexit("create_and_init_maps: numacls overflowed\n");
	}
	aclplast = 0L;
	inplast = 0L;

finish:
	return (retval);
}

caddr_t
setup(caddr_t dev)
{
	int corefs;
	static char devstr[MAXPATHLEN + 1];

	havesb = 0;
	devname = devstr;

	derive_devstr(dev, devstr, sizeof (devstr));
	errorlocked = is_errorlocked(devstr);
	corefs = check_mount_state(devstr, sizeof (devstr));

	sblock_init();

	if (open_and_intro(devstr, corefs) == -1)
		goto cleanup;

	if (mflag && mounted(devstr, devstr,
	    sizeof (devstr)) == M_RW)
		return (devstr);

	/*
	 * Check log state
	 */
	if (!logsetup(devstr))
		goto cleanup;

	/*
	 * Flush fs if we're going to do anything other than a sanity check.
	 * Note, if logging then the fs was already flushed in logsetup().
	 */
	if (!islog && !mflag)
		flush_fs();

	if (find_superblock(devstr) == -1)
		goto cleanup;

	fixup_superblock();

	if (errorlocked &&
	    (initial_error_state_adjust() == -1))
		goto cleanup;

	/*
	 * asblk could be dirty because we found a mismatch between
	 * the primary superblock and one of its backups in checksb().
	 */
	if (asblk.b_dirty && !bflag) {
		(void) memmove(&altsblock, &sblock, (size_t)sblock.fs_sbsize);
		flush(fswritefd, &asblk);
	}

	getsummaryinfo();

	/*
	 * if not error-locked, using the standard superblock,
	 *   not bad log, not forced, preening, and is clean;
	 *   stop checking
	 */
	if (!errorlocked && (bflag == 0) &&
	    ((!islog || islogok) &&
	    (fflag == 0) && preen &&
	    (FSOKAY == (sblock.fs_state + sblock.fs_time)) &&
	    ((sblock.fs_clean == FSLOG && islog) ||
	    ((sblock.fs_clean == FSCLEAN) || (sblock.fs_clean == FSSTABLE))))) {
		iscorrupt = 0;
		printclean();
		goto cleanup;
	}

	if (create_and_init_maps() == -1)
		goto nomaps;

	bufinit();
	return (devstr);

nomaps:
	ckfini();
	exitstat = EXERRFATAL;
	/* FALLTHROUGH */

cleanup:
	unbufinit();
	uncreate_maps();
	ungetsummaryinfo();

	/*
	 * Can't get rid of the superblock buffer, because our
	 * caller references it to generate the summary statistics.
	 */

	return (NULL);
}

/*
 * Undoes the allocations in create_and_init_maps()
 */
static void
uncreate_maps(void)
{
	/*
	 * No ordering dependency amongst these, so they are here in
	 * the same order they were calculated.
	 */
	if (blockmap != NULL)
		free(blockmap);
	if (statemap != NULL)
		free(statemap);
	if (lncntp != NULL)
		free(lncntp);
	if (inpsort != NULL)
		free(inpsort);
	if (inphead != NULL)
		free(inphead);
	if (aclpsort != NULL)
		free(aclpsort);
	if (aclphead != NULL)
		free(aclphead);
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
	caddr_t err;

	/*
	 * When the fs check is successfully completed, the alternate super
	 * block at sblk.b_bno will be overwritten by ckfini() with the
	 * repaired super block.
	 */
	sblk.b_bno = bflag ? bflag : (SBOFF / dev_bsize);
	sblk.b_size = SBSIZE;

	/*
	 * Sanity-check some of the values we are going to use later
	 * in allocation requests.
	 */
	if (sblock.fs_cstotal.cs_ndir < 1 ||
	    sblock.fs_cstotal.cs_ndir > sblock.fs_ncg * sblock.fs_ipg) {
		if (verbose)
			(void) printf(
	    "Found %d directories, should be between 1 and %d inclusive.\n",
			    sblock.fs_cstotal.cs_ndir,
			    sblock.fs_ncg * sblock.fs_ipg);
		err = "NUMBER OF DIRECTORIES OUT OF RANGE";
		goto failedsb;
	}

	if (sblock.fs_nrpos <= 0 || sblock.fs_postbloff < 0 ||
	    sblock.fs_cpc < 0 ||
	    (sblock.fs_postbloff +
	    (sblock.fs_nrpos * sblock.fs_cpc * sizeof (short))) >
	    sblock.fs_sbsize) {
		err = "ROTATIONAL POSITION TABLE SIZE OUT OF RANGE";
		goto failedsb;
	}

	if (sblock.fs_cssize !=
	    fragroundup(&sblock, sblock.fs_ncg * sizeof (struct csum))) {
		err = "SIZE OF CYLINDER GROUP SUMMARY AREA WRONG";
		goto failedsb;
	}

	if (sblock.fs_inopb != (sblock.fs_bsize / sizeof (struct dinode))) {
		err = "INOPB NONSENSICAL RELATIVE TO BSIZE";
		goto failedsb;
	}

	if (sblock.fs_bsize > MAXBSIZE) {
		err = "BLOCK SIZE LARGER THAN MAXIMUM SUPPORTED";
		goto failedsb;
	}

	if (sblock.fs_bsize != (sblock.fs_frag * sblock.fs_fsize)) {
		err = "FRAGS PER BLOCK OR FRAG SIZE WRONG";
		goto failedsb;
	}

	if (sblock.fs_dsize >= sblock.fs_size) {
		err = "NUMBER OF DATA BLOCKS OUT OF RANGE";
		goto failedsb;
	}

#if 0
	if (sblock.fs_size >
	    (sblock.fs_nsect * sblock.fs_ntrak * sblock.fs_ncyl)) {
		err = "FILESYSTEM SIZE LARGER THAN DEVICE";
		goto failedsb;
	}
#endif

	/*
	 *  Check that the number of inodes per group isn't less than or
	 *  equal to zero.  Also makes sure it isn't more than the
	 *  maximum number mkfs enforces.
	 */
	if (sblock.fs_ipg <= 0 || sblock.fs_ipg > MAXIpG) {
		err = "INODES PER GROUP OUT OF RANGE";
		goto failedsb;
	}

	if (sblock.fs_cgsize > sblock.fs_bsize) {
		err = "CG HEADER LARGER THAN ONE BLOCK";
		goto failedsb;
	}

	/*
	 * Set all possible fields that could differ, then do check
	 * of whole super block against an alternate super block.
	 * When an alternate super-block is specified this check is skipped.
	 */
	(void) getblk(&asblk, cgsblock(&sblock, sblock.fs_ncg - 1),
	    (size_t)sblock.fs_sbsize);
	if (asblk.b_errs != 0) {
		brelse(&asblk);
		return (0);
	}
	if (bflag != 0) {
		/*
		 * Invalidate clean flag and state information.
		 * Note that we couldn't return until after the
		 * above getblk(), because we're going to want to
		 * update asblk when everything's done.
		 */
		sblock.fs_clean = FSACTIVE;
		sblock.fs_state = (long)sblock.fs_time;
		sblock.fs_reclaim = 0;
		sbdirty();
		havesb = 1;
		return (1);
	}
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
	(void) memmove((void *)altsblock.fs_fsmnt, (void *)sblock.fs_fsmnt,
	    sizeof (sblock.fs_fsmnt));
	/*
	 * The following should not have to be copied.
	 */
	(void) memmove((void *)altsblock.fs_u.fs_csp_pad,
	    (void *)sblock.fs_u.fs_csp_pad, sizeof (sblock.fs_u.fs_csp_pad));
	altsblock.fs_fsbtodb = sblock.fs_fsbtodb;
	altsblock.fs_npsect = sblock.fs_npsect;
	altsblock.fs_nrpos = sblock.fs_nrpos;
	if (memcmp((void *)&sblock, (void *)&altsblock,
	    (size_t)sblock.fs_sbsize) != 0) {
		err = "BAD VALUES IN SUPER BLOCK";
		goto failedsb;
	}
	havesb = 1;
	return (1);

failedsb:
	badsb(listerr, err);
	return (0);
}

static void
badsb(int listerr, caddr_t s)
{
	if (!listerr)
		return;
	if (preen)
		(void) printf("%s: ", devname);
	(void) printf("BAD SUPERBLOCK AT BLOCK %d: %s\n",
	    bflag != 0 ? bflag : SBLOCK, s);
	if (preen) {
		pwarn(
	    "USE AN ALTERNATE SUPERBLOCK TO SUPPLY NEEDED INFORMATION;\n");
		pwarn("e.g. fsck [-F ufs] -o b=# [special ...] \n");
		exitstat = EXERRFATAL;
		pfatal(
	    "where # is the alternate super block. SEE fsck_ufs(1M). \n");
	}
	/* we're expected to return if not preening */
}

/*
 * Write out the super block into each of the alternate super blocks.
 */
void
write_altsb(int fd)
{
	int cylno;

	for (cylno = 0; cylno < sblock.fs_ncg; cylno++)
		bwrite(fd, (caddr_t)&sblock, fsbtodb(&sblock,
		    cgsblock(&sblock, cylno)), sblock.fs_sbsize);
}

static void
sblock_init(void)
{
	fsmodified = 0;
	if (errorlocked)
		isdirty = 1;
	lfdir = 0;
	initbarea(&sblk);
	initbarea(&asblk);

	/*
	 * May have buffer left over from previous filesystem check.
	 */
	if (sblk.b_un.b_buf == NULL)
		sblk.b_un.b_buf = calloc(1, SBSIZE);
	if (asblk.b_un.b_buf == NULL)
		asblk.b_un.b_buf = calloc(1, SBSIZE);
	if (sblk.b_un.b_buf == NULL || asblk.b_un.b_buf == NULL)
		errexit("cannot allocate space for superblock\n");
	/*
	 * Could get the actual sector size from the device here,
	 * but considering how much would need to change in the rest
	 * of the system before it'd be a problem for us, it's not
	 * worth worrying about right now.
	 */
	dev_bsize = secsize = DEV_BSIZE;
}

/*
 * Calculate a prototype superblock based on information in the disk label.
 * When done the cgsblock macro can be calculated and the fs_ncg field
 * can be used. Do NOT attempt to use other macros without verifying that
 * their needed information is available!
 *
 * In BSD, the disk label includes all sorts of useful information,
 * like cpg.  Solaris doesn't have that, and deriving it (as well as
 * some other parameters) is difficult.  Rather than duplicate the
 * code, just ask mkfs what it would've come up with by default.
 * Ideally, we'd just link in the code, but given the source base
 * involved, it's more practical to just get a binary dump.
 *
 * The one minor drawback to the above approach is that newfs and mkfs
 * will produce vastly different layouts for the same partition if
 * they're allowed to default everything.  So, if the superblock that
 * mkfs gives us doesn't work for guessing where the alternates are,
 * we need to try newfs.
 */
static int
calcsb(calcsb_t style, caddr_t dev, int devfd, struct fs *fs)
{
#define	FROM_CHILD	0
#define	TO_FSCK		1
#define	CMD_IDX		0
#define	DEV_IDX		3
#define	SIZE_IDX	4

	int child_pipe[2];
	caddr_t mkfsline[] = {
		"",		/* CMD_IDX */
		"-o",
		"calcbinsb,N",
		NULL,		/* DEV_IDX */
		NULL,		/* SIZE_IDX */
		NULL
	};
	caddr_t newfsline[] = {
		"",		/* CMD_IDX */
		"-B",
		"-N",
		NULL,		/* DEV_IDX */
		NULL
	};
	int pending, transferred;
	caddr_t *cmdline;
	caddr_t target;
	caddr_t sizestr = NULL;
	caddr_t path_old, path_new, mkfs_dir, mkfs_path, newfs_path;
	caddr_t slash;
	diskaddr_t size;
	int devnull;

	switch (style) {
	case MKFS_STYLE:
		if (debug)
			(void) printf("calcsb() going with style MKFS\n");
		cmdline = mkfsline;
		break;
	case NEWFS_STYLE:
		if (debug)
			(void) printf("calcsb() going with style NEWFS\n");
		cmdline = newfsline;
		break;
	default:
		if (debug)
			(void) printf("calcsb() doesn't undestand style %d\n",
			    style);
		return (0);
	}

	cmdline[DEV_IDX] = dev;

	/*
	 * Normally, only use the stock versions of the utilities.
	 * However, if we're debugging, the odds are that we're
	 * using experimental versions of them as well, so allow
	 * some flexibility.
	 */
	mkfs_path = getenv("MKFS_PATH");
	if (!debug || (mkfs_path == NULL))
		mkfs_path = MKFS_PATH;

	newfs_path = getenv("NEWFS_PATH");
	if (!debug || (newfs_path == NULL))
		newfs_path = NEWFS_PATH;

	if (style == MKFS_STYLE) {
		cmdline[CMD_IDX] = mkfs_path;

		size = getdisksize(dev, devfd);
		if (size == 0)
			return (0);

		(void) fsck_asprintf(&sizestr, "%lld", (longlong_t)size);
		cmdline[SIZE_IDX] = sizestr;
	} else if (style == NEWFS_STYLE) {
		/*
		 * Make sure that newfs will find the right version of mkfs.
		 */
		cmdline[CMD_IDX] = newfs_path;
		path_old = getenv("PATH");
		/* mkfs_path is always initialized, despite lint's concerns */
		mkfs_dir = strdup(mkfs_path);
		if (mkfs_dir == NULL)
			return (0);
		/*
		 * If no location data for mkfs, don't need to do
		 * anything about PATH.
		 */
		slash = strrchr(mkfs_dir, '/');
		if (slash != NULL) {
			/*
			 * Just want the dir, so discard the executable name.
			 */
			*slash = '\0';

			/*
			 * newfs uses system() to find mkfs, so make sure
			 * that the one we want to use is first on the
			 * list.  Don't free path_new upon success, as it
			 * has become part of the environment.
			 */
			(void) fsck_asprintf(&path_new, "PATH=%s:%s",
			    mkfs_dir, path_old);
			if (putenv(path_new) != 0) {
				free(mkfs_dir);
				free(path_new);
				return (0);
			}
		}
		free(mkfs_dir);
	} else {
		/*
		 * Bad search style, quietly return failure.
		 */
		if (debug) {
			(void) printf("calcsb: got bad style number %d\n",
			    (int)style);
		}
		return (0);
	}

	if (pipe(child_pipe) < 0) {
		pfatal("calcsb: could not create pipe: %s\n", strerror(errno));
		if (sizestr != NULL)
			free(sizestr);
		return (0);
	}

	switch (fork()) {
	case -1:
		pfatal("calcsb: fork failed: %s\n", strerror(errno));
		if (sizestr != NULL)
			free(sizestr);
		return (0);
	case 0:
		if (dup2(child_pipe[TO_FSCK], fileno(stdout)) < 0) {
			(void) printf(
			    "calcsb: could not rename file descriptor: %s\n",
			    strerror(errno));
			exit(EXBADPARM);
		}
		devnull = open("/dev/null", O_WRONLY);
		if (devnull == -1) {
			(void) printf("calcsb: could not open /dev/null: %s\n",
			    strerror(errno));
			exit(EXBADPARM);
		}
		if (dup2(devnull, fileno(stderr)) < 0) {
			(void) printf(
			    "calcsb: could not rename file descriptor: %s\n",
			    strerror(errno));
			exit(EXBADPARM);
		}
		(void) close(child_pipe[FROM_CHILD]);
		(void) execv(cmdline[CMD_IDX], cmdline);
		(void) printf("calcsb: could not exec %s: %s\n",
		    cmdline[CMD_IDX], strerror(errno));
		exit(EXBADPARM);
		/* NOTREACHED */
	default:
		break;
	}

	(void) close(child_pipe[TO_FSCK]);
	if (sizestr != NULL)
		free(sizestr);

	pending = sizeof (struct fs);
	target = (caddr_t)fs;
	do {
		transferred = read(child_pipe[FROM_CHILD], target, pending);
		pending -= transferred;
		target += transferred;
	} while ((pending > 0) && (transferred > 0));

	if (pending > 0) {
		if (transferred < 0)
			pfatal(
		    "calcsb: binary read of superblock from %s failed: %s\n",
			    (style == MKFS_STYLE) ? "mkfs" : "newfs",
			    (transferred < 0) ? strerror(errno) : "");
		else
			pfatal(
		    "calcsb: short read of superblock from %s\n",
			    (style == MKFS_STYLE) ? "mkfs" : "newfs");
		return (0);
	}

	(void) close(child_pipe[FROM_CHILD]);
	(void) wait(NULL);

	if ((fs->fs_magic != FS_MAGIC) &&
	    (fs->fs_magic != MTB_UFS_MAGIC))
		return (0);

	return (1);
}
