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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_SYS_FS_UFS_FS_H
#define	_SYS_FS_UFS_FS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>
#include <sys/types32.h>
#include <sys/t_lock.h>		/* for kmutex_t */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following values are minor release values for UFS.
 * The fs_version field in the superblock will equal one of them.
 */

#define		MTB_UFS_VERSION_MIN	1
#define		MTB_UFS_VERSION_1	1
#define		UFS_VERSION_MIN	0
#define		UFS_EFISTYLE4NONEFI_VERSION_2	2

/*
 * Each disk drive contains some number of file systems.
 * A file system consists of a number of cylinder groups.
 * Each cylinder group has inodes and data.
 *
 * A file system is described by its super-block, which in turn
 * describes the cylinder groups.  The super-block is critical
 * data and is replicated in the first 10 cylinder groups and the
 * the last 10 cylinder groups to protect against
 * catastrophic loss.  This is done at mkfs time and the critical
 * super-block data does not change, so the copies need not be
 * referenced further unless disaster strikes.
 *
 * For file system fs, the offsets of the various blocks of interest
 * are given in the super block as:
 *	[fs->fs_sblkno]		Super-block
 *	[fs->fs_cblkno]		Cylinder group block
 *	[fs->fs_iblkno]		Inode blocks
 *	[fs->fs_dblkno]		Data blocks
 * The beginning of cylinder group cg in fs, is given by
 * the ``cgbase(fs, cg)'' macro.
 *
 * The first boot and super blocks are given in absolute disk addresses.
 * The byte-offset forms are preferred, as they don't imply a sector size.
 */
#define	BBSIZE		8192
#define	SBSIZE		8192
#define	BBOFF		((off_t)(0))
#define	SBOFF		((off_t)(BBOFF + BBSIZE))
#define	BBLOCK		((daddr32_t)(0))
#define	SBLOCK		((daddr32_t)(BBLOCK + BBSIZE / DEV_BSIZE))

/*
 * Addresses stored in inodes are capable of addressing fragments
 * of `blocks'. File system blocks of at most size MAXBSIZE can
 * be optionally broken into 2, 4, or 8 pieces, each of which is
 * addressible; these pieces may be DEV_BSIZE, or some multiple of
 * a DEV_BSIZE unit.
 *
 * Large files consist of exclusively large data blocks.  To avoid
 * undue wasted disk space, the last data block of a small file may be
 * allocated as only as many fragments of a large block as are
 * necessary.  The file system format retains only a single pointer
 * to such a fragment, which is a piece of a single large block that
 * has been divided.  The size of such a fragment is determinable from
 * information in the inode, using the ``blksize(fs, ip, lbn)'' macro.
 *
 * The file system records space availability at the fragment level;
 * to determine block availability, aligned fragments are examined.
 *
 * The root inode is the root of the file system.
 * Inode 0 can't be used for normal purposes and
 * historically bad blocks were linked to inode 1,
 * thus the root inode is 2. (inode 1 is no longer used for
 * this purpose, however numerous dump tapes make this
 * assumption, so we are stuck with it)
 * The lost+found directory is given the next available
 * inode when it is created by ``mkfs''.
 */
#define	UFSROOTINO	((ino_t)2)	/* i number of all roots */
#define	LOSTFOUNDINO    (UFSROOTINO + 1)
#ifndef _LONGLONG_TYPE
#define	UFS_MAXOFFSET_T	MAXOFF_T
#define	UFS_FILESIZE_BITS	32
#else
#define	UFS_MAXOFFSET_T	((1LL << NBBY * sizeof (daddr32_t) + DEV_BSHIFT - 1) \
							- 1)
#define	UFS_FILESIZE_BITS	41
#endif /* _LONGLONG_TYPE */

/*
 * MINBSIZE is the smallest allowable block size.
 * In order to insure that it is possible to create files of size
 * 2^32 with only two levels of indirection, MINBSIZE is set to 4096.
 * MINBSIZE must be big enough to hold a cylinder group block,
 * thus changes to (struct cg) must keep its size within MINBSIZE.
 * Note that super blocks are always of size SBSIZE,
 * and that both SBSIZE and MAXBSIZE must be >= MINBSIZE.
 */
#define	MINBSIZE	4096

/*
 * The path name on which the file system is mounted is maintained
 * in fs_fsmnt. MAXMNTLEN defines the amount of space allocated in
 * the super block for this name.
 * The limit on the amount of summary information per file system
 * is defined by MAXCSBUFS. It is currently parameterized for a
 * maximum of two million cylinders.
 */
#define	MAXMNTLEN 512
#define	MAXCSBUFS 32

#define	LABEL_TYPE_VTOC		1
#define	LABEL_TYPE_EFI		2
#define	LABEL_TYPE_OTHER	3

/*
 * The following constant is taken from the ANSI T13 ATA Specification
 * and defines the maximum size (in sectors) that an ATA disk can be
 * and still has to provide CHS translation. For a disk above this
 * size all sectors are to be accessed via their LBA address. This
 * makes a good cut off value to move from disk provided geometry
 * to the predefined defaults used in efi label disks.
 */
#define	CHSLIMIT	(63 * 256 * 1024)

/*
 * Per cylinder group information; summarized in blocks allocated
 * from first cylinder group data blocks.  These blocks have to be
 * read in from fs_csaddr (size fs_cssize) in addition to the
 * super block.
 *
 * N.B. sizeof (struct csum) must be a power of two in order for
 * the ``fs_cs'' macro to work (see below).
 */
struct csum {
	int32_t	cs_ndir;	/* number of directories */
	int32_t	cs_nbfree;	/* number of free blocks */
	int32_t	cs_nifree;	/* number of free inodes */
	int32_t	cs_nffree;	/* number of free frags */
};

/*
 * In the 5.0 release, the file system state flag in the superblock (fs_clean)
 * is now used. The value of fs_clean can be:
 *	FSACTIVE	file system may have fsck inconsistencies
 *	FSCLEAN		file system has successfully unmounted (implies
 *			everything is ok)
 *	FSSTABLE	No fsck inconsistencies, no guarantee on user data
 *	FSBAD		file system is mounted from a partition that is
 *			neither FSCLEAN or FSSTABLE
 *	FSSUSPEND	Clean flag processing is temporarily disabled
 *	FSLOG		Logging file system
 * Under this scheme, fsck can safely skip file systems that
 * are FSCLEAN or FSSTABLE.  To provide additional safeguard,
 * fs_clean information could be trusted only if
 * fs_state == FSOKAY - fs_time, where FSOKAY is a constant
 *
 * Note: mount(2) will now return ENOSPC if fs_clean is neither FSCLEAN nor
 * FSSTABLE, or fs_state is not valid.  The exceptions are the root or
 * the read-only partitions
 */

/*
 * Super block for a file system.
 *
 * Most of the data in the super block is read-only data and needs
 * no explicit locking to protect it. Exceptions are:
 *	fs_time
 *	fs_optim
 *	fs_cstotal
 *	fs_fmod
 *	fs_cgrotor
 *	fs_flags   (largefiles flag - set when a file grows large)
 * These fields require the use of fs->fs_lock.
 */
#define	FS_MAGIC	0x011954
#define	MTB_UFS_MAGIC	0xdecade
#define	FSOKAY		(0x7c269d38)
/*  #define	FSOKAY		(0x7c269d38 + 3) */
/*
 * fs_clean values
 */
#define	FSACTIVE	((char)0)
#define	FSCLEAN		((char)0x1)
#define	FSSTABLE	((char)0x2)
#define	FSBAD		((char)0xff)	/* mounted !FSCLEAN and !FSSTABLE */
#define	FSSUSPEND	((char)0xfe)	/* temporarily suspended */
#define	FSLOG		((char)0xfd)	/* logging fs */
#define	FSFIX		((char)0xfc)	/* being repaired while mounted */

/*
 * fs_flags values
 */
#define	FSLARGEFILES	((char)0x1)	/* largefiles exist on filesystem */

struct  fs {
	uint32_t fs_link;		/* linked list of file systems */
	uint32_t fs_rolled;		/* logging only: fs fully rolled */
	daddr32_t fs_sblkno;		/* addr of super-block in filesys */
	daddr32_t fs_cblkno;		/* offset of cyl-block in filesys */
	daddr32_t fs_iblkno;		/* offset of inode-blocks in filesys */
	daddr32_t fs_dblkno;		/* offset of first data after cg */
	int32_t	fs_cgoffset;		/* cylinder group offset in cylinder */
	int32_t	fs_cgmask;		/* used to calc mod fs_ntrak */
	time32_t fs_time;		/* last time written */
	int32_t	fs_size;		/* number of blocks in fs */
	int32_t	fs_dsize;		/* number of data blocks in fs */
	int32_t	fs_ncg;			/* number of cylinder groups */
	int32_t	fs_bsize;		/* size of basic blocks in fs */
	int32_t	fs_fsize;		/* size of frag blocks in fs */
	int32_t	fs_frag;		/* number of frags in a block in fs */
/* these are configuration parameters */
	int32_t	fs_minfree;		/* minimum percentage of free blocks */
	int32_t	fs_rotdelay;		/* num of ms for optimal next block */
	int32_t	fs_rps;			/* disk revolutions per second */
/* these fields can be computed from the others */
	int32_t	fs_bmask;		/* ``blkoff'' calc of blk offsets */
	int32_t	fs_fmask;		/* ``fragoff'' calc of frag offsets */
	int32_t	fs_bshift;		/* ``lblkno'' calc of logical blkno */
	int32_t	fs_fshift;		/* ``numfrags'' calc number of frags */
/* these are configuration parameters */
	int32_t	fs_maxcontig;		/* max number of contiguous blks */
	int32_t	fs_maxbpg;		/* max number of blks per cyl group */
/* these fields can be computed from the others */
	int32_t	fs_fragshift;		/* block to frag shift */
	int32_t	fs_fsbtodb;		/* fsbtodb and dbtofsb shift constant */
	int32_t	fs_sbsize;		/* actual size of super block */
	int32_t	fs_csmask;		/* csum block offset */
	int32_t	fs_csshift;		/* csum block number */
	int32_t	fs_nindir;		/* value of NINDIR */
	int32_t	fs_inopb;		/* value of INOPB */
	int32_t	fs_nspf;		/* value of NSPF */
/* yet another configuration parameter */
	int32_t	fs_optim;		/* optimization preference, see below */
/* these fields are derived from the hardware */
	/* USL SVR4 compatibility */
#ifdef _LITTLE_ENDIAN
	/*
	 * USL SVR4 compatibility
	 *
	 * There was a significant divergence here between Solaris and
	 * SVR4 for x86.  By swapping these two members in the superblock,
	 * we get read-only compatibility of SVR4 filesystems.  Otherwise
	 * there would be no compatibility.  This change was introduced
	 * during bootstrapping of Solaris on x86.  By making this ifdef'ed
	 * on byte order, we provide ongoing compatibility across all
	 * platforms with the same byte order, the highest compatibility
	 * that can be achieved.
	 */
	int32_t	fs_state;		/* file system state time stamp */
#else
	int32_t	fs_npsect;		/* # sectors/track including spares */
#endif
	int32_t fs_si;			/* summary info state - lufs only */
	int32_t	fs_trackskew;		/* sector 0 skew, per track */
/* a unique id for this filesystem (currently unused and unmaintained) */
/* In 4.3 Tahoe this space is used by fs_headswitch and fs_trkseek */
/* Neither of those fields is used in the Tahoe code right now but */
/* there could be problems if they are.				*/
	int32_t	fs_id[2];		/* file system id */
/* sizes determined by number of cylinder groups and their sizes */
	daddr32_t fs_csaddr;		/* blk addr of cyl grp summary area */
	int32_t	fs_cssize;		/* size of cyl grp summary area */
	int32_t	fs_cgsize;		/* cylinder group size */
/* these fields are derived from the hardware */
	int32_t	fs_ntrak;		/* tracks per cylinder */
	int32_t	fs_nsect;		/* sectors per track */
	int32_t	fs_spc;			/* sectors per cylinder */
/* this comes from the disk driver partitioning */
	int32_t	fs_ncyl;		/* cylinders in file system */
/* these fields can be computed from the others */
	int32_t	fs_cpg;			/* cylinders per group */
	int32_t	fs_ipg;			/* inodes per group */
	int32_t	fs_fpg;			/* blocks per group * fs_frag */
/* this data must be re-computed after crashes */
	struct	csum fs_cstotal;	/* cylinder summary information */
/* these fields are cleared at mount time */
	char	fs_fmod;		/* super block modified flag */
	char	fs_clean;		/* file system state flag */
	char	fs_ronly;		/* mounted read-only flag */
	char	fs_flags;		/* largefiles flag, etc. */
	char	fs_fsmnt[MAXMNTLEN];	/* name mounted on */
/* these fields retain the current block allocation info */
	int32_t	fs_cgrotor;		/* last cg searched */
	/*
	 * The following used to be fs_csp[MAXCSBUFS]. It was not
	 * used anywhere except in old utilities.  We removed this
	 * in 5.6 and expect fs_u.fs_csp to be used instead.
	 * We no longer limit fs_cssize based on MAXCSBUFS.
	 */
	union { 			/* fs_cs (csum) info */
		uint32_t fs_csp_pad[MAXCSBUFS];
		struct csum *fs_csp;
	} fs_u;
	int32_t	fs_cpc;			/* cyl per cycle in postbl */
	short	fs_opostbl[16][8];	/* old rotation block list head */
	int32_t	fs_sparecon[51];	/* reserved for future constants */
	int32_t fs_version;		/* minor version of ufs */
	int32_t	fs_logbno;		/* block # of embedded log */
	int32_t fs_reclaim;		/* reclaim open, deleted files */
	int32_t	fs_sparecon2;		/* reserved for future constant */
#ifdef _LITTLE_ENDIAN
	/* USL SVR4 compatibility */
	int32_t	fs_npsect;		/* # sectors/track including spares */
#else
	int32_t	fs_state;		/* file system state time stamp */
#endif
	quad_t	fs_qbmask;		/* ~fs_bmask - for use with quad size */
	quad_t	fs_qfmask;		/* ~fs_fmask - for use with quad size */
	int32_t	fs_postblformat;	/* format of positional layout tables */
	int32_t	fs_nrpos;		/* number of rotaional positions */
	int32_t	fs_postbloff;		/* (short) rotation block list head */
	int32_t	fs_rotbloff;		/* (uchar_t) blocks for each rotation */
	int32_t	fs_magic;		/* magic number */
	uchar_t	fs_space[1];		/* list of blocks for each rotation */
/* actually longer */
};

/*
 * values for fs_reclaim
 */
#define	FS_RECLAIM	(0x00000001)	/* run the reclaim-files thread */
#define	FS_RECLAIMING	(0x00000002)	/* running the reclaim-files thread */
#define	FS_CHECKCLEAN	(0x00000004)	/* checking for a clean file system */
#define	FS_CHECKRECLAIM	(0x00000008)	/* checking for a reclaimable file */

/*
 * values for fs_rolled
 */
#define	FS_PRE_FLAG	0	/* old system, prior to fs_rolled flag */
#define	FS_ALL_ROLLED	1
#define	FS_NEED_ROLL	2

/*
 * values for fs_si, logging only
 * si is the summary of the summary - a copy of the cylinder group summary
 * info held in an array for perf. On a mount if this is out of date
 * (FS_SI_BAD) it can be re-constructed by re-reading the cgs.
 */
#define	FS_SI_OK	0	/* on-disk summary info ok */
#define	FS_SI_BAD	1	/* out of date on-disk si */

/*
 * Preference for optimization.
 */
#define	FS_OPTTIME	0	/* minimize allocation time */
#define	FS_OPTSPACE	1	/* minimize disk fragmentation */

/*
 * Rotational layout table format types
 */
#define	FS_42POSTBLFMT		-1	/* 4.2BSD rotational table format */
#define	FS_DYNAMICPOSTBLFMT	1	/* dynamic rotational table format */

/*
 * Macros for access to superblock array structures
 */
#ifdef _KERNEL
#define	fs_postbl(ufsvfsp, cylno) \
	(((ufsvfsp)->vfs_fs->fs_postblformat != FS_DYNAMICPOSTBLFMT) \
	? ((ufsvfsp)->vfs_fs->fs_opostbl[cylno]) \
	: ((short *)((char *)(ufsvfsp)->vfs_fs + \
	(ufsvfsp)->vfs_fs->fs_postbloff) \
	+ (cylno) * (ufsvfsp)->vfs_nrpos))
#else
#define	fs_postbl(fs, cylno) \
	(((fs)->fs_postblformat != FS_DYNAMICPOSTBLFMT) \
	? ((fs)->fs_opostbl[cylno]) \
	: ((short *)((char *)(fs) + \
	(fs)->fs_postbloff) \
	+ (cylno) * (fs)->fs_nrpos))
#endif

#define	fs_rotbl(fs) \
	(((fs)->fs_postblformat != FS_DYNAMICPOSTBLFMT) \
	? ((fs)->fs_space) \
	: ((uchar_t *)((char *)(fs) + (fs)->fs_rotbloff)))

/*
 * Convert cylinder group to base address of its global summary info.
 *
 * N.B. This macro assumes that sizeof (struct csum) is a power of two.
 * We just index off the first entry into one big array
 */

#define	fs_cs(fs, indx) fs_u.fs_csp[(indx)]

/*
 * Cylinder group block for a file system.
 *
 * Writable fields in the cylinder group are protected by the associated
 * super block lock fs->fs_lock.
 */
#define	CG_MAGIC	0x090255
struct	cg {
	uint32_t cg_link;		/* NOT USED linked list of cyl groups */
	int32_t	cg_magic;		/* magic number */
	time32_t cg_time;		/* time last written */
	int32_t	cg_cgx;			/* we are the cgx'th cylinder group */
	short	cg_ncyl;		/* number of cyl's this cg */
	short	cg_niblk;		/* number of inode blocks this cg */
	int32_t	cg_ndblk;		/* number of data blocks this cg */
	struct	csum cg_cs;		/* cylinder summary information */
	int32_t	cg_rotor;		/* position of last used block */
	int32_t	cg_frotor;		/* position of last used frag */
	int32_t	cg_irotor;		/* position of last used inode */
	int32_t	cg_frsum[MAXFRAG];	/* counts of available frags */
	int32_t	cg_btotoff;		/* (int32_t)block totals per cylinder */
	int32_t	cg_boff;		/* (short) free block positions */
	int32_t	cg_iusedoff;		/* (char) used inode map */
	int32_t	cg_freeoff;		/* (uchar_t) free block map */
	int32_t	cg_nextfreeoff;		/* (uchar_t) next available space */
	int32_t	cg_sparecon[16];	/* reserved for future use */
	uchar_t	cg_space[1];		/* space for cylinder group maps */
/* actually longer */
};

/*
 * Macros for access to cylinder group array structures
 */

#define	cg_blktot(cgp) \
	(((cgp)->cg_magic != CG_MAGIC) \
	? (((struct ocg *)(cgp))->cg_btot) \
	: ((int32_t *)((char *)(cgp) + (cgp)->cg_btotoff)))

#ifdef _KERNEL
#define	cg_blks(ufsvfsp, cgp, cylno) \
	(((cgp)->cg_magic != CG_MAGIC) \
	? (((struct ocg *)(cgp))->cg_b[cylno]) \
	: ((short *)((char *)(cgp) + (cgp)->cg_boff) + \
	(cylno) * (ufsvfsp)->vfs_nrpos))
#else
#define	cg_blks(fs, cgp, cylno) \
	(((cgp)->cg_magic != CG_MAGIC) \
	? (((struct ocg *)(cgp))->cg_b[cylno]) \
	: ((short *)((char *)(cgp) + (cgp)->cg_boff) + \
	(cylno) * (fs)->fs_nrpos))
#endif

#define	cg_inosused(cgp) \
	(((cgp)->cg_magic != CG_MAGIC) \
	? (((struct ocg *)(cgp))->cg_iused) \
	: ((char *)((char *)(cgp) + (cgp)->cg_iusedoff)))

#define	cg_blksfree(cgp) \
	(((cgp)->cg_magic != CG_MAGIC) \
	? (((struct ocg *)(cgp))->cg_free) \
	: ((uchar_t *)((char *)(cgp) + (cgp)->cg_freeoff)))

#define	cg_chkmagic(cgp) \
	((cgp)->cg_magic == CG_MAGIC || \
	((struct ocg *)(cgp))->cg_magic == CG_MAGIC)

/*
 * The following structure is defined
 * for compatibility with old file systems.
 */
struct	ocg {
	uint32_t cg_link;		/* NOT USED linked list of cyl groups */
	uint32_t cg_rlink;		/* NOT USED incore cyl groups */
	time32_t cg_time;		/* time last written */
	int32_t	cg_cgx;			/* we are the cgx'th cylinder group */
	short	cg_ncyl;		/* number of cyl's this cg */
	short	cg_niblk;		/* number of inode blocks this cg */
	int32_t	cg_ndblk;		/* number of data blocks this cg */
	struct	csum cg_cs;		/* cylinder summary information */
	int32_t	cg_rotor;		/* position of last used block */
	int32_t	cg_frotor;		/* position of last used frag */
	int32_t	cg_irotor;		/* position of last used inode */
	int32_t	cg_frsum[8];		/* counts of available frags */
	int32_t	cg_btot[32];		/* block totals per cylinder */
	short	cg_b[32][8];		/* positions of free blocks */
	char	cg_iused[256];		/* used inode map */
	int32_t	cg_magic;		/* magic number */
	uchar_t	cg_free[1];		/* free block map */
/* actually longer */
};

/*
 * Turn frag offsets into disk block addresses.
 * This maps frags to device size blocks.
 * (In the names of these macros, "fsb" refers to "frags", not
 * file system blocks.)
 */
#ifdef KERNEL
#define	fsbtodb(fs, b)	(((daddr_t)(b)) << (fs)->fs_fsbtodb)
#else /* KERNEL */
#define	fsbtodb(fs, b)	(((diskaddr_t)(b)) << (fs)->fs_fsbtodb)
#endif /* KERNEL */

#define	dbtofsb(fs, b)	((b) >> (fs)->fs_fsbtodb)

/*
 * Get the offset of the log, in either sectors, frags, or file system
 * blocks.  The interpretation of the fs_logbno field depends on whether
 * this is UFS or MTB UFS.  (UFS stores the value as sectors.  MTBUFS
 * stores the value as frags.)
 */

#ifdef KERNEL
#define	logbtodb(fs, b)	((fs)->fs_magic == FS_MAGIC ? \
		(daddr_t)(b) : ((daddr_t)(b) << (fs)->fs_fsbtodb))
#else /* KERNEL */
#define	logbtodb(fs, b)	((fs)->fs_magic == FS_MAGIC ? \
		(diskaddr_t)(b) : ((diskaddr_t)(b) << (fs)->fs_fsbtodb))
#endif /* KERNEL */
#define	logbtofrag(fs, b)	((fs)->fs_magic == FS_MAGIC ? \
		(b) >> (fs)->fs_fsbtodb : (b))
#define	logbtofsblk(fs, b) ((fs)->fs_magic == FS_MAGIC ? \
		(b) >> ((fs)->fs_fsbtodb + (fs)->fs_fragshift) : \
		(b) >> (fs)->fs_fragshift)

/*
 * Cylinder group macros to locate things in cylinder groups.
 * They calc file system addresses of cylinder group data structures.
 */
#define	cgbase(fs, c)	((daddr32_t)((fs)->fs_fpg * (c)))

#define	cgstart(fs, c) \
	(cgbase(fs, c) + (fs)->fs_cgoffset * ((c) & ~((fs)->fs_cgmask)))

#define	cgsblock(fs, c)	(cgstart(fs, c) + (fs)->fs_sblkno)	/* super blk */

#define	cgtod(fs, c)	(cgstart(fs, c) + (fs)->fs_cblkno)	/* cg block */

#define	cgimin(fs, c)	(cgstart(fs, c) + (fs)->fs_iblkno)	/* inode blk */

#define	cgdmin(fs, c)	(cgstart(fs, c) + (fs)->fs_dblkno)	/* 1st data */

/*
 * Macros for handling inode numbers:
 *	inode number to file system block offset.
 *	inode number to cylinder group number.
 *	inode number to file system block address.
 */
#define	itoo(fs, x)	((x) % (uint32_t)INOPB(fs))

#define	itog(fs, x)	((x) / (uint32_t)(fs)->fs_ipg)

#define	itod(fs, x) \
	((daddr32_t)(cgimin(fs, itog(fs, x)) + \
	(blkstofrags((fs), (((x)%(ulong_t)(fs)->fs_ipg)/(ulong_t)INOPB(fs))))))

/*
 * Give cylinder group number for a file system block.
 * Give cylinder group block number for a file system block.
 */
#define	dtog(fs, d)	((d) / (fs)->fs_fpg)
#define	dtogd(fs, d)	((d) % (fs)->fs_fpg)

/*
 * Extract the bits for a block from a map.
 * Compute the cylinder and rotational position of a cyl block addr.
 */
#define	blkmap(fs, map, loc) \
	(((map)[(loc) / NBBY] >> ((loc) % NBBY)) & \
	(0xff >> (NBBY - (fs)->fs_frag)))

#define	cbtocylno(fs, bno) \
	((bno) * NSPF(fs) / (fs)->fs_spc)

#ifdef _KERNEL
#define	cbtorpos(ufsvfsp, bno) \
	((((bno) * NSPF((ufsvfsp)->vfs_fs) % (ufsvfsp)->vfs_fs->fs_spc) % \
	(ufsvfsp)->vfs_fs->fs_nsect) * \
	(ufsvfsp)->vfs_nrpos) / (ufsvfsp)->vfs_fs->fs_nsect
#else
#define	cbtorpos(fs, bno) \
	((((bno) * NSPF(fs) % (fs)->fs_spc) % \
	(fs)->fs_nsect) * \
	(fs)->fs_nrpos) / (fs)->fs_nsect
#endif

/*
 * The following macros optimize certain frequently calculated
 * quantities by using shifts and masks in place of divisions
 * modulos and multiplications.
 */

/*
 * This macro works for 40 bit offset support in ufs because
 * this calculates offset in the block and therefore no loss of
 * information while casting to int.
 */

#define	blkoff(fs, loc)		/* calculates (loc % fs->fs_bsize) */ \
	((int)((loc) & ~(fs)->fs_bmask))

/*
 * This macro works for 40 bit offset support similar to blkoff
 */

#define	fragoff(fs, loc)	/* calculates (loc % fs->fs_fsize) */ \
	((int)((loc) & ~(fs)->fs_fmask))

/*
 * The cast to int32_t does not result in any loss of information because
 * the number of logical blocks in the file system is limited to
 * what fits in an int32_t anyway.
 */

#define	lblkno(fs, loc)		/* calculates (loc / fs->fs_bsize) */ \
	((int32_t)((loc) >> (fs)->fs_bshift))

/*
 * The same argument as above applies here.
 */

#define	numfrags(fs, loc)	/* calculates (loc / fs->fs_fsize) */ \
	((int32_t)((loc) >> (fs)->fs_fshift))

/*
 * Size can be a 64-bit value and therefore we sign extend fs_bmask
 * to a 64-bit value too so that the higher 32 bits are masked
 * properly. Note that the type of fs_bmask has to be signed. Otherwise
 * compiler will set the higher 32 bits as zero and we don't want
 * this to happen.
 */

#define	blkroundup(fs, size)	/* calculates roundup(size, fs->fs_bsize) */ \
	(((size) + (fs)->fs_bsize - 1) & (offset_t)(fs)->fs_bmask)

/*
 * Same argument as above.
 */

#define	fragroundup(fs, size)	/* calculates roundup(size, fs->fs_fsize) */ \
	(((size) + (fs)->fs_fsize - 1) & (offset_t)(fs)->fs_fmask)

/*
 * frags cannot exceed 32-bit value since we only support 40bit sizes.
 */

#define	fragstoblks(fs, frags)	/* calculates (frags / fs->fs_frag) */ \
	((frags) >> (fs)->fs_fragshift)

#define	blkstofrags(fs, blks)	/* calculates (blks * fs->fs_frag) */ \
	((blks) << (fs)->fs_fragshift)

#define	fragnum(fs, fsb)	/* calculates (fsb % fs->fs_frag) */ \
	((fsb) & ((fs)->fs_frag - 1))

#define	blknum(fs, fsb)		/* calculates rounddown(fsb, fs->fs_frag) */ \
	((fsb) &~ ((fs)->fs_frag - 1))

/*
 * Determine the number of available frags given a
 * percentage to hold in reserve
 */
#define	freespace(fs, ufsvfsp) \
	((blkstofrags((fs), (fs)->fs_cstotal.cs_nbfree) + \
	(fs)->fs_cstotal.cs_nffree) - (ufsvfsp)->vfs_minfrags)

/*
 * Determining the size of a file block in the file system.
 */

#define	blksize(fs, ip, lbn) \
	(((lbn) >= NDADDR || \
	(ip)->i_size >= (offset_t)((lbn) + 1) << (fs)->fs_bshift) \
	    ? (fs)->fs_bsize \
	    : (fragroundup(fs, blkoff(fs, (ip)->i_size))))

#define	dblksize(fs, dip, lbn) \
	(((lbn) >= NDADDR || \
	(dip)->di_size >= (offset_t)((lbn) + 1) << (fs)->fs_bshift) \
	    ? (fs)->fs_bsize \
	    : (fragroundup(fs, blkoff(fs, (dip)->di_size))))

/*
 * Number of disk sectors per block; assumes DEV_BSIZE byte sector size.
 */
#define	NSPB(fs)	((fs)->fs_nspf << (fs)->fs_fragshift)
#define	NSPF(fs)	((fs)->fs_nspf)

/*
 * INOPB is the number of inodes in a secondary storage block.
 */
#define	INOPB(fs)	((fs)->fs_inopb)
#define	INOPF(fs)	((fs)->fs_inopb >> (fs)->fs_fragshift)

/*
 * NINDIR is the number of indirects in a file system block.
 */
#define	NINDIR(fs)	((fs)->fs_nindir)

/*
 * bit map related macros
 */
#define	bitloc(a, i)	((a)[(i)/NBBY])
#define	setbit(a, i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define	clrbit(a, i)	((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define	isset(a, i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define	isclr(a, i)	(((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)

#define	getfs(vfsp) \
	((struct fs *)((struct ufsvfs *)vfsp->vfs_data)->vfs_bufp->b_un.b_addr)

#define	RETRY_LOCK_DELAY 1

/*
 * Macros to test and acquire i_rwlock:
 * some vnops hold the target directory's i_rwlock after calling
 * ufs_lockfs_begin but in many other operations (like ufs_readdir)
 * VOP_RWLOCK is explicitly called by the filesystem independent code before
 * calling the file system operation. In these cases the order is reversed
 * (i.e i_rwlock is taken first and then ufs_lockfs_begin is called). This
 * is fine as long as ufs_lockfs_begin acts as a VOP counter but with
 * ufs_quiesce setting the SLOCK bit this becomes a synchronizing
 * object which might lead to a deadlock. So we use rw_tryenter instead of
 * rw_enter. If we fail to get this lock and find that SLOCK bit is set, we
 * call ufs_lockfs_end and restart the operation.
 */

#define	ufs_tryirwlock(lock, mode, label) \
{\
	indeadlock = 0;\
label:\
	if (!rw_tryenter(lock, mode))\
	{\
		if (ulp && ULOCKFS_IS_SLOCK(ulp)) {\
			indeadlock = 1;\
		} else {\
			delay(RETRY_LOCK_DELAY);\
			goto  label;\
		}\
	}\
}

/*
 * The macro ufs_tryirwlock_trans is used in functions which call
 * TRANS_BEGIN_CSYNC and ufs_lockfs_begin, hence the need to call
 * TRANS_END_CSYNC and ufs_lockfs_end.
 */

#define	ufs_tryirwlock_trans(lock, mode, transmode, label) \
{\
	indeadlock = 0;\
label:\
	if (!rw_tryenter(lock, mode))\
	{\
		if (ulp && ULOCKFS_IS_SLOCK(ulp)) {\
			TRANS_END_CSYNC(ufsvfsp, error, issync,\
				transmode, trans_size);\
			ufs_lockfs_end(ulp);\
			indeadlock = 1;\
		} else {\
			delay(RETRY_LOCK_DELAY);\
			goto  label;\
		}\
	}\
}

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_FS_H */
