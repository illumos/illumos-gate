/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GRUB_UFS_H
#define _GRUB_UFS_H_

#ifdef	FSYS_UFS

/* ufs specific constants */
#define UFS_SBLOCK	16
#define UFS_SBSIZE	8192
#define	UFS_MAGIC	0x011954
#define	ROOTINO		2	/* i number of all roots */
#define UFS_NDADDR	12	/* direct blocks */
#define	UFS_NIADDR	3	/* indirect blocks */
#define	MAXMNTLEN	512
#define	MAXCSBUFS	32

/* file types */
#define	IFMT		0xf000
#define	IFREG		0x8000
#define	IFDIR		0x4000

typedef unsigned char	grub_uchar_t;
typedef	unsigned short	grub_ushort_t;
typedef	unsigned short	grub_o_mode_t;
typedef	unsigned short	grub_o_uid_t;
typedef	unsigned short	grub_o_gid_t;
typedef	long		grub_ino_t;
typedef	long		grub_int32_t;
typedef	long		grub_uid_t;
typedef	long		grub_gid_t;
typedef unsigned long	grub_uint32_t;
typedef unsigned long	grub_daddr32_t;
typedef	unsigned long	grub_time32_t;
typedef struct { int val[2]; } grub_quad_t;

struct timeval32 {
  	grub_time32_t	tv_sec;
	grub_int32_t	tv_usec;
};

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
	grub_int32_t	cs_ndir;	/* number of directories */
	grub_int32_t	cs_nbfree;	/* number of free blocks */
	grub_int32_t	cs_nifree;	/* number of free inodes */
	grub_int32_t	cs_nffree;	/* number of free frags */
};

/* Ufs super block */
struct fs {
	grub_uint32_t	fs_link;	/* linked list of file systems */
	grub_uint32_t	fs_rolled;	/* logging only: fs fully rolled */
	grub_daddr32_t	fs_sblkno;	/* addr of super-block in filesys */
	grub_daddr32_t	fs_cblkno;	/* offset of cyl-block in filesys */
	grub_daddr32_t	fs_iblkno;	/* offset of inode-blocks in filesys */
	grub_daddr32_t	fs_dblkno;	/* offset of first data after cg */
	grub_int32_t	fs_cgoffset;	/* cylinder group offset in cylinder */
	grub_int32_t	fs_cgmask;	/* used to calc mod fs_ntrak */
	grub_time32_t	fs_time;	/* last time written */
	grub_int32_t	fs_size;	/* number of blocks in fs */
	grub_int32_t	fs_dsize;	/* number of data blocks in fs */
	grub_int32_t	fs_ncg;		/* number of cylinder groups */
	grub_int32_t	fs_bsize;	/* size of basic blocks in fs */
	grub_int32_t	fs_fsize;	/* size of frag blocks in fs */
	grub_int32_t	fs_frag;	/* number of frags in a block in fs */
	/* these are configuration parameters */
	grub_int32_t	fs_minfree;	/* minimum percentage of free blocks */
	grub_int32_t	fs_rotdelay;	/* num of ms for optimal next block */
	grub_int32_t	fs_rps;		/* disk revolutions per second */
	/* these fields can be computed from the others */
	grub_int32_t	fs_bmask;	/* ``blkoff'' calc of blk offsets */
	grub_int32_t	fs_fmask;	/* ``fragoff'' calc of frag offsets */
	grub_int32_t	fs_bshift;	/* ``lblkno'' calc of logical blkno */
	grub_int32_t	fs_fshift;	/* ``numfrags'' calc number of frags */
	/* these are configuration parameters */
	grub_int32_t	fs_maxcontig;	/* max number of contiguous blks */
	grub_int32_t	fs_maxbpg;	/* max number of blks per cyl group */
	/* these fields can be computed from the others */
	grub_int32_t	fs_fragshift;	/* block to frag shift */
	grub_int32_t	fs_fsbtodb;	/* fsbtodb and dbtofsb shift constant */
	grub_int32_t	fs_sbsize;	/* actual size of super block */
	grub_int32_t	fs_csmask;	/* csum block offset */
	grub_int32_t	fs_csshift;	/* csum block number */
	grub_int32_t	fs_nindir;	/* value of NINDIR */
	grub_int32_t	fs_inopb;	/* value of INOPB */
	grub_int32_t	fs_nspf;	/* value of NSPF */
	/* yet another configuration parameter */
	grub_int32_t	fs_optim;	/* optimization preference, see below */
	/* these fields are derived from the hardware */
	/* USL SVR4 compatibility */
	/*
	 *	* USL SVR4 compatibility
	 *
	 * There was a significant divergence here between Solaris and
	 * SVR4 for x86.	By swapping these two members in the superblock,
	 * we get read-only compatibility of SVR4 filesystems.	Otherwise
	 * there would be no compatibility.	This change was introduced
	 * during bootstrapping of Solaris on x86.	By making this ifdef'ed
	 * on byte order, we provide ongoing compatibility across all
	 * platforms with the same byte order, the highest compatibility
	 * that can be achieved.
	 */
	grub_int32_t	fs_state;	/* file system state time stamp */
	grub_int32_t	fs_si;		/* summary info state - lufs only */
	grub_int32_t	fs_trackskew;	/* sector 0 skew, per track */
	/* unique id for this filesystem (currently unused and unmaintained) */
	/* In 4.3 Tahoe this space is used by fs_headswitch and fs_trkseek */
	/* Neither of those fields is used in the Tahoe code right now but */
	/* there could be problems if they are.	*/
	grub_int32_t	fs_id[2];	/* file system id */
	/* sizes determined by number of cylinder groups and their sizes */
	grub_daddr32_t	fs_csaddr;	/* blk addr of cyl grp summary area */
	grub_int32_t	fs_cssize;	/* size of cyl grp summary area */
	grub_int32_t	fs_cgsize;	/* cylinder group size */
	/* these fields are derived from the hardware */
	grub_int32_t	fs_ntrak;	/* tracks per cylinder */
	grub_int32_t	fs_nsect;	/* sectors per track */
	grub_int32_t	fs_spc;		/* sectors per cylinder */
	/* this comes from the disk driver partitioning */
	grub_int32_t	fs_ncyl;	/* cylinders in file system */
	/* these fields can be computed from the others */
	grub_int32_t	fs_cpg;		/* cylinders per group */
	grub_int32_t	fs_ipg;		/* inodes per group */
	grub_int32_t	fs_fpg;		/* blocks per group * fs_frag */
	/* this data must be re-computed after crashes */
	struct csum	fs_cstotal;	/* cylinder summary information */
	/* these fields are cleared at mount time */
	char		fs_fmod;	/* super block modified flag */
	char		fs_clean;	/* file system state flag */
	char		fs_ronly;	/* mounted read-only flag */
	char		fs_flags;	/* largefiles flag, etc. */
	char		fs_fsmnt[MAXMNTLEN];	/* name mounted on */
	/* these fields retain the current block allocation info */
	grub_int32_t	fs_cgrotor;	/* last cg searched */
	/*
	 * The following used to be fs_csp[MAXCSBUFS]. It was not
	 * used anywhere except in old utilities.  We removed this
	 * in 5.6 and expect fs_u.fs_csp to be used instead.
	 * We no longer limit fs_cssize based on MAXCSBUFS.
	 */
	union {	/* fs_cs (csum) info */
		grub_uint32_t	fs_csp_pad[MAXCSBUFS];
		struct csum	*fs_csp;
	} fs_u;
	grub_int32_t	fs_cpc;		/* cyl per cycle in postbl */
	short		fs_opostbl[16][8];  /* old rotation block list head */
	grub_int32_t	fs_sparecon[51];    /* reserved for future constants */
	grub_int32_t	fs_version;	/* minor version of MTB ufs */
	grub_int32_t	fs_logbno;	/* block # of embedded log */
	grub_int32_t	fs_reclaim;	/* reclaim open, deleted files */
	grub_int32_t	fs_sparecon2;	/* reserved for future constant */
	/* USL SVR4 compatibility */
	grub_int32_t	fs_npsect;	/* # sectors/track including spares */
	grub_quad_t	fs_qbmask;	/* ~fs_bmask - for use with quad size */
	grub_quad_t	fs_qfmask;	/* ~fs_fmask - for use with quad size */
	grub_int32_t	fs_postblformat; /* fmt of positional layout tables */
	grub_int32_t	fs_nrpos;	/* number of rotaional positions */
	grub_int32_t	fs_postbloff;	/* (short) rotation block list head */
	grub_int32_t	fs_rotbloff;	/* (grub_uchar_t) blocks for each */
					/* rotation */
	grub_int32_t	fs_magic;	/* magic number */
	grub_uchar_t	fs_space[1];	/* list of blocks for each rotation */
	/* actually longer */
};

struct icommon {
	grub_o_mode_t	ic_smode;	/* 0: mode and type of file */
	short		ic_nlink;	/* 2: number of links to file */
	grub_o_uid_t	ic_suid;	/* 4: owner's user id */
	grub_o_gid_t	ic_sgid;	/* 6: owner's group id */
	grub_uint32_t	ic_sizelo;	/* 8: number of bytes in file */
	grub_uint32_t	ic_sizehi;	/* 12: number of bytes in file */
	struct timeval32 ic_atime;	/* 16: time last accessed */
	struct timeval32 ic_mtime;	/* 24: time last modified */
	struct timeval32 ic_ctime;	/* 32: last time inode changed */
	grub_daddr32_t	ic_db[UFS_NDADDR];	/* 40: disk block addresses */
	grub_daddr32_t	ic_ib[UFS_NIADDR];	/* 88: indirect blocks */
	grub_int32_t	ic_flags;	/* 100: cflags */
	grub_int32_t	ic_blocks;	/* 104: 512 byte blocks actually held */
	grub_int32_t	ic_gen;		/* 108: generation number */
	grub_int32_t	ic_shadow;	/* 112: shadow inode */
	grub_uid_t	ic_uid;		/* 116: long EFT version of uid */
	grub_gid_t	ic_gid;		/* 120: long EFT version of gid */
	grub_uint32_t	ic_oeftflag;	/* 124: extended attr directory ino, */
					/*      0 = none */
};

struct direct {
	grub_ino_t	d_ino;
	grub_ushort_t	d_reclen;
	grub_ushort_t	d_namelen;
	char		d_name[MAXNAMELEN + 1];
};

/* inode macros */
#define INOPB(fs)       ((fs)->fs_inopb)
#define itoo(fs, x)	((x) % (grub_uint32_t)INOPB(fs))
#define	itog(fs, x)	((x) / (grub_uint32_t)(fs)->fs_ipg)
#define itod(fs, x)	((grub_daddr32_t)(cgimin(fs, itog(fs, x)) + \
  (blkstofrags((fs), \
  ((x) % (grub_uint32_t)(fs)->fs_ipg / (grub_uint32_t)INOPB(fs))))))

/* block conversion macros */
#define	UFS_NINDIR(fs)	((fs)->fs_nindir)	/* # of indirects */
#define blkoff(fs, loc)	((int)((loc & ~(fs)->fs_bmask)))
#define lblkno(fs, loc) ((grub_int32_t)((loc) >> (fs)->fs_bshift))
/* frag to blk */
#define fsbtodb(fs, b)	(((grub_daddr32_t)(b)) << (fs)->fs_fsbtodb)
#define blkstofrags(fs, b) ((b) << (fs)->fs_fragshift)

/* cynlinder group macros */
#define cgbase(fs, c)	((grub_daddr32_t)((fs)->fs_fpg * (c)))
#define	cgimin(fs, c)	(cgstart(fs, c) + (fs)->fs_iblkno) /* inode block */
#define cgstart(fs, c) \
  (cgbase(fs, c) + (fs)->fs_cgoffset * ((c) & ~((fs)->fs_cgmask)))

#endif	/* FSYS_UFS */

#endif /* !_GRUB_UFS_H */
