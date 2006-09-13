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

#ifndef	_SYS_FS_PC_FS_H
#define	_SYS_FS_PC_FS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef	uint16_t	pc_cluster16_t;
typedef	uint32_t	pc_cluster32_t;

/*
 * PC (MSDOS) compatible virtual file system.
 *
 * A main goal of the implementation was to maintain statelessness
 * except while files are open. Thus mounting and unmounting merely
 * declared the file system name. The user may change disks at almost
 * any time without concern (just like the PC). It is assumed that when
 * files are open for writing the disk access light will be on, as a
 * warning not to change disks. The implementation must, however, detect
 * disk change and recover gracefully. It does this by comparing the
 * in core entry for a directory to the on disk entry whenever a directory
 * is searched. If a discrepancy is found active directories become root and
 * active files are marked invalid.
 *
 * There are only two type of nodes on the PC file system; files and
 * directories. These are represented by two separate vnode op vectors,
 * and they are kept in two separate tables. Files are known by the
 * disk block number and block (cluster) offset of the files directory
 * entry. Directories are known by the starting cluster number.
 *
 * The file system is locked for during each user operation. This is
 * done to simplify disk verification error conditions.
 *
 * Notes on FAT32 support
 * ----------------------
 * The basic difference between FAT32 and FAT16 is that cluster numbers are now
 * 32-bit instead of 16-bit. The FAT is thus an array of 32-bit cluster numbers,
 * and because of this the cluster size can be much smaller on a large disk
 * (4k, say, on a 1 Gig drive instead of 16k). Unfortunately, the FAT is not
 * the only place cluster numbers are stored - the starting cluster is stored
 * in the directory entry for a file, and of course it's only 16-bit. Luckily,
 * there's a 16-bit OS/2 Extended Attribute field that is now used to store the
 * upper 16-bits of the starting cluster number.
 *
 * Most of the FAT32 changes to pcfs are under 'if it's FAT32' to minimize the
 * effect on non-FAT32 filesystems (and still share the code), except for the
 * starting cluster changes. It seemed easier to make common functions to
 * handle that.
 *
 * Other changes:
 *
 *     1. FAT32 partitions are indicated by partition types 0xB and 0xC.
 *     2. The boot sector is now 2 sectors, to make room for FAT32 extensions.
 *     3. The root directory is no longer stored in a fixed location. Its'
 *        starting cluster is stored in the extended boot sector.
 *     4. "Summary information" is now stored and we need to (at least) maintain
 *        the number of free clusters or scandisk will be upset. Though the
 *        sector this info is in is pointed to by the extensions in the boot
 *        sector, the magic offset of this information is just that so
 *        far - magic. 0x1e0.
 *     5. FAT32 can use the alternate FAT. But we don't.
 *
 * FAT32 also exposed a latent bug: we bread() each copy of the FAT in one
 * big chunk.  This is not good on a large FAT32 drive, such as a 1 Gig
 * Jaz drive that has 4k clusters, since the FAT becomes 1 Meg in size and
 * bread blocks forever. So now we read the FAT in chunks.
 */

/*
 * pre-FAT32 boot sector.
 */
struct bootsec {
	uchar_t	instr[3];
	uchar_t	version[8];
	uchar_t	bps[2];			/* bytes per sector */
	uchar_t	spcl;			/* sectors per allocation unit */
	uchar_t	res_sec[2];		/* reserved sectors, starting at 0 */
	uchar_t	nfat;			/* number of FATs */
	uchar_t	rdirents[2];		/* number of root directory entries */
	uchar_t	numsect[2];		/* old total sectors in logical image */
	uchar_t	mediadesriptor;		/* media descriptor byte */
	ushort_t fatsec;		/* number of sectors per FAT */
	ushort_t spt;			/* sectors per track */
	ushort_t nhead;			/* number of heads */
	uint_t	hiddensec;		/* number of hidden sectors */
	uint_t	totalsec;		/* total sectors in logical image */
};

/*
 * FAT32 volumes have a bigger boot sector. They include the normal
 * boot sector.
 */
struct fat32_bootsec {
	struct bootsec	f_bs;
	uint32_t	f_fatlength;	/* size of FAT */
	uint16_t	f_flags;
	uint8_t		f_major;	/* major filesystem version #? */
	uint8_t		f_minor;	/* minor filesystem version #? */
	uint32_t	f_rootcluster;	/* first cluster in root directory */
	uint16_t	f_infosector;	/* where summary info is */
	uint16_t	f_backupboot;	/* backup boot sector */
	uint16_t	f_reserved2[6];
};

#define	FAT32_FS_SIGN	0x61417272
#define	FAT32_BOOT_FSINFO_OFF	0x1e0

/*
 * summary information for fat32 volumes. We need to maintain fs_free_clusters
 * or Microsoft Scandisk will be upset.
 */
struct fat32_boot_fsinfo {
	uint32_t	fs_reserved1;
	uint32_t	fs_signature;	/* 0x61417272 */
	uint32_t	fs_free_clusters;  /* # free clusters. -1 if unknown */
	uint32_t	fs_next_cluster;   /* unused by pcfs */
	uint32_t	fs_reserved2[4];
};

#define	FSINFO_UNKNOWN	(-1)

struct pcfs {
	struct vfs *pcfs_vfs;		/* vfs for this fs */
	int pcfs_flags;			/* flags */
	int pcfs_ldrv;			/* logical DOS drive number */
	dev_t pcfs_xdev;		/* actual device that is mounted */
	struct vnode *pcfs_devvp;	/*   and a vnode for it */
	int pcfs_secsize;		/* sector size in bytes */
	int pcfs_spcl;			/* sectors per cluster */
	int pcfs_spt;			/* sectors per track */
	int pcfs_sdshift;		/* shift to convert sector into */
					/* DEV_BSIZE "sectors"; assume */
					/* pcfs_secsize is 2**n times of */
					/* DEV_BSIZE */
	int pcfs_fatsec;		/* number of sec per FAT */
	int pcfs_numfat;		/* number of FAT copies */
	int pcfs_rdirsec;		/* number of sec in root dir */
	daddr_t pcfs_dosstart;		/* start blkno of DOS partition */
	daddr_t pcfs_fatstart;		/* start blkno of first FAT */
	daddr_t pcfs_rdirstart;		/* start blkno of root dir */
	daddr_t pcfs_datastart;		/* start blkno of data area */
	int pcfs_clsize;		/* cluster size in bytes */
	int pcfs_ncluster;		/* number of clusters in fs */
	int pcfs_entps;			/* number of dir entry per sector */
	int pcfs_nrefs;			/* number of active pcnodes */
	int pcfs_frefs;			/* number of active file pcnodes */
	int pcfs_nxfrecls;		/* next free cluster */
	uchar_t *pcfs_fatp;		/* ptr to FAT data */
	uchar_t *pcfs_fat_changemap;	/* map of changed fat data */
	int pcfs_fatsize;		/* size of FAT data */
	int pcfs_fat_changemapsize;	/* size of FAT changemap */
	time_t pcfs_fattime;		/* time FAT becomes invalid */
	time_t pcfs_verifytime;		/* time to reverify disk */
	kmutex_t	pcfs_lock;		/* per filesystem lock */
	kthread_id_t pcfs_owner;		/* id of thread locking pcfs */
	int pcfs_count;			/* # of pcfs locks for pcfs_owner */
	struct fat32_boot_fsinfo fsinfo_native; /* native fsinfo for fat32 */
	uint32_t	f32fsinfo_sector; /* where to read/write fsinfo */
	struct pcfs *pcfs_nxt;		/* linked list of all mounts */
	int pcfs_fatjustread;		/* Used to flag a freshly found FAT */
	struct vnode *pcfs_root;	/* vnode for the root dir of the fs */
};

/*
 * flags
 */
#define	PCFS_FATMOD		0x01	/* FAT has been modified */
#define	PCFS_LOCKED		0x02	/* fs is locked */
#define	PCFS_WANTED		0x04	/* locked fs is wanted */
#define	PCFS_FAT16		0x400	/* 16 bit FAT */
#define	PCFS_NOCHK		0x800	/* don't resync fat on error */
#define	PCFS_BOOTPART		0x1000	/* boot partition type */
#define	PCFS_HIDDEN		0x2000	/* show hidden files */
#define	PCFS_PCMCIA_NO_CIS	0x4000	/* PCMCIA psuedo floppy */
#define	PCFS_FOLDCASE		0x8000	/* fold filenames to lowercase */
#define	PCFS_FAT32		0x10000	/* 32 bit FAT */
#define	PCFS_IRRECOV		0x20000	/* FS was messed with during write */
#define	PCFS_NOCLAMPTIME	0x40000	/* expose full FAT timestamp range */

/* for compatibility */
struct old_pcfs_args {
	int	secondswest;	/* seconds west of Greenwich */
	int	dsttime;    	/* type of dst correction */
};

struct pcfs_args {
	int	secondswest;	/* seconds west of Greenwich */
	int	dsttime;    	/* type of dst correction */
	int	flags;
};

/*
 * flags for the pcfs_args 'flags' field.
 *
 * Note that these two macros are obsolete - do not use them.
 */
#define	PCFS_MNT_HIDDEN		0x01	/* show hidden files */
#define	PCFS_MNT_FOLDCASE	0x02	/* fold all names from media to */
					/* lowercase */
#define	PCFS_MNT_NOCLAMPTIME	0x04	/* expose full FAT timestamp range */

/*
 * pcfs mount options.
 */
#define	MNTOPT_PCFS_HIDDEN	"hidden"
#define	MNTOPT_PCFS_NOHIDDEN	"nohidden"
#define	MNTOPT_PCFS_FOLDCASE	"foldcase"
#define	MNTOPT_PCFS_NOFOLDCASE	"nofoldcase"
#define	MNTOPT_PCFS_CLAMPTIME	"clamptime"
#define	MNTOPT_PCFS_NOCLAMPTIME	"noclamptime"

/*
 * Disk timeout value in sec.
 * This is used to time out the in core FAT and to re-verify the disk.
 * This should be less than the time it takes to change floppys
 */
#define	PCFS_DISKTIMEOUT	2

#define	VFSTOPCFS(VFSP)		((struct pcfs *)((VFSP)->vfs_data))
#define	PCFSTOVFS(FSP)		((FSP)->pcfs_vfs)

/*
 * special cluster numbers in FAT
 */
#define	PCF_FREECLUSTER		0x00	/* cluster is available */
#define	PCF_ERRORCLUSTER	0x01	/* error occurred allocating cluster */
#define	PCF_12BCLUSTER		0xFF0	/* 12-bit version of reserved cluster */
#define	PCF_RESCLUSTER		0xFFF0	/* 16-bit version of reserved cluster */
#define	PCF_RESCLUSTER32	0xFFFFFF0 /* 32-bit version */
#define	PCF_BADCLUSTER		0xFFF7	/* bad cluster, do not use */
#define	PCF_BADCLUSTER32	0xFFFFFF7 /* 32-bit version */
#define	PCF_LASTCLUSTER		0xFFF8	/* >= means last cluster in file */
#define	PCF_LASTCLUSTER32	0xFFFFFF8 /* 32-bit version */
#define	PCF_LASTCLUSTERMARK	0xFFFF	/* value used to mark last cluster */
#define	PCF_LASTCLUSTERMARK32	0xFFFFFFF /* 32-bit version */
#define	PCF_FIRSTCLUSTER	2	/* first valid cluster number */

/*
 * file system constants
 */
#define	PC_MAXFATSEC	256		/* maximum number of sectors in FAT */

/*
 * file system parameter macros
 */

#define	IS_FAT32(PCFS) \
	(((PCFS)->pcfs_flags & PCFS_FAT32) == PCFS_FAT32)

#define	IS_FAT16(PCFS) \
	(((PCFS)->pcfs_flags & PCFS_FAT16) == PCFS_FAT16)

#define	IS_FAT12(PCFS) \
	(((PCFS)->pcfs_flags & (PCFS_FAT16 | PCFS_FAT32)) == 0)

#define	pc_clear_fatchanges(PCFS) \
	bzero((PCFS)->pcfs_fat_changemap, (PCFS)->pcfs_fat_changemapsize)

#define	pc_blksize(PCFS, PCP, OFF)	/* file system block size */ \
	(((PCTOV(PCP)->v_flag & VROOT) && !IS_FAT32(PCFS)) ? \
	    ((OFF) >= \
	    ((PCFS)->pcfs_rdirsec & \
	    ~((PCFS)->pcfs_spcl - 1)) * ((PCFS)->pcfs_secsize)? \
	    ((PCFS)->pcfs_rdirsec & \
	    ((PCFS)->pcfs_spcl - 1)) * ((PCFS)->pcfs_secsize): \
	    (PCFS)->pcfs_clsize): \
	    (PCFS)->pcfs_clsize)

#define	pc_blkoff(PCFS, OFF)		/* offset within block */ \
	((int)((OFF) & ((PCFS)->pcfs_clsize - 1)))

#define	pc_lblkno(PCFS, OFF)		/* logical block (cluster) no */ \
	((daddr_t)((OFF) / (PCFS)->pcfs_clsize))

#define	pc_dbtocl(PCFS, DB)		/* disk blks to clusters */ \
	((int)((DB) / (PCFS)->pcfs_spcl))

#define	pc_cltodb(PCFS, CL)		/* clusters to disk blks */ \
	((daddr_t)((CL) * (PCFS)->pcfs_spcl))

#define	pc_cldaddr(PCFS, CL)	/* DEV_BSIZE "sector" addr for cluster */ \
	(((daddr_t)((PCFS)->pcfs_datastart + \
	    ((CL) - PCF_FIRSTCLUSTER) * (PCFS)->pcfs_spcl)) << \
	    (PCFS)->pcfs_sdshift)

#define	pc_daddrcl(PCFS, DADDR)		/* cluster for disk address */ \
	((int)(((((DADDR) >> (PCFS)->pcfs_sdshift) - (PCFS)->pcfs_datastart) / \
	(PCFS)->pcfs_spcl) + 2))

#define	pc_dbdaddr(PCFS, DB)	/* sector to DEV_BSIZE "sector" addr */ \
	((DB) << (PCFS)->pcfs_sdshift)

#define	pc_daddrdb(PCFS, DADDR)	/* DEV_BSIZE "sector" addr to sector addr */ \
	((DADDR) >> (PCFS)->pcfs_sdshift)

#define	pc_validcl(PCFS, CL)		/* check that cluster no is legit */ \
	((int)(CL) >= PCF_FIRSTCLUSTER && \
	    (int)(CL) <= (PCFS)->pcfs_ncluster)

/*
 * external routines.
 */
extern int pc_lockfs(struct pcfs *, int, int); /* lock fs and get fat */
extern void pc_unlockfs(struct pcfs *);	/* ulock the fs */
extern int pc_getfat(struct pcfs *);	/* get fat from disk */
extern void pc_invalfat(struct pcfs *);	/* invalidate incore fat */
extern int pc_syncfat(struct pcfs *);	/* sync fat to disk */
extern int pc_freeclusters(struct pcfs *);	/* num free clusters in fs */
extern pc_cluster32_t pc_alloccluster(struct pcfs *, int);
extern void pc_setcluster(struct pcfs *, pc_cluster32_t, pc_cluster32_t);
extern void pc_mark_fat_updated(struct pcfs *fsp, pc_cluster32_t cn);
extern int pc_fat_is_changed(struct pcfs *fsp, pc_cluster32_t bn);

/*
 * debugging
 */
extern int pcfsdebuglevel;
#define	PC_DPRINTF0(level, A) \
	if (pcfsdebuglevel >= level) \
	    cmn_err(CE_CONT, (A))
#define	PC_DPRINTF1(level, A, B) \
	if (pcfsdebuglevel >= level) \
	    cmn_err(CE_CONT, (A), (B))
#define	PC_DPRINTF2(level, A, B, C) \
	if (pcfsdebuglevel >= level) \
	    cmn_err(CE_CONT, (A), (B), (C))
#define	PC_DPRINTF3(level, A, B, C, D) \
	if (pcfsdebuglevel >= level) \
	    cmn_err(CE_CONT, (A), (B), (C), (D))
#define	PC_DPRINTF4(level, A, B, C, D, E) \
	if (pcfsdebuglevel >= level) \
	    cmn_err(CE_CONT, (A), (B), (C), (D), (E))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_PC_FS_H */
