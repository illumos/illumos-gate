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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_PC_FS_H
#define	_SYS_FS_PC_FS_H

#include <sys/thread.h>
#include <sys/ksynch.h>
#include <sys/sysmacros.h>
#include <sys/byteorder.h>

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
 * The FAT bootsector uses little-endian multibyte values not aligned at
 * a 'native' wordsize. Instead of defining a strange data structure and
 * odd accessor methods for some members while using standard C accesses
 * for others, we don't bother and just define the structure offsets, and
 * a common set of misaligned-littleendian accessor macros.
 *
 * The "bootsec" and "fat32_bootsec" structures are only provided for
 * compatibility with old code including <sys/fs/pc_fs.h> but not used
 * by the PCFS kernel driver anymore.
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


#define	OFF_JMPBOOT	0
#define	OFF_OEMNAME	3
#define	OFF_BYTESPERSEC	11
#define	OFF_SECPERCLUS	13
#define	OFF_RSVDSECCNT	14
#define	OFF_NUMFATS	16
#define	OFF_ROOTENTCNT	17
#define	OFF_TOTSEC16	19
#define	OFF_MEDIA	21
#define	OFF_FATSZ16	22
#define	OFF_SECPERTRK	24
#define	OFF_NUMHEADS	26
#define	OFF_HIDDSEC	28
#define	OFF_TOTSEC32	32
#define	OFF_BPBSIG	510

#define	OFF_DRVNUM16	36
#define	OFF_BOOTSIG16	38
#define	OFF_VOLID16	39
#define	OFF_VOLLAB16	43
#define	OFF_FILSYSTYP16	54

#define	OFF_FATSZ32	36
#define	OFF_EXTFLAGS32	40
#define	OFF_FSVER32	42
#define	OFF_ROOTCLUS32	44
#define	OFF_FSINFO32	48
#define	OFF_BKBOOTSEC32	50
#define	OFF_DRVNUM32	64
#define	OFF_BOOTSIG32	66
#define	OFF_VOLID32	67
#define	OFF_VOLLAB32	71
#define	OFF_FILSYSTYP32	82

#define	LE_16_NA(addr)					\
	(((uint16_t)*((uint8_t *)(addr))) +		\
	((uint16_t)*((uint8_t *)(addr) + 1) << 8))

#define	LE_32_NA(addr)					\
	(((uint32_t)*((uint8_t *)(addr))) +		\
	((uint32_t)*((uint8_t *)(addr) + 1) << 8) +	\
	((uint32_t)*((uint8_t *)(addr) + 2) << 16) +	\
	((uint32_t)*((uint8_t *)(addr) + 3) << 24))

/*
 * Generic FAT BPB fields
 */
#define	bpb_jmpBoot(bpb)		((unsigned char *)(bpb))
#define	bpb_OEMName(bpb)		((char *)(bpb) + OFF_OEMNAME)
#define	bpb_get_BytesPerSec(bpb)	LE_16_NA((bpb) + OFF_BYTESPERSEC)
#define	bpb_get_SecPerClus(bpb)		(((uint8_t *)(bpb))[OFF_SECPERCLUS])
#define	bpb_get_RsvdSecCnt(bpb)		LE_16_NA((bpb) + OFF_RSVDSECCNT)
#define	bpb_get_NumFATs(bpb)		(((uint8_t *)(bpb))[OFF_NUMFATS])
#define	bpb_get_RootEntCnt(bpb)		LE_16_NA((bpb) + OFF_ROOTENTCNT)
#define	bpb_get_TotSec16(bpb)		LE_16_NA((bpb) + OFF_TOTSEC16)
#define	bpb_get_Media(bpb)		(((uint8_t *)(bpb))[OFF_MEDIA])
#define	bpb_get_FatSz16(bpb)		LE_16_NA((bpb) + OFF_FATSZ16)
#define	bpb_get_SecPerTrk(bpb)		LE_16_NA((bpb) + OFF_SECPERTRK)
#define	bpb_get_NumHeads(bpb)		LE_16_NA((bpb) + OFF_NUMHEADS)
#define	bpb_get_HiddSec(bpb)		LE_32_NA((bpb) + OFF_HIDDSEC)
#define	bpb_get_TotSec32(bpb)		LE_32_NA((bpb) + OFF_TOTSEC32)
#define	bpb_get_BPBSig(bpb)		LE_16_NA((bpb) + OFF_BPBSIG)

/*
 * FAT12/16 extended BPB fields
 */
#define	bpb_get_DrvNum16(bpb)		(((uint8_t *)(bpb))[OFF_DRVNUM16])
#define	bpb_get_BootSig16(bpb)		(((uint8_t *)(bpb))[OFF_BOOTSIG16])
#define	bpb_VolLab16(bpb)		((char *)(bpb) + OFF_VOLLAB16)
#define	bpb_FilSysType16(bpb)		((char *)(bpb) + OFF_FILSYSTYP16)
#define	bpb_get_VolID16(bpb)		LE_32_NA((bpb) + OFF_VOLID16)

/*
 * FAT32 extended BPB fields
 */
#define	bpb_get_FatSz32(bpb)		LE_32_NA((bpb) + OFF_FATSZ32)
#define	bpb_get_ExtFlags32(bpb)		LE_16_NA((bpb) + OFF_EXTFLAGS32)
#define	bpb_get_FSVer32(bpb)		LE_16_NA((bpb) + OFF_FSVER32)
#define	bpb_get_RootClus32(bpb)		LE_32_NA((bpb) + OFF_ROOTCLUS32)
#define	bpb_get_FSInfo32(bpb)		LE_16_NA((bpb) + OFF_FSINFO32)
#define	bpb_get_BkBootSec32(bpb)	LE_16_NA((bpb) + OFF_BKBOOTSEC32)
#define	bpb_get_DrvNum32(bpb)		(((uint8_t *)(bpb))[OFF_DRVNUM32])
#define	bpb_get_BootSig32(bpb)		(((uint8_t *)(bpb))[OFF_BOOTSIG32])
#define	bpb_get_VolID32(bpb)		LE_32_NA((bpb) + OFF_VOLID32)
#define	bpb_VolLab32(bpb)		((char *)(bpb) + OFF_VOLLAB32)
#define	bpb_FilSysType32(bpb)		((char *)(bpb) + OFF_FILSYSTYP32)

/*
 * Validators
 */
#define	VALID_SECSIZE(s)	\
	(s == 512 || s == 1024 || s == 2048 || s == 4096)
#define	VALID_SPCL(s)		(ISP2((s)) && (unsigned int)(s) <= 128)
#define	VALID_CLSIZE(s)		(ISP2((s)) && (unsigned int)(s) <= (64 * 1024))
#define	VALID_NUMFATS(n)	((n) > 0 && (n) < 8)
#define	VALID_RSVDSEC(s)	((s) > 0)
#define	VALID_BPBSIG(sig)	((sig) == MBB_MAGIC)
#define	VALID_BOOTSIG(sig)	((sig) == 0x29)
#define	VALID_MEDIA(m)		((m) == 0xF0 || ((m) >= 0xF8 && (m) <= 0xFF))

/*
 * this might require a change for codepage support. In particular,
 * pc_validchar() cannot be a macro anymore if codepages get involved.
 */
#define	VALID_VOLLAB(l)		(			\
	pc_validchar((l)[0]) && pc_validchar((l)[1]) && \
	pc_validchar((l)[2]) &&	pc_validchar((l)[3]) && \
	pc_validchar((l)[4]) && pc_validchar((l)[5]) && \
	pc_validchar((l)[6]) && pc_validchar((l)[7]) && \
	pc_validchar((l)[8]) && pc_validchar((l)[9]) && \
	pc_validchar((l)[10]))

/*
 * We might actually use the 'validchar' checks as well; it only needs
 * to be printable. Should this ever caused failed media recognition,
 * we can change it. Many ISVs put different strings into the "oemname"
 * field.
 */
#define	VALID_OEMNAME(nm)	(			\
	bcmp((nm), "MSDOS", 5) == 0 || bcmp((nm), "MSWIN", 5) == 0)
#define	VALID_FSTYPSTR16(typ)	(bcmp((typ), "FAT", 3) == 0)
#define	VALID_FSTYPSTR32(typ)	(bcmp((typ), "FAT32", 5) == 0)
#define	VALID_JMPBOOT(b)	(			\
	((b)[0] == 0xeb && (b)[2] == 0x90) || (b)[0] == 0xe9)
#define	VALID_FSVER32(v)	((v) == PCFS_SUPPORTED_FSVER)
/*
 * Can we check this properly somehow ? There should be a better way.
 * The FAT spec doesn't mention reserved bits need to be zero ...
 */
#define	VALID_EXTFLAGS(flags)	(((flags) & 0x8f) == (flags))

/*
 * Validation results
 */
#define	BPB_SECSIZE_OK		(1 << 0)	/* ok: 512/1024/2048/4096 */
#define	BPB_OEMNAME_OK		(1 << 1)	/* "MSDOS" or "MSWIN" */
#define	BPB_JMPBOOT_OK		(1 << 2)	/* 16bit "jmp" / "call" */
#define	BPB_SECPERCLUS_OK	(1 << 3)	/* power of 2, [1 .. 128] */
#define	BPB_RSVDSECCNT_OK	(1 << 4)	/* cannot be zero */
#define	BPB_NUMFAT_OK		(1 << 5)	/* >= 1, <= 8 */
#define	BPB_ROOTENTCNT_OK	(1 << 6)	/* 0 on FAT32, != 0 else */
#define	BPB_TOTSEC_OK		(1 << 7)	/* smaller than volume */
#define	BPB_TOTSEC16_OK		(1 << 8)	/* 0 on FAT32, != 0 on FAT12 */
#define	BPB_TOTSEC32_OK		(1 << 9)	/* 0 on FAT12, != 0 on FAT32 */
#define	BPB_MEDIADESC_OK	(1 << 10)	/* 0xf0 or 0xf8..0xff */
#define	BPB_FATSZ_OK		(1 << 11)	/* [nclusters], no smaller */
#define	BPB_FATSZ16_OK		(1 << 12)	/* 0 on FAT32, != 0 else */
#define	BPB_FATSZ32_OK		(1 << 13)	/* non-zero on FAT32 */
#define	BPB_BPBSIG_OK		(1 << 14)	/* 0x55, 0xAA */
#define	BPB_BOOTSIG16_OK	(1 << 15)	/* 0x29 - if present */
#define	BPB_BOOTSIG32_OK	(1 << 16)	/* 0x29 - unless SYSLINUX2.x */
#define	BPB_FSTYPSTR16_OK	(1 << 17)	/* At least "FAT" */
#define	BPB_FSTYPSTR32_OK	(1 << 18)	/* "FAT32" */
#define	BPB_EXTFLAGS_OK		(1 << 19)	/* reserved bits should be 0 */
#define	BPB_FSVER_OK		(1 << 20)	/* must be 0 */
#define	BPB_ROOTCLUSTER_OK	(1 << 21)	/* must be != 0 and valid */
#define	BPB_FSISEC_OK		(1 << 22)	/* != 0, <= reserved */
#define	BPB_BKBOOTSEC_OK	(1 << 23)	/* != 0, <= reserved, != fsi */
#define	BPB_VOLLAB16_OK		(1 << 24)	/* passes pc_validchar() */
#define	BPB_VOLLAB32_OK		(1 << 25)	/* passes pc_validchar() */
#define	BPB_NCLUSTERS_OK	(1 << 26)	/* from FAT spec */
#define	BPB_CLSIZE_OK		(1 << 27)	/* cluster size */
#define	BPB_MEDIASZ_OK		(1 << 28)	/* filesystem fits on device */

#define	FAT12_VALIDMSK							\
	(BPB_SECSIZE_OK | BPB_SECPERCLUS_OK | BPB_CLSIZE_OK |		\
	BPB_RSVDSECCNT_OK | BPB_NUMFAT_OK | BPB_ROOTENTCNT_OK |		\
	BPB_TOTSEC_OK | BPB_TOTSEC16_OK |				\
	BPB_FATSZ_OK | BPB_FATSZ16_OK |	BPB_BPBSIG_OK)

#define	FAT16_VALIDMSK							\
	(BPB_SECSIZE_OK | BPB_SECPERCLUS_OK | BPB_CLSIZE_OK |		\
	BPB_RSVDSECCNT_OK | BPB_NUMFAT_OK | BPB_ROOTENTCNT_OK |		\
	BPB_TOTSEC_OK | BPB_TOTSEC16_OK | BPB_TOTSEC32_OK | 		\
	BPB_FATSZ_OK | BPB_FATSZ16_OK | BPB_BPBSIG_OK)

/*
 * A note on FAT32: According to the FAT spec, FAT32 _must_ have a valid
 * extended BPB and therefore, as a proof of its existance, the FAT32
 * boot signature (offset 66) must be valid as well. Why don't we check
 * for BPB_BOOTSIG32_OK  then ?
 *
 * We don't test for this here first-pass, because there are media out
 * there that are valid FAT32 structurally but don't have a valid sig.
 * This happens if older versions of the SYSLINUX bootloader (below 3.x)
 * are installed on a media with a FAT32 on it. SYSLINUX 2.x and lower
 * overwrite the BPB past the end of the FAT12/16 extension with its
 * bootloader code - and the FAT16 extended BPB is 62 Bytes...
 * All structurally relevant fields of the FAT32 BPB are within the first
 * 52 Bytes, so the filesystem is accessible - but the signature check
 * would reject it.
 */
#define	FAT32_VALIDMSK							\
	(BPB_SECSIZE_OK | BPB_SECPERCLUS_OK | BPB_CLSIZE_OK |		\
	BPB_RSVDSECCNT_OK | BPB_NUMFAT_OK | BPB_ROOTENTCNT_OK |		\
	BPB_TOTSEC_OK | BPB_TOTSEC16_OK | BPB_TOTSEC32_OK | 		\
	BPB_FATSZ_OK | BPB_FATSZ16_OK |	BPB_FATSZ32_OK |		\
	BPB_EXTFLAGS_OK | BPB_FSVER_OK | BPB_ROOTCLUSTER_OK |		\
	BPB_BPBSIG_OK)

/*
 * FAT32 BPB allows 'versioning' via FSVer32. We follow the 'NULL' spec.
 */
#define	PCFS_SUPPORTED_FSVER	0


/*
 * Filesystem summary information (introduced originally for FAT32 volumes).
 * We need to maintain fs_free_clusters or Microsoft Scandisk will be upset.
 * We keep these values in-core even for FAT12/FAT16 but will never attempt
 * to write them out to disk then.
 */
typedef struct fat_fsinfo {
	uint32_t fs_free_clusters;	/* # free clusters. -1 if unknown */
	uint32_t fs_next_free;		/* search next free after this cn */
} fat_fsi_t;

/*
 * On-disk FSI. All values in little endian. Only FAT32 has this.
 */
typedef struct fat_od_fsi {
	uint32_t	fsi_leadsig;		/* 0x41615252 */
	char		fsi_reserved1[480];
	uint32_t	fsi_strucsig;		/* 0x61417272 */
	fat_fsi_t	fsi_incore;		/* free/nextfree */
	char		fsi_reserved2[12];
	uint32_t	fsi_trailsig;		/* 0xaa550000 */
} fat_od_fsi_t;

#define	FSI_LEADSIG	LE_32(0x41615252)
#define	FSI_STRUCSIG	LE_32(0x61417272)
#define	FSI_TRAILSIG	LE_32(0xaa550000)	/* same as MBB_MAGIC */

#define	FSISIG_OK(fsi)	(						\
	((fat_od_fsi_t *)(fsi))->fsi_leadsig == FSI_LEADSIG &&		\
	((fat_od_fsi_t *)(fsi))->fsi_strucsig == FSI_STRUCSIG &&	\
	((fat_od_fsi_t *)(fsi))->fsi_trailsig == FSI_TRAILSIG)

#define	FSINFO_UNKNOWN	((uint32_t)(-1))	/* free/next not valid */

typedef enum { FAT12, FAT16, FAT32, FAT_UNKNOWN, FAT_QUESTIONABLE } fattype_t;


struct pcfs {
	struct vfs *pcfs_vfs;		/* vfs for this fs */
	int pcfs_flags;			/* flags */
	int pcfs_ldrive;		/* logical DOS drive number */
	fattype_t pcfs_fattype;
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
	daddr_t pcfs_fsistart;		/* start blkno of FSI sector */
	daddr_t pcfs_fatstart;		/* start blkno of first FAT */
	daddr_t pcfs_rdirstart;		/* start blkno of root dir */
	daddr_t pcfs_datastart;		/* start blkno of data area */
	int pcfs_clsize;		/* cluster size in bytes */
	int pcfs_ncluster;		/* number of clusters in fs */
	int pcfs_nrefs;			/* number of active pcnodes */
	int pcfs_frefs;			/* number of active file pcnodes */
	int pcfs_nxfrecls;		/* next free cluster */
	uchar_t *pcfs_fatp;		/* ptr to FAT data */
	uchar_t *pcfs_fat_changemap;	/* map of changed fat data */
	int pcfs_fat_changemapsize;	/* size of FAT changemap */
	time_t pcfs_fattime;		/* time FAT becomes invalid */
	time_t pcfs_verifytime;		/* time to reverify disk */
	kmutex_t	pcfs_lock;		/* per filesystem lock */
	kthread_id_t pcfs_owner;		/* id of thread locking pcfs */
	int pcfs_count;			/* # of pcfs locks for pcfs_owner */
	struct fat_fsinfo pcfs_fsinfo;	/* in-core fsinfo */
	struct pcfs *pcfs_nxt;		/* linked list of all mounts */
	int pcfs_fatjustread;		/* Used to flag a freshly found FAT */
	struct vnode *pcfs_root;	/* vnode for the root dir of the fs */
	int pcfs_secondswest;		/* recording timezone for this fs */
	len_t pcfs_mediasize;
	int pcfs_rootblksize;
	int pcfs_mediadesc;		/* media descriptor */
	pc_cluster32_t pcfs_lastclmark;
	pc_cluster32_t pcfs_rootclnum;
	timestruc_t pcfs_mounttime;	/* timestamp for "/" */
};

/*
 * flags
 */
#define	PCFS_FATMOD		0x01	/* FAT has been modified */
#define	PCFS_LOCKED		0x02	/* fs is locked */
#define	PCFS_WANTED		0x04	/* locked fs is wanted */
#define	PCFS_NOCHK		0x800	/* don't resync fat on error */
#define	PCFS_BOOTPART		0x1000	/* boot partition type */
#define	PCFS_HIDDEN		0x2000	/* show hidden files */
#define	PCFS_PCMCIA_NO_CIS	0x4000	/* PCMCIA psuedo floppy */
#define	PCFS_FOLDCASE		0x8000	/* fold filenames to lowercase */
#define	PCFS_FSINFO_OK		0x10000	/* valid FAT32 fsinfo sector */
#define	PCFS_IRRECOV		0x20000	/* FS was messed with during write */
#define	PCFS_NOCLAMPTIME	0x40000	/* expose full FAT timestamp range */
#define	PCFS_NOATIME		0x80000	/* disable atime updates */

#define	IS_FAT12(PCFS)	((PCFS)->pcfs_fattype == FAT12)
#define	IS_FAT16(PCFS)	((PCFS)->pcfs_fattype == FAT16)
#define	IS_FAT32(PCFS)	((PCFS)->pcfs_fattype == FAT32)

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
 * pcfs mount options.
 */
#define	MNTOPT_PCFS_HIDDEN	"hidden"
#define	MNTOPT_PCFS_NOHIDDEN	"nohidden"
#define	MNTOPT_PCFS_FOLDCASE	"foldcase"
#define	MNTOPT_PCFS_NOFOLDCASE	"nofoldcase"
#define	MNTOPT_PCFS_CLAMPTIME	"clamptime"
#define	MNTOPT_PCFS_NOCLAMPTIME	"noclamptime"
#define	MNTOPT_PCFS_TIMEZONE	"timezone"
#define	MNTOPT_PCFS_SECSIZE	"secsize"

/*
 * Disk timeout value in sec.
 * This is used to time out the in core FAT and to re-verify the disk.
 * This should be less than the time it takes to change floppys
 */
#define	PCFS_DISKTIMEOUT	2

#define	PCFS_MAXOFFSET_T	UINT32_MAX	/* PCFS max file size */

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

#define	pc_clear_fatchanges(PCFS) \
	bzero((PCFS)->pcfs_fat_changemap, (PCFS)->pcfs_fat_changemapsize)

#define	pc_blksize(PCFS, PCP, OFF)	/* file system block size */	\
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

#define	pc_dbdaddr(PCFS, DB)	/* sector to DEV_BSIZE "sector" addr */ \
	((DB) << (PCFS)->pcfs_sdshift)

#define	pc_daddrdb(PCFS, DADDR)	/* DEV_BSIZE "sector" addr to sector addr */ \
	((DADDR) >> (PCFS)->pcfs_sdshift)

#define	pc_cldaddr(PCFS, CL)	/* DEV_BSIZE "sector" addr for cluster */ \
	pc_dbdaddr(PCFS, ((daddr_t)((PCFS)->pcfs_datastart +	\
	pc_cltodb(PCFS, (CL) - PCF_FIRSTCLUSTER))))

#define	pc_daddrcl(PCFS, DADDR)		/* cluster for disk address */	\
	((int)(PCF_FIRSTCLUSTER +					\
	pc_dbtocl(pc_daddrdb(PCFS, DADDR) - (PCFS)->pcfs_datastart)))

/*
 * Number of directory entries per sector / cluster
 */
#define	pc_direntpersec(PCFS)						\
	((int)((PCFS)->pcfs_secsize / sizeof (struct pcdir)))

#define	pc_direntpercl(PCFS)						\
	((int)((PCFS)->pcfs_clsize  / sizeof (struct pcdir)))

/*
 * out-of-range check for cluster numbers.
 */
#define	pc_validcl(PCFS, CL)		/* check that cluster no is legit */ \
	((int)(CL) >= PCF_FIRSTCLUSTER && \
	    (int)(CL) < (PCFS)->pcfs_ncluster + PCF_FIRSTCLUSTER)

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
