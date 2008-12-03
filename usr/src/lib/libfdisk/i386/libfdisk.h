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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _LIBFDISK_H_
#define	_LIBFDISK_H_

#include <limits.h>
#include <sys/dktp/fdisk.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_LOGDRIVE_OFFSET 63

#define	FDISK_ERRNO		200
#define	FDISK_ETOOLONG		(FDISK_ERRNO + 0)
#define	FDISK_EOOBOUND		(FDISK_ERRNO + 1)
#define	FDISK_EZERO		(FDISK_ERRNO + 2)
#define	FDISK_EOVERLAP		(FDISK_ERRNO + 3)
#define	FDISK_ENOVGEOM		(FDISK_ERRNO + 4)
#define	FDISK_ENOPGEOM		(FDISK_ERRNO + 5)
#define	FDISK_ENOLGEOM		(FDISK_ERRNO + 6)
#define	FDISK_ENOLOGDRIVE	(FDISK_ERRNO + 7)
#define	FDISK_EBADLOGDRIVE	(FDISK_ERRNO + 8)
#define	FDISK_ENOEXTPART	(FDISK_ERRNO + 9)
#define	FDISK_EBADMAGIC		(FDISK_ERRNO + 10)
#define	FDISK_EMOUNTED		(FDISK_ERRNO + 11)

#define	FDISK_SUCCESS 0

#define	FDISK_READ_DISK		0x00000001

#define	LINUX_SWAP_MAGIC_LENGTH	10
enum {
	PHYSGEOM = 0,
	VIRTGEOM,
	NCYL,
	NHEADS,
	NSECTPT,
	SSIZE,
	ACYL
};

enum {
	FDISK_MINOR_WRITE = 1,
	FDISK_MAJOR_WRITE
};

#define	FDISK_SECTS_PER_CYL(epp) \
	(epp->disk_geom.phys_heads * epp->disk_geom.phys_sec)
#define	FDISK_SECT_TO_CYL(epp, x)	((x) / (FDISK_SECTS_PER_CYL(epp)))
#define	FDISK_CYL_TO_SECT(epp, x)	((x) * (FDISK_SECTS_PER_CYL(epp)))
#define	FDISK_ABS_CYL_NUM(epp, x)	(FDISK_SECT_TO_CYL(x) +\
    epp->ext_beg_cyl)

#define	FDISK_CYL_BNDRY_ALIGN(epp, x)	(((x) % (FDISK_SECTS_PER_CYL(epp))) ? \
	(((x)/(FDISK_SECTS_PER_CYL(epp))) + 1) :\
	((x)/(FDISK_SECTS_PER_CYL(epp))))

/*
 * Extended partition structure :
 *  +--------------+
 *  |+--+          |
 *  ||  |----------+---> structure at the beginning of the extended partition
 *  ||--|          |     ( Lets call it the EBR - Extended Boot Record )
 *  ||  |      +---+--->
 *  |+--+      |   |     Logical drive within the extended partition
 *  |+---------+--+|     ( We will plainly call this a logical drive )
 *  ||            ||
 *  ||            ||
 *  ||            ||
 *  |+------------+|
 *  +--------------+
 *
 *
 * EBR is effectively "struct ipart parts[2]".
 * The picture below shows what the EBR contains. The EBR has
 * two important pieces of information. The first is the offset and the size
 * of the logical drive in this extended partition. The second is the offset
 * and size of the next extended partition. The offsets are relative to
 * beginning of the first extended partition. These extended partitions are
 * arranged like a linked list.
 * Note that (currently) only one extended partition can exist in the MBR.
 * The system ID of a logical drive within the extended partition cannot be
 * that of an extended partition.
 *
 *                   +------+
 *                   |      |
 *  +--------------+ |    +-v------------+
 *  |+--+          | |    |+--+          |
 *  ||  |---+      | |    ||  |          |
 *  ||--|   |      | |    ||--|          |
 *  ||  |---|------+-+    ||  |          |
 *  |+--+   |      |      |+--+          |
 *  |+------v-----+|      |+------------+|
 *  ||            ||      ||            ||
 *  ||            ||      ||            ||
 *  ||            ||      ||            ||
 *  |+------------+|      |+------------+|
 *  +--------------+      +--------------+
 *
 */

/*
 * Main structure used to record changes to the partitions made.
 * Changes are not written to disk everytime, but maintained in this structure.
 * This information is used when the user chooses to commit the changes.
 * A linked list of this structure represents the ondisk partitions.
 */
typedef struct logical_drive {

	/* structure holding the EBR data */
	struct ipart parts[2];

	/*
	 * Absolute beginning sector of the extended partition, and hence an
	 * indicator of where the EBR for this logical drive would go on disk.
	 * NOTE : In case the first logical drive in this extended partition is
	 * out of (disk) order, this indicates the beginning of the logical
	 * drive. The EBR will anyway be at the first sector of the extended
	 * partition, for the first logical drive.
	 */
	uint32_t abs_secnum;

	/*
	 * Offset of the logical drive from the beginning of its extended
	 * partition
	 */
	uint32_t logdrive_offset;

	/* Size of the logical drive in sectors */
	uint32_t numsect;

	/* Beginning and ending cylinders of the extended partition */
	uint32_t begcyl, endcyl;

	/*
	 * Flag to indicate if this record is to be sync'ed to disk.
	 * It takes two values : FDISK_MAJOR_WRITE and FDISK_MINOR_WRITE
	 * If it is a minor write, there is no need to update the information
	 * in the kernel structures. Example of a minor write is correction of
	 * a corrupt boot signature.
	 */
	int modified;

	/*
	 * This pointer points to the next extended partition in the order
	 * found on disk.
	 */
	struct logical_drive *next;

	/*
	 * This pointer points to the next extended partition in a sorted list
	 * sorted in the ascending order of their beginning cylinders.
	 */
	struct logical_drive *sorted_next;

} logical_drive_t;

typedef struct fdisk_disk_geom {
	ushort_t phys_cyl;
	ushort_t phys_sec;
	ushort_t phys_heads;
	ushort_t alt_cyl;
	ushort_t virt_cyl;
	ushort_t virt_sec;
	ushort_t virt_heads;
	ushort_t sectsize;
} fdisk_disk_geom_t;

typedef struct ext_part
{
	/* Structure holding geometry information about the device */
	fdisk_disk_geom_t disk_geom;

	struct ipart *mtable;

	char device_name[PATH_MAX];

	int dev_fd;

	int op_flag;

	/*
	 * Head of the in memory structure (singly linked list) of extended
	 * partition information.
	 */
	logical_drive_t *ld_head;
	logical_drive_t *sorted_ld_head;

	/* Beginning cylinder of the extended partition */
	uint32_t ext_beg_cyl;

	/* Ending cylinder of the extended partition */
	uint32_t ext_end_cyl;

	/* Beginning sector of the extended partition */
	uint32_t ext_beg_sec;

	/* Ending sector of the extended partition */
	uint32_t ext_end_sec;

	/* Count of the number of logical drives in the extended partition */
	int logical_drive_count;

	/*
	 * Flag to keep track of the update to be made to the Extended Boot
	 * Record (EBR) when all logical drives are deleted. The EBR is filled
	 * with zeroes in such a case.
	 */
	int first_ebr_is_null;

	/*
	 * Flag to indicate corrupt logical drives. Can happen when a partition
	 * manager creates an extended partition and does not null the first EBR
	 * or when important ondisk structures are overwritten by a bad program
	 */
	int corrupt_logical_drives;

	/*
	 * The boot block signature 0xAA55 might not be found on some of the
	 * EBRs. ( Even though the rest of the data might be good )
	 * The following array is used to store the list of such logical drive
	 * numbers.
	 */
	uchar_t invalid_bb_sig[MAX_EXT_PARTS];

	/*
	 * Can add  a "next" pointer here in case support for multiple
	 * extended partitions becomes the standard someday.
	 *
	 * struct ext_part *next;
	 */
} ext_part_t;

#define	fdisk_get_logical_drive_count(epp) ((epp)->logical_drive_count)
#define	fdisk_corrupt_logical_drives(epp) ((epp)->corrupt_logical_drives)
#define	fdisk_get_ext_beg_cyl(epp) ((epp)->ext_beg_cyl)
#define	fdisk_get_ext_end_cyl(epp) ((epp)->ext_end_cyl)
#define	fdisk_get_ext_beg_sec(epp) ((epp)->ext_beg_sec)
#define	fdisk_get_ext_end_sec(epp) ((epp)->ext_end_sec)
#define	fdisk_get_ld_head(epp) ((epp)->ld_head)
#define	fdisk_is_solaris_part(id) (((id) == SUNIXOS) || ((id) == SUNIXOS2))
#define	fdisk_is_dos_extended(id) (((id) == EXTDOS) || ((id) == FDISK_EXTLBA))

extern int fdisk_is_linux_swap(ext_part_t *epp, uint32_t part_start,
    off_t *lsm_offset);
extern int libfdisk_init(ext_part_t **epp, char *devstr, struct ipart *parttab,
    int opflag);
extern int libfdisk_reset(ext_part_t *epp);
extern void libfdisk_fini(ext_part_t **epp);
extern int fdisk_ext_find_first_free_sec(ext_part_t *epp,
    uint32_t *first_free_sec);
extern uint32_t fdisk_ext_find_last_free_sec(ext_part_t *epp, uint32_t begsec);
extern int fdisk_ext_part_exists(ext_part_t *epp);
extern int fdisk_validate_logical_drive(ext_part_t *epp, uint32_t begsec,
    uint32_t offset, uint32_t numsec);
extern int fdisk_ext_validate_part_start(ext_part_t *epp, uint32_t begcyl,
    uint32_t *begsec);
extern int fdisk_get_solaris_part(ext_part_t *epp, int *pnum, uint32_t *begsec,
    uint32_t *numsec);
extern int fdisk_get_part_info(ext_part_t *epp, int pnum, uchar_t *sysid,
    uint32_t *begsec, uint32_t *numsec);
extern int fdisk_commit_ext_part(ext_part_t *epp);
extern void fdisk_change_logical_drive_id(ext_part_t *epp, int pno,
    uchar_t partid);
extern void fdisk_add_logical_drive(ext_part_t *epp, uint32_t begsec,
    uint32_t endsec, uchar_t partid);
extern void fdisk_delete_logical_drive(ext_part_t *epp, int pno);
extern int fdisk_init_ext_part(ext_part_t *epp, uint32_t rsect, uint32_t nsect);
extern int fdisk_delete_ext_part(ext_part_t *epp);
extern int fdisk_get_disk_geom(ext_part_t *epp, int type, int what);
extern int fdisk_invalid_bb_sig(ext_part_t *epp, uchar_t **bbsig_arr);
extern int fdisk_mounted_logical_drives(ext_part_t *epp);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBFDISK_H_ */
