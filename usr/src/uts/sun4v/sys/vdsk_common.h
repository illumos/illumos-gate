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

#ifndef	_VDSK_COMMON_H
#define	_VDSK_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header file contains the private LDoms Virtual Disk (vDisk) definitions
 * common to both the server (vds) and the client (vdc)
 */

#include <sys/efi_partition.h>
#include <sys/machparam.h>
#include <sys/vtoc.h>

#include <sys/ldc.h>
#include <sys/vio_common.h>
#include <sys/vio_mailbox.h>

/*
 * vDisk definitions
 */

/*
 * The number of Descriptor Ring entries
 *
 * Constraints:
 * 	- overall DRing size must be greater than 8K (MMU_PAGESIZE)
 *	- overall DRing size should be 8K aligned (desirable but not enforced)
 *	- DRing entry must be 8 byte aligned
 */
#define	VD_DRING_LEN		512

/*
 *
 */
#define	VD_DRING_ENTRY_SZ	(sizeof (vd_dring_entry_t) + 		\
		(sizeof (ldc_mem_cookie_t) * (VD_MAX_COOKIES - 1)))

/*
 * The maximum block size we can transmit using one Descriptor Ring entry
 *
 * Currently no FS uses more than 128K and it doesn't look like they
 * will either as there is no perf gain to be had by larger values.
 * ( see ZFS comment at definition of SPA_MAXBLOCKSIZE ).
 *
 * We choose 256K to give us some headroom.
 */
#define	VD_MAX_BLOCK_SIZE	(256 * 1024)

#define	VD_MAX_COOKIES		((VD_MAX_BLOCK_SIZE / PAGESIZE) + 1)
#define	VD_USEC_TIMEOUT		20000
#define	VD_LDC_IDS_PROP		"ldc-ids"
#define	VD_LDC_MTU		256

/*
 * Flags used by ioctl routines to indicate if a copyin/copyout is needed
 */
#define	VD_COPYOUT		0x1
#define	VD_COPYIN		0x2

/*
 * vDisk operations on physical devices
 */
#define	VD_OP_BREAD		0x01	/* Block Read */
#define	VD_OP_BWRITE		0x02	/* Block Write */
#define	VD_OP_FLUSH		0x03	/* Flush disk write cache contents */
#define	VD_OP_GET_WCE		0x04	/* Get disk W$ status */
#define	VD_OP_SET_WCE		0x05	/* Enable/Disable disk W$ */
#define	VD_OP_GET_VTOC		0x06	/* Get VTOC */
#define	VD_OP_SET_VTOC		0x07	/* Set VTOC */
#define	VD_OP_GET_DISKGEOM	0x08	/* Get disk geometry */
#define	VD_OP_SET_DISKGEOM	0x09	/* Set disk geometry */
#define	VD_OP_SCSICMD		0x0a	/* SCSI control command */
#define	VD_OP_GET_DEVID		0x0b	/* Get device id */
#define	VD_OP_GET_EFI 		0x0c	/* Get EFI */
#define	VD_OP_SET_EFI 		0x0d	/* Set EFI */
#define	VD_OP_RESET		0x0e	/* Reset disk */
#define	VD_OP_GET_ACCESS	0x0f	/* Get disk access */
#define	VD_OP_SET_ACCESS	0x10	/* Set disk access */
#define	VD_OP_GET_CAPACITY	0x11	/* Get disk capacity */
#define	VD_OP_MASK		0xFF	/* mask of all possible operations */
#define	VD_OP_COUNT		0x11	/* Number of operations */

/*
 * Status for the VD_OP_GET_ACCESS operation
 */
#define	VD_ACCESS_DENIED	0x00	/* access is not allowed */
#define	VD_ACCESS_ALLOWED	0x01	/* access is allowed */

/*
 * Flags for the VD_OP_SET_ACCESS operation
 */
#define	VD_ACCESS_SET_CLEAR	0x00	/* clear exclusive access rights */
#define	VD_ACCESS_SET_EXCLUSIVE	0x01	/* set exclusive access rights */
#define	VD_ACCESS_SET_PREEMPT	0x02	/* forcefully set access rights */
#define	VD_ACCESS_SET_PRESERVE	0x04	/* preserve access rights */

/*
 * This is a mask of all the basic operations supported by all
 * disk types (v1.0).
 */
#define	VD_OP_MASK_READ			\
	((1 << VD_OP_BREAD) |			\
	(1 << VD_OP_GET_WCE) |			\
	(1 << VD_OP_GET_VTOC) |			\
	(1 << VD_OP_GET_DISKGEOM) |		\
	(1 << VD_OP_GET_DEVID) |		\
	(1 << VD_OP_GET_EFI))

#define	VD_OP_MASK_WRITE			\
	((1 << VD_OP_BWRITE) |			\
	(1 << VD_OP_FLUSH) |			\
	(1 << VD_OP_SET_WCE) |			\
	(1 << VD_OP_SET_VTOC) |			\
	(1 << VD_OP_SET_DISKGEOM) |		\
	(1 << VD_OP_SET_EFI))

/*
 * Mask for additional operations provided for SCSI disks (v1.1)
 */
#define	VD_OP_MASK_SCSI				\
	((1 << VD_OP_SCSICMD) |			\
	(1 << VD_OP_RESET) |			\
	(1 << VD_OP_GET_ACCESS) |		\
	(1 << VD_OP_SET_ACCESS) |		\
	(1 << VD_OP_GET_CAPACITY))

/*
 * macro to check if the operation 'op' is supported by checking the list
 * of operations supported which is exported by the vDisk server.
 */
#define	VD_OP_SUPPORTED(ops_bitmask, op)	((ops_bitmask) & (1 << (op)))

/*
 * Slice for absolute disk transaction.
 */
#define	VD_SLICE_NONE		0xFF

/*
 * EFI disks do not have a slice 7. Actually that slice is used to represent
 * the whole disk.
 */
#define	VD_EFI_WD_SLICE	7

/*
 * Definitions of the various ways vds can export disk support to vdc.
 */
typedef enum vd_disk_type {
	VD_DISK_TYPE_UNK = 0,		/* Unknown device type */
	VD_DISK_TYPE_SLICE,		/* slice in block device */
	VD_DISK_TYPE_DISK		/* entire disk (slice 2) */
} vd_disk_type_t;

/*
 * Definitions of the various disk label that vDisk supports.
 */
typedef enum vd_disk_label {
	VD_DISK_LABEL_UNK = 0,		/* Unknown disk label */
	VD_DISK_LABEL_VTOC,		/* VTOC disk label */
	VD_DISK_LABEL_EFI		/* EFI disk label */
} vd_disk_label_t;

/*
 * vDisk Descriptor payload
 */
typedef struct vd_dring_payload {
	uint64_t	req_id;		/* The request ID being processed */
	uint8_t		operation;	/* operation for server to perform */
	uint8_t		slice;		/* The disk slice being accessed */
	uint16_t	resv1;		/* padding */
	uint32_t	status;		/* "errno" of server operation */
	uint64_t	addr;		/* LP64	diskaddr_t (block I/O) */
	uint64_t	nbytes;		/* LP64 size_t */
	uint32_t	ncookies;	/* Number of cookies used */
	uint32_t	resv2;		/* padding */

	ldc_mem_cookie_t	cookie[1];	/* variable sized array */
} vd_dring_payload_t;


/*
 * vDisk Descriptor entry
 */
typedef struct vd_dring_entry {
	vio_dring_entry_hdr_t		hdr;		/* common header */
	vd_dring_payload_t		payload;	/* disk specific data */
} vd_dring_entry_t;

/*
 * vDisk logical partition
 */
typedef struct vd_slice {
	daddr_t	start;		/* block number of slice start */
	daddr_t nblocks;	/* number of blocks in the slice */
} vd_slice_t;


/*
 * vDisk control operation structures
 */

/*
 * vDisk geometry definition (VD_OP_GET_DISKGEOM and VD_OP_SET_DISKGEOM)
 */
typedef struct vd_geom {
	uint16_t	ncyl;		/* number of data cylinders */
	uint16_t	acyl;		/* number of alternate cylinders */
	uint16_t	bcyl;		/* cyl offset for fixed head area */
	uint16_t	nhead;		/* number of heads */
	uint16_t	nsect;		/* number of data sectors per track */
	uint16_t	intrlv;		/* interleave factor */
	uint16_t	apc;		/* alternates per cyl (SCSI only) */
	uint16_t	rpm;		/* revolutions per minute */
	uint16_t	pcyl;		/* number of physical cylinders */
	uint16_t	write_reinstruct;	/* # sectors to skip, writes */
	uint16_t	read_reinstruct;	/* # sectors to skip, reads */
} vd_geom_t;


/*
 * vDisk partition definition
 */
typedef struct vd_partition {
	uint16_t	id_tag;		/* ID tag of partition */
	uint16_t	perm;		/* permission flags for partition */
	uint32_t	reserved;	/* padding */
	uint64_t	start;		/* block number of partition start */
	uint64_t	nblocks;	/* number of blocks in partition */
} vd_partition_t;

/*
 * vDisk VTOC definition (VD_OP_GET_VTOC and VD_OP_SET_VTOC)
 */
#define	VD_VOLNAME_LEN		8	/* length of volume_name field */
#define	VD_ASCIILABEL_LEN	128	/* length of ascii_label field */
typedef struct vd_vtoc {
	char		volume_name[VD_VOLNAME_LEN];	/* volume name */
	uint16_t	sector_size;		/* sector size in bytes */
	uint16_t	num_partitions;		/* number of partitions */
	char		ascii_label[VD_ASCIILABEL_LEN];	/* ASCII label */
	vd_partition_t	partition[V_NUMPAR];	/* partition headers */
} vd_vtoc_t;


/*
 * vDisk EFI definition (VD_OP_GET_EFI and VD_OP_SET_EFI)
 */
typedef struct vd_efi {
	uint64_t	lba;		/* lba of the request */
	uint64_t	length;		/* length of data */
	char		data[1];	/* data of the request */
} vd_efi_t;


/*
 * vDisk DEVID definition (VD_OP_GET_DEVID)
 */
#define	VD_DEVID_SIZE(l)	(sizeof (vd_devid_t) - 1 + l)
#define	VD_DEVID_DEFAULT_LEN	128

typedef struct vd_devid {
	uint16_t	reserved;	/* padding */
	uint16_t	type;		/* type of device id */
	uint32_t	length;		/* length the device id */
	char		id[1];		/* device id */
} vd_devid_t;

/*
 * vDisk CAPACITY definition (VD_OP_GET_CAPACITY)
 */
typedef struct vd_capacity {
	uint32_t	vdisk_block_size;	/* block size in bytes */
	uint32_t	reserved;		/* reserved */
	uint64_t	vdisk_size;		/* disk size in blocks */
} vd_capacity_t;

/* Identifier for unknown disk size */
#define	VD_SIZE_UNKNOWN		-1

/*
 * vDisk SCSI definition (VD_OP_SCSICMD)
 */
typedef struct vd_scsi {
	uint8_t		cmd_status;	/* command completion status */
	uint8_t		sense_status;	/* sense command completion status */
	uint8_t		task_attribute;	/* task attribute */
	uint8_t		task_priority;	/* task priority */
	uint8_t		crn;		/* command reference number */
	uint8_t		reserved;	/* reserved */
	uint16_t	timeout;	/* command timeout */
	uint64_t	options;	/* options */
	uint64_t	cdb_len;	/* CDB data length */
	uint64_t	sense_len;	/* sense request length */
	uint64_t	datain_len;	/* data in buffer length */
	uint64_t	dataout_len;	/* data out buffer length */
	char		data[1];	/* data (CDB, sense, data in/out */
} vd_scsi_t;

/* Minimum size of the vd_scsi structure */
#define	VD_SCSI_SIZE	(sizeof (vd_scsi_t) - sizeof (uint64_t))

/*
 * Macros to access data buffers in a vd_scsi structure. When using these
 * macros, the vd_scsi structure needs to be populated with the sizes of
 * data buffers allocated in the structure.
 */
#define	VD_SCSI_DATA_CDB(vscsi)		\
	((union scsi_cdb *)(uintptr_t)((vscsi)->data))

#define	VD_SCSI_DATA_SENSE(vscsi) 	\
	((struct scsi_extended_sense *)(uintptr_t)((vscsi)->data + \
	    P2ROUNDUP((vscsi)->cdb_len, sizeof (uint64_t))))

#define	VD_SCSI_DATA_IN(vscsi)		\
	((uintptr_t)((vscsi)->data +	\
	    P2ROUNDUP((vscsi)->cdb_len, sizeof (uint64_t)) + 	\
	    P2ROUNDUP((vscsi)->sense_len, sizeof (uint64_t))))

#define	VD_SCSI_DATA_OUT(vscsi)		\
	((uintptr_t)((vscsi)->data +	\
	    P2ROUNDUP((vscsi)->cdb_len, sizeof (uint64_t)) + 	\
	    P2ROUNDUP((vscsi)->sense_len, sizeof (uint64_t)) + 	\
	    P2ROUNDUP((vscsi)->datain_len, sizeof (uint64_t))))

/* vDisk SCSI task attribute */
#define	VD_SCSI_TASK_SIMPLE	0x01	/* simple task */
#define	VD_SCSI_TASK_ORDERED	0x02	/* ordered task */
#define	VD_SCSI_TASK_HQUEUE	0x03	/* head of queue task */
#define	VD_SCSI_TASK_ACA	0x04	/* ACA task */

/* vDisk SCSI options */
#define	VD_SCSI_OPT_CRN		0x01	/* request has a CRN */
#define	VD_SCSI_OPT_NORETRY	0x02	/* do not attempt any retry */

/*
 * Copy the contents of a vd_geom_t to the contents of a dk_geom struct
 */
#define	VD_GEOM2DK_GEOM(vd_geom, dk_geom)				\
{									\
	bzero((dk_geom), sizeof (*(dk_geom)));				\
	(dk_geom)->dkg_ncyl		= (vd_geom)->ncyl;		\
	(dk_geom)->dkg_acyl		= (vd_geom)->acyl;		\
	(dk_geom)->dkg_bcyl		= (vd_geom)->bcyl;		\
	(dk_geom)->dkg_nhead		= (vd_geom)->nhead;		\
	(dk_geom)->dkg_nsect		= (vd_geom)->nsect;		\
	(dk_geom)->dkg_intrlv		= (vd_geom)->intrlv;		\
	(dk_geom)->dkg_apc		= (vd_geom)->apc;		\
	(dk_geom)->dkg_rpm		= (vd_geom)->rpm;		\
	(dk_geom)->dkg_pcyl		= (vd_geom)->pcyl;		\
	(dk_geom)->dkg_write_reinstruct	= (vd_geom)->write_reinstruct;	\
	(dk_geom)->dkg_read_reinstruct	= (vd_geom)->read_reinstruct;	\
}

/*
 * Copy the contents of a vd_vtoc_t to the contents of a vtoc struct
 */
#define	VD_VTOC2VTOC(vd_vtoc, vtoc)					\
{									\
	bzero((vtoc), sizeof (*(vtoc)));				\
	bcopy((vd_vtoc)->volume_name, (vtoc)->v_volume,			\
	    MIN(sizeof ((vd_vtoc)->volume_name),			\
		sizeof ((vtoc)->v_volume)));				\
	bcopy((vd_vtoc)->ascii_label, (vtoc)->v_asciilabel,		\
	    MIN(sizeof ((vd_vtoc)->ascii_label),			\
		sizeof ((vtoc)->v_asciilabel)));			\
	(vtoc)->v_sanity	= VTOC_SANE;				\
	(vtoc)->v_version	= V_VERSION;				\
	(vtoc)->v_sectorsz	= (vd_vtoc)->sector_size;		\
	(vtoc)->v_nparts	= (vd_vtoc)->num_partitions;		\
	for (int i = 0; i < (vd_vtoc)->num_partitions; i++) {		\
		(vtoc)->v_part[i].p_tag	= (vd_vtoc)->partition[i].id_tag; \
		(vtoc)->v_part[i].p_flag = (vd_vtoc)->partition[i].perm; \
		(vtoc)->v_part[i].p_start = (vd_vtoc)->partition[i].start; \
		(vtoc)->v_part[i].p_size = (vd_vtoc)->partition[i].nblocks; \
	}								\
}

/*
 * Copy the contents of a dk_geom struct to the contents of a vd_geom_t
 */
#define	DK_GEOM2VD_GEOM(dk_geom, vd_geom)				\
{									\
	bzero((vd_geom), sizeof (*(vd_geom)));				\
	(vd_geom)->ncyl			= (dk_geom)->dkg_ncyl;		\
	(vd_geom)->acyl			= (dk_geom)->dkg_acyl;		\
	(vd_geom)->bcyl			= (dk_geom)->dkg_bcyl;		\
	(vd_geom)->nhead		= (dk_geom)->dkg_nhead;		\
	(vd_geom)->nsect		= (dk_geom)->dkg_nsect;		\
	(vd_geom)->intrlv		= (dk_geom)->dkg_intrlv;	\
	(vd_geom)->apc			= (dk_geom)->dkg_apc;		\
	(vd_geom)->rpm			= (dk_geom)->dkg_rpm;		\
	(vd_geom)->pcyl			= (dk_geom)->dkg_pcyl;		\
	(vd_geom)->write_reinstruct	= (dk_geom)->dkg_write_reinstruct; \
	(vd_geom)->read_reinstruct	= (dk_geom)->dkg_read_reinstruct; \
}

/*
 * Copy the contents of a vtoc struct to the contents of a vd_vtoc_t
 */
#define	VTOC2VD_VTOC(vtoc, vd_vtoc)					\
{									\
	bzero((vd_vtoc), sizeof (*(vd_vtoc)));				\
	bcopy((vtoc)->v_volume, (vd_vtoc)->volume_name,			\
	    MIN(sizeof ((vtoc)->v_volume),				\
		sizeof ((vd_vtoc)->volume_name)));			\
	bcopy((vtoc)->v_asciilabel, (vd_vtoc)->ascii_label,		\
	    MIN(sizeof ((vtoc)->v_asciilabel),				\
		sizeof ((vd_vtoc)->ascii_label)));			\
	(vd_vtoc)->sector_size			= (vtoc)->v_sectorsz;	\
	(vd_vtoc)->num_partitions		= (vtoc)->v_nparts;	\
	for (int i = 0; i < (vtoc)->v_nparts; i++) {			\
		(vd_vtoc)->partition[i].id_tag	= (vtoc)->v_part[i].p_tag; \
		(vd_vtoc)->partition[i].perm	= (vtoc)->v_part[i].p_flag; \
		(vd_vtoc)->partition[i].start	= (vtoc)->v_part[i].p_start; \
		(vd_vtoc)->partition[i].nblocks	= (vtoc)->v_part[i].p_size; \
	}								\
}

/*
 * Copy the contents of a vd_efi_t to the contents of a dk_efi_t.
 * Note that (dk_efi)->dki_data and (vd_efi)->data should be correctly
 * initialized prior to using this macro.
 */
#define	VD_EFI2DK_EFI(vd_efi, dk_efi)					\
{									\
	(dk_efi)->dki_lba	= (vd_efi)->lba;			\
	(dk_efi)->dki_length	= (vd_efi)->length;			\
	bcopy((vd_efi)->data, (dk_efi)->dki_data, (dk_efi)->dki_length); \
}

/*
 * Copy the contents of dk_efi_t to the contents of vd_efi_t.
 * Note that (dk_efi)->dki_data and (vd_efi)->data should be correctly
 * initialized prior to using this macro.
 */
#define	DK_EFI2VD_EFI(dk_efi, vd_efi)					\
{									\
	(vd_efi)->lba		= (dk_efi)->dki_lba;			\
	(vd_efi)->length	= (dk_efi)->dki_length;			\
	bcopy((dk_efi)->dki_data, (vd_efi)->data, (vd_efi)->length);	\
}

#define	VD_MEDIATYPE2DK_MEDIATYPE(mt)					\
	((mt) == VD_MEDIA_FIXED ? DK_FIXED_DISK :			\
	    (mt) == VD_MEDIA_CD ? DK_CDROM :				\
	    (mt) == VD_MEDIA_DVD ? DK_DVDROM :				\
	    DK_UNKNOWN)

#define	DK_MEDIATYPE2VD_MEDIATYPE(mt)					\
	((mt) == DK_REMOVABLE_DISK ? VD_MEDIA_FIXED :			\
	    (mt) == DK_MO_ERASABLE ? VD_MEDIA_FIXED :			\
	    (mt) == DK_MO_WRITEONCE ? VD_MEDIA_FIXED :			\
	    (mt) == DK_AS_MO ? VD_MEDIA_FIXED :				\
	    (mt) == DK_CDROM ? VD_MEDIA_CD :				\
	    (mt) == DK_CDR ? VD_MEDIA_CD :				\
	    (mt) == DK_CDRW ? VD_MEDIA_CD :				\
	    (mt) == DK_DVDROM ? VD_MEDIA_DVD :				\
	    (mt) == DK_DVDR ? VD_MEDIA_DVD :				\
	    (mt) == DK_DVDRAM ? VD_MEDIA_DVD :				\
	    (mt) == DK_FIXED_DISK ? VD_MEDIA_FIXED :			\
	    (mt) == DK_FLOPPY ? VD_MEDIA_FIXED :			\
	    (mt) == DK_ZIP ? VD_MEDIA_FIXED :				\
	    (mt) == DK_JAZ ? VD_MEDIA_FIXED :				\
	    VD_MEDIA_FIXED)

/*
 * Hooks for EFI support
 */

/*
 * The EFI alloc_and_read() function will use some ioctls to get EFI data
 * but the device reference we will use is different depending if the command
 * is issued from the vDisk server side (vds) or from the vDisk client side
 * (vdc). The vd_efi_dev structure is filled by vdc/vds to indicate the ioctl
 * function to call back and to provide information about the virtual disk.
 */
typedef int (*vd_efi_ioctl_func)(void *, int, uintptr_t);

typedef	struct vd_efi_dev {
	void *vdisk;			/* opaque pointer to the vdisk */
	size_t block_size;		/* vdisk block size */
	size_t disk_size;		/* vdisk size in blocks */
	vd_efi_ioctl_func vdisk_ioctl;	/* vdisk ioctl function */
} vd_efi_dev_t;

#define	VD_EFI_DEV_SET(efi_dev, vdsk, ioctl)		\
	(efi_dev).vdisk = vdsk;				\
	(efi_dev).vdisk_ioctl = ioctl;			\
	(efi_dev).block_size = (vdsk)->block_size;	\
	(efi_dev).disk_size = (vdsk)->vdisk_size;


int vd_efi_alloc_and_read(vd_efi_dev_t *dev, efi_gpt_t **gpt, efi_gpe_t **gpe);
void vd_efi_free(vd_efi_dev_t *dev, efi_gpt_t *gpt, efi_gpe_t *gpe);

/*
 * Macros to update the I/O statistics kstat consumed by iostat(1m).
 */

/*
 * Given a pointer to the instance private data of a vDisk driver (vd),
 * the type of operation and the number of bytes read/written, this macro
 * updates the I/O statistics in the kstat.
 */
#define	VD_UPDATE_IO_STATS(vd, op, len)					\
	{								\
		ASSERT((vd) != NULL);					\
		ASSERT(MUTEX_HELD(&(vd)->lock));			\
		ASSERT(((op) == VD_OP_BREAD) || ((op) == VD_OP_BWRITE));\
		if ((vd)->io_stats != NULL) { 				\
			kstat_io_t *kip = KSTAT_IO_PTR((vd)->io_stats);	\
			if ((op) == VD_OP_BREAD) {			\
				kip->reads++;				\
				kip->nread += (len);			\
			} else {					\
				kip->writes++;				\
				kip->nwritten += (len);			\
			}						\
		}							\
	}

/*
 * These wrapper macros take a pointer to the I/O statistics kstat and
 * update the queue length statistics. These are 'safe' wrappers which
 * check to see if the kstat was created when the vDisk instance was
 * added (i.e. is not NULL).
 */
#define	VD_KSTAT_WAITQ_ENTER(vd)					\
	if ((vd)->io_stats != NULL) {					\
		ASSERT(MUTEX_HELD(&(vd)->lock));			\
		kstat_waitq_enter(KSTAT_IO_PTR((vd)->io_stats));	\
	}

#define	VD_KSTAT_WAITQ_EXIT(vd)						\
	if ((vd)->io_stats != NULL) {					\
		ASSERT(MUTEX_HELD(&(vd)->lock));			\
		kstat_waitq_exit(KSTAT_IO_PTR((vd)->io_stats));		\
	}

#define	VD_KSTAT_WAITQ_TO_RUNQ(vd)					\
	if ((vd)->io_stats != NULL) {					\
		ASSERT(MUTEX_HELD(&(vd)->lock));			\
		kstat_waitq_to_runq(KSTAT_IO_PTR((vd)->io_stats));	\
	}

#define	VD_KSTAT_RUNQ_ENTER(vd)						\
	if ((vd)->io_stats != NULL) {					\
		ASSERT(MUTEX_HELD(&(vd)->lock));			\
		kstat_runq_enter(KSTAT_IO_PTR((vd)->io_stats));		\
	}

#define	VD_KSTAT_RUNQ_EXIT(vd)						\
	if ((vd)->io_stats != NULL) {					\
		ASSERT(MUTEX_HELD(&(vd)->lock));			\
		kstat_runq_exit(KSTAT_IO_PTR((vd)->io_stats));		\
	}

/*
 * Given a pointer to the instance private data of a vDisk driver (vd) and
 * the name of the error stats entry we wish to update, increment that value
 */
#define	VD_UPDATE_ERR_STATS(vd, stat_entry)				\
{									\
	ASSERT((vd) != NULL);						\
	ASSERT(MUTEX_HELD(&(vd)->lock));				\
	if ((vd)->err_stats != NULL) {					\
		vd_err_stats_t	*stp;					\
		stp = (vd_err_stats_t *)(vd)->err_stats->ks_data;	\
		stp->stat_entry.value.ui32++;				\
	}								\
}

/* Structure to record vDisk error statistics */
typedef struct vd_err_stats {
	struct kstat_named	vd_softerrs;	/* Softerrs */
	struct kstat_named	vd_transerrs;	/* Transport errs */
	struct kstat_named	vd_protoerrs;	/* VIO Protocol errs */
	struct kstat_named	vd_vid;		/* Vendor ID */
	struct kstat_named	vd_pid;		/* Product ID */
	struct kstat_named	vd_capacity;	/* Capacity of the disk */
} vd_err_stats_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _VDSK_COMMON_H */
