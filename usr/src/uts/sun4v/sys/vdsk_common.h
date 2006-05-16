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
#define	VD_LDC_QLEN		32

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
#define	VD_OP_MASK		0xFF	/* mask of all possible operations */
#define	VD_OP_COUNT		10	/* Number of operations */

/*
 * Definitions of the various ways vds can export disk support to vdc.
 */
typedef enum vd_disk_type {
	VD_DISK_TYPE_UNK = 0,		/* Unknown device type */
	VD_DISK_TYPE_SLICE,		/* slice in block device */
	VD_DISK_TYPE_DISK		/* entire disk (slice 2) */
} vd_disk_type_t;

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
 * vDisk control operation structures
 *
 * XXX FIXME - future support - add structures for VD_OP_XXXX
 */

/*
 * VTOC message
 *
 * vDisk Get Volume Table of Contents (VD_OP_GET_VTOC)
 *
 */
typedef struct vd_partition {
	uint16_t	p_tag;		/* ID tag of partition */
	uint16_t	p_flag;		/* permision flags */
	uint32_t	reserved;	/* padding */
	int64_t		p_start;	/* start sector no of partition */
	int64_t		p_size;		/* # of blocks in partition */
} vd_partition_t;

typedef struct vd_vtoc {
	uint8_t		v_volume[LEN_DKL_VVOL]; /* volume name */
	uint16_t	v_sectorsz;		/* sector size in bytes */
	uint16_t	v_nparts;		/* num of partitions */
	uint32_t	reserved;		/* padding */
	uint8_t		v_asciilabel[LEN_DKL_ASCII];    /* for compatibility */

} vd_vtoc_t;


/*
 * vDisk Get Geometry (VD_OP_GET_GEOM)
 */
typedef struct vd_geom {
	uint16_t	dkg_ncyl;	/* # of data cylinders */
	uint16_t	dkg_acyl;	/* # of alternate cylinders */
	uint16_t	dkg_bcyl;	/* cyl offset (for fixed head area) */
	uint16_t	dkg_nhead;	/* # of heads */
	uint16_t	dkg_nsect;	/* # of data sectors per track */
	uint16_t	dkg_intrlv;	/* interleave factor */
	uint16_t	dkg_apc;	/* alternates per cyl (SCSI only) */
	uint16_t	dkg_rpm;	/* revolutions per minute */
	uint16_t	dkg_pcyl;	/* # of physical cylinders */
	uint16_t	dkg_write_reinstruct;	/* # sectors to skip, writes */
	uint16_t	dkg_read_reinstruct;	/* # sectors to skip, reads */
} vd_geom_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _VDSK_COMMON_H */
