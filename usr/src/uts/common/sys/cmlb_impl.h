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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CMLB_IMPL_H
#define	_SYS_CMLB_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/cmlb.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * FDISK partitions - 4 primary and MAX_EXT_PARTS number of Extended
 * Partitions.
 */
#define	FDISK_PARTS		(FD_NUMPART + MAX_EXT_PARTS)

#if defined(_SUNOS_VTOC_8)
/*
 * As lofi needs to support p0 on sparc in case of labeled virtual disks,
 * define NDSMAP to support one extra entrie.
 */
#define	NSDMAP			(NDKMAP + 1)
#elif defined(_SUNOS_VTOC_16)
#define	NSDMAP			(NDKMAP + FDISK_PARTS + 1)
#else
#error "No VTOC format defined."
#endif

#define	MAXPART			(NSDMAP + 1)
#define	WD_NODE			7
#define	P0_RAW_DISK		(NDKMAP)

#if defined(__i386) || defined(__amd64)

#define	FDISK_P1		(NDKMAP+1)
#define	FDISK_P2		(NDKMAP+2)
#define	FDISK_P3		(NDKMAP+3)
#define	FDISK_P4		(NDKMAP+4)

#endif  /* __i386 || __amd64 */

/* Driver Logging Levels */
#define	CMLB_LOGMASK_ERROR	0x00000001
#define	CMLB_LOGMASK_INFO	0x00000002
#define	CMLB_LOGMASK_TRACE	0x00000004

#define	CMLB_TRACE		0x00000001
#define	CMLB_INFO		0x00000002
#define	CMLB_ERROR		0x00000004


#define	CMLB_MUTEX(cl)		(&((cl)->cl_mutex))
#define	CMLB_DEVINFO(cl)	((cl)->cl_devi)
#define	CMLB_LABEL(cl)		(ddi_driver_name((cl->cl_devi)))


#define	ISREMOVABLE(cl)		(cl->cl_is_removable)
#define	ISCD(cl)		(cl->cl_device_type == DTYPE_RODIRECT)
#define	ISHOTPLUGGABLE(cl)	(cl->cl_is_hotpluggable)

#define	CMLBUNIT_SHIFT		(CMLBUNIT_DFT_SHIFT)
#define	CMLBPART_MASK		((1 << CMLBUNIT_SHIFT) - 1)

#define	CMLBUNIT(dev, shift)	(getminor((dev)) >> (shift))
#define	CMLBPART(dev)		(getminor((dev)) &  CMLBPART_MASK)

/*
 * Return codes of cmlb_uselabel().
 */
#define	CMLB_LABEL_IS_VALID	0
#define	CMLB_LABEL_IS_INVALID	1

#define	CMLB_2TB_BLOCKS		0xffffffff
#define	CMLB_1TB_BLOCKS		0x7fffffff

#define	CMLB_EXTVTOC_LIMIT	CMLB_2TB_BLOCKS
#define	CMLB_OLDVTOC_LIMIT	CMLB_1TB_BLOCKS

/*
 * fdisk partition mapping structure
 */
struct fmap {
	ulong_t fmap_start;	/* starting block number */
	ulong_t fmap_nblk;	/* number of blocks */
	uchar_t fmap_systid;		/* systid of the partition */
};

/* for cm_state */
typedef enum  {
	CMLB_INITED = 0,
	CMLB_ATTACHED
} cmlb_state_t;

typedef enum
{
	CMLB_LABEL_UNDEF = 0,
	CMLB_LABEL_VTOC,
	CMLB_LABEL_EFI
} cmlb_label_t;

#define	CMLB_ALLOW_2TB_WARN 0x1


typedef struct cmlb_lun {
	dev_info_t	*cl_devi;		/* pointer to devinfo */
	struct dk_vtoc	cl_vtoc;	/* disk VTOC */
	struct dk_geom	cl_g;		/* disk geometry */

	diskaddr_t	cl_blockcount;		/* capacity */
	uint32_t	cl_tgt_blocksize;	/* blocksize */

	diskaddr_t	cl_solaris_size;	/* size of Solaris partition */
	uint_t		cl_solaris_offset;	/* offset to Solaris part. */

	struct  dk_map  cl_map[MAXPART];	/* logical partitions */
						/* cylno is overloaded. used */
						/* for starting block for EFI */

	diskaddr_t	cl_offset[MAXPART];	/* partition start blocks */

	struct fmap	cl_fmap[FDISK_PARTS];	/* fdisk partitions */

	uchar_t		cl_asciilabel[LEN_DKL_ASCII];	/* Disk ASCII label */

	/*
	 * This is the HBAs current notion of the geometry of the drive,
	 * for HBAs that support the "geometry" property.
	 */
	struct cmlb_geom	cl_lgeom;

	/*
	 * This is the geometry of the device as reported by the MODE SENSE,
	 * command, Page 3 (Format Device Page) and Page 4 (Rigid Disk Drive
	 * Geometry Page), assuming MODE SENSE is supported by the target.
	 */
	struct cmlb_geom	cl_pgeom;

	ushort_t	cl_dkg_skew;		/* skew */

	cmlb_label_t	cl_def_labeltype;	/* default label type */

	/* label type based on which minor nodes were created last */
	cmlb_label_t	cl_last_labeltype;

	cmlb_label_t	cl_cur_labeltype;	/* current label type */

	/* indicates whether vtoc label is read from media */
	cmlb_label_t		cl_label_from_media;

	cmlb_state_t	cl_state;		/* state of handle */

	boolean_t	cl_f_geometry_is_valid;
	int		cl_sys_blocksize;

	kmutex_t	cl_mutex;

	/* the following are passed in at attach time */
	boolean_t	cl_is_removable;	/* is removable */
	boolean_t	cl_is_hotpluggable;	/* is hotpluggable */
	int		cl_alter_behavior;
	char 		*cl_node_type;		/* DDI_NT_... */
	int		cl_device_type;		/* DTYPE_DIRECT,.. */
	int		cl_reserved;		/* reserved efi partition # */
	cmlb_tg_ops_t 	*cmlb_tg_ops;
#if defined(__i386) || defined(__amd64)
	/*
	 * Flag indicating whether extended partition nodes should be created
	 * or not. Is set in cmlb_attach. After creating nodes in
	 * cmlb_read_fdisk, it will be unset.
	 */
	int		cl_update_ext_minor_nodes;
	int		cl_logical_drive_count;
#endif  /* __i386 || __amd64 */
	uint8_t		cl_msglog_flag;		/* used to enable/suppress */
						/* certain log messages */
} cmlb_lun_t;

_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::cmlb_tg_ops))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::cl_devi))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::cl_is_removable))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::cl_is_hotpluggable))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::cl_node_type))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::cl_sys_blocksize))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::cl_alter_behavior))
_NOTE(SCHEME_PROTECTS_DATA("private data", cmlb_geom))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing", cmlb_lun::cl_f_geometry_is_valid))

_NOTE(MUTEX_PROTECTS_DATA(cmlb_lun::cl_mutex, cmlb_lun::cl_vtoc))


#define	DK_TG_READ(ihdlp, bufaddr, start_block, reqlength, tg_cookie)\
	(ihdlp->cmlb_tg_ops->tg_rdwr)(CMLB_DEVINFO(ihdlp), TG_READ, \
	bufaddr, start_block, reqlength, tg_cookie)

#define	DK_TG_WRITE(ihdlp,  bufaddr, start_block, reqlength, tg_cookie)\
	(ihdlp->cmlb_tg_ops->tg_rdwr)(CMLB_DEVINFO(ihdlp), TG_WRITE,\
	bufaddr, start_block, reqlength, tg_cookie)

#define	DK_TG_GETPHYGEOM(ihdlp, phygeomp, tg_cookie) \
	(ihdlp->cmlb_tg_ops->tg_getinfo)(CMLB_DEVINFO(ihdlp), TG_GETPHYGEOM,\
	    (void *)phygeomp, tg_cookie)

#define	DK_TG_GETVIRTGEOM(ihdlp, virtgeomp, tg_cookie) \
	(ihdlp->cmlb_tg_ops->tg_getinfo)(CMLB_DEVINFO(ihdlp), TG_GETVIRTGEOM,\
	    (void *)virtgeomp, tg_cookie)

#define	DK_TG_GETCAP(ihdlp, capp, tg_cookie) \
	(ihdlp->cmlb_tg_ops->tg_getinfo)(CMLB_DEVINFO(ihdlp), TG_GETCAPACITY,\
	capp, tg_cookie)

#define	DK_TG_GETBLOCKSIZE(ihdlp, lbap, tg_cookie) \
	(ihdlp->cmlb_tg_ops->tg_getinfo)(CMLB_DEVINFO(ihdlp),\
	TG_GETBLOCKSIZE, lbap, tg_cookie)

#define	DK_TG_GETATTRIBUTE(ihdlp, attributep, tg_cookie) \
	(ihdlp->cmlb_tg_ops->tg_getinfo)(CMLB_DEVINFO(ihdlp), TG_GETATTR,\
	    attributep, tg_cookie)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_CMLB_IMPL_H */
