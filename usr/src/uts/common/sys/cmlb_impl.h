/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CMLB_IMPL_H
#define	_SYS_CMLB_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/cmlb.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#if defined(_SUNOS_VTOC_8)
#define	NSDMAP			NDKMAP
#elif defined(_SUNOS_VTOC_16)
#define	NSDMAP			(NDKMAP + FD_NUMPART + 1)
#else
#error "No VTOC format defined."
#endif

#define	MAXPART			(NSDMAP + 1)
#define	WD_NODE			7


#if defined(__i386) || defined(__amd64)

#define	P0_RAW_DISK		(NDKMAP)
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


#define	CMLB_MUTEX(un)		(&((un)->un_mutex))
#define	CMLB_DEVINFO(un)	((un)->un_devi)
#define	CMLB_LABEL(un)		(DEVI(((un)->un_devi))->devi_binding_name)


#define	ISREMOVABLE(un)		(un->un_is_removable == 1)
#define	ISCD(un)		(un->un_device_type == DTYPE_RODIRECT)

#if defined(_SUNOS_VTOC_8)

#define	CMLBUNIT_SHIFT		3
#define	CMLBPART_MASK		7

#elif defined(_SUNOS_VTOC_16)

#define	CMLBUNIT_SHIFT		6
#define	CMLBPART_MASK		63

#else
#error "No VTOC format defined."
#endif

#define	CMLBUNIT(dev)		(getminor((dev)) >> CMLBUNIT_SHIFT)
#define	CMLBPART(dev)		(getminor((dev)) &  CMLBPART_MASK)


#define	TRUE 			1
#define	FALSE			0

/*
 * Return codes of cmlb_uselabel().
 */
#define	CMLB_LABEL_IS_VALID	0
#define	CMLB_LABEL_IS_INVALID	1

/*
 * fdisk partition mapping structure
 */
struct fmap {
	daddr_t fmap_start;	/* starting block number */
	daddr_t fmap_nblk;	/* number of blocks */
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


typedef struct cmlb_lun {
	dev_info_t	*un_devi;		/* pointer to devinfo */
	struct  	dk_vtoc un_vtoc;	/* disk VTOC */
	struct  	dk_geom un_g;		/* disk geometry */

	diskaddr_t	un_blockcount;		/* capacity */

	diskaddr_t	un_solaris_size;	/* size of Solaris partition */
	uint_t		un_solaris_offset;	/* offset to Solaris part. */

	struct  dk_map  un_map[MAXPART];	/* logical partitions */
	diskaddr_t	un_offset[MAXPART];	/* partition start blocks */

	struct fmap	un_fmap[FD_NUMPART];	/* fdisk partitions */

	uchar_t		un_asciilabel[LEN_DKL_ASCII];	/* Disk ASCII label */

	/*
	 * This is the HBAs current notion of the geometry of the drive,
	 * for HBAs that support the "geometry" property.
	 */
	struct cmlb_geom	un_lgeom;

	/*
	 * This is the geometry of the device as reported by the MODE SENSE,
	 * command, Page 3 (Format Device Page) and Page 4 (Rigid Disk Drive
	 * Geometry Page), assuming MODE SENSE is supported by the target.
	 */
	struct cmlb_geom	un_pgeom;

	ushort_t	un_dkg_skew;		/* skew */

	cmlb_label_t	un_def_labeltype;	/* default label type */

	/* label type based on which minor nodes were created last */
	cmlb_label_t	un_last_labeltype;

	cmlb_label_t	un_cur_labeltype;	/* current label type */

	/* indicates whether vtoc label is read from media */
	uchar_t		un_vtoc_label_is_from_media;

	cmlb_state_t	un_state;		/* state of handle */

	int		un_f_geometry_is_valid;
	int		un_sys_blocksize;

	kmutex_t	un_mutex;

	/* the following are passed in at attach time */
	int		un_is_removable;	/* 1 is removable */

	int		un_alter_behavior;
	char 		*un_node_type;		/* DDI_NT_... */
	int		un_device_type;		/* DTYPE_DIRECT,.. */
	cmlb_tg_ops_t 	*cmlb_tg_ops;


} cmlb_lun_t;

_NOTE(MUTEX_PROTECTS_DATA(cmlb_lun::un_mutex, cmlb_lun))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::cmlb_tg_ops))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::un_devi))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::un_is_removable))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::un_node_type))
_NOTE(SCHEME_PROTECTS_DATA("stable data", cmlb_lun::un_sys_blocksize))
_NOTE(SCHEME_PROTECTS_DATA("private data", cmlb_geom))


#define	DK_TG_READ(ihdlp, bufaddr, start_block, reqlength)\
	(ihdlp->cmlb_tg_ops->tg_rdwr)(CMLB_DEVINFO(ihdlp), TG_READ, bufaddr,\
	    start_block, reqlength)

#define	DK_TG_WRITE(ihdlp, bufaddr, start_block, reqlength)\
	(ihdlp->cmlb_tg_ops->tg_rdwr)(CMLB_DEVINFO(ihdlp), TG_WRITE, bufaddr,\
	    start_block, reqlength)

#define	DK_TG_GETPHYGEOM(ihdlp, phygeomp) \
	(ihdlp->cmlb_tg_ops->tg_getphygeom)(CMLB_DEVINFO(ihdlp), \
	    (cmlb_geom_t *)phygeomp)

#define	DK_TG_GETVIRTGEOM(ihdlp, virtgeomp) \
	(ihdlp->cmlb_tg_ops->tg_getvirtgeom)(CMLB_DEVINFO(ihdlp),\
	    (cmlb_geom_t *)virtgeomp)

#define	DK_TG_GETCAP(ihdlp, capp) \
	(ihdlp->cmlb_tg_ops->tg_getcapacity)(CMLB_DEVINFO(ihdlp), capp)

#define	DK_TG_GETATTRIBUTE(ihdlp, attributep) \
	(ihdlp->cmlb_tg_ops->tg_getattribute)(CMLB_DEVINFO(ihdlp), \
	    attributep)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_CMLB_IMPL_H */
