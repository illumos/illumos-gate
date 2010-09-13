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

#ifndef _SYS__MD_SP_H
#define	_SYS__MD_SP_H

#include <sys/lvm/mdvar.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	META_SP_DEBUG ("META_SP_DEBUG")

/* on-disk structures */
#define	MD_SP_MAGIC			(0x20000127)
/* number of sectors to reserve at the beginning of the volume */
#define	MD_SP_START			(0)
/* current watermark version number */
#define	MD_SP_VERSION			(1)
/* size of a watermark in sectors */
#define	MD_SP_WMSIZE			(1)
/* free watermark name */
#define	MD_SP_FREEWMNAME		"free"
/* local set name */
#define	MD_SP_LOCALSETNAME		""
/* maximum length of a soft partition metadevice name. eg. dXXXX\0 */
#define	MD_SP_MAX_DEVNAME_PLUS_1	(6)

/*
 * The size of this structure is forced to be 512 bytes (ie a sector) by
 * using a union. Note the MD_MAX_SETNAME_PLUS_1 is set in meta_basic.h
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef union mp_watermark {
	struct {
		uint32_t	wm_magic;	/* magic number */
		uint32_t	wm_version;	/* version number */
		uint32_t	wm_checksum;	/* structure checksum */
		uint32_t	wm_seq;		/* sequence number */
		uint32_t	wm_type;	/* extent type */
		uint64_t	wm_length;	/* length of extent */
		char		wm_mdname[MD_MAX_SETNAME_PLUS_1 +
				    MD_SP_MAX_DEVNAME_PLUS_1];	/* SP name */
		char		wm_setname[MD_MAX_SETNAME_PLUS_1]; /* setname */
	} wm;
	uchar_t			wm_pad[MD_SP_WMSIZE * DEV_BSIZE];
} mp_watermark_t;
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#define	wm_magic	wm.wm_magic
#define	wm_version	wm.wm_version
#define	wm_checksum	wm.wm_checksum
#define	wm_seq		wm.wm_seq
#define	wm_type		wm.wm_type
#define	wm_length	wm.wm_length
#define	wm_mdname	wm.wm_mdname
#define	wm_setname	wm.wm_setname

/* Watermark types */
typedef enum sp_ext_type {
	EXTTYP_ALLOC	= 0x1,	/* this extent is in use by a soft partition */
	EXTTYP_FREE	= 0x2,	/* extent is not in use */
	EXTTYP_END	= 0x3,	/* last descriptor on the volume */
	EXTTYP_RESERVED	= 0x4	/* extent will not be used or updated */
} sp_ext_type_t;

/* ioctls */
#define	MD_IOC_SPSTATUS		(MDIOC_MISC|0)
#define	MD_IOC_SPUPDATEWM	(MDIOC_MISC|1)
#define	MD_IOC_SPREADWM		(MDIOC_MISC|2)
#define	MD_MN_IOC_SPUPDATEWM	(MDIOC_MISC|3)

#ifdef _KERNEL

/*
 * parent and child save areas provide the mechanism for tracking
 * I/O operations in the metadevice stack.
 */

/* soft partitioning parent save area */
typedef struct md_spps {		/* soft partition parent save */
	DAEMON_QUEUE
	mp_unit_t	*ps_un;		/* sp unit structure */
	mdi_unit_t	*ps_ui;		/* incore unit struct */
	buf_t		*ps_bp;		/* parent buffer */
	caddr_t		 ps_addr;
	int		 ps_frags;
	int		 ps_flags;
	/*
	 * New structure members should be added here; fields added
	 * after ps_mx will not be zeroed during initialization.
	 */
	kmutex_t	 ps_mx;
} md_spps_t;

/* parent save flags. */
#define	MD_SPPS_ERROR		0x0001
#define	MD_SPPS_DONTFREE	0x0002
#define	MD_SPPS_DONE		0x0004

/* soft partitioning child save area */
typedef struct md_spcs {
	DAEMON_QUEUE
	minor_t		 cs_mdunit;	/* child minor number */
	md_spps_t	*cs_ps;		/* parent save pointer */
	/* Add new structure members HERE!! */
	buf_t		 cs_buf;	/* child buffer */
	/*  DO NOT add struture members here; cs_buf is dynamically sized */
} md_spcs_t;

#define	SPPS_FREE(kc, ps)			\
{						\
	if ((ps)->ps_flags & MD_SPPS_DONTFREE)	\
		(ps)->ps_flags |= MD_SPPS_DONE;	\
	else					\
		kmem_cache_free((kc), (ps));	\
}

/* externals from sp.c */
extern int	sp_build_incore(void *, int);
extern void	reset_sp(mp_unit_t *, minor_t, int);
extern int	sp_directed_read(minor_t, vol_directed_rd_t *, int);

/* externals from sp_ioctl.c */
extern int	md_sp_ioctl(dev_t dev, int cmd, void *data,
	int mode, IOLOCK *lockp);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS__MD_SP_H */
