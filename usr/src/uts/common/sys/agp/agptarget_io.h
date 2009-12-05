/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AGPTARGET_IO_H
#define	_SYS_AGPTARGET_IO_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	AGPTARGET_NAME		"agptarget"
#define	AGPTARGET_DEVLINK	"/dev/agp/agptarget"

/* macros for layered ioctls */
#define	AGPTARGETIOC_BASE		'M'
#define	CHIP_DETECT		_IOR(AGPTARGETIOC_BASE, 30, int)
#define	I8XX_GET_PREALLOC_SIZE	_IOR(AGPTARGETIOC_BASE, 31, size_t)
#define	AGP_TARGET_GETINFO	_IOR(AGPTARGETIOC_BASE, 32, i_agp_info_t)
#define	AGP_TARGET_SET_GATTADDR	_IOW(AGPTARGETIOC_BASE, 33, uint32_t)
#define	AGP_TARGET_SETCMD	_IOW(AGPTARGETIOC_BASE, 34, uint32_t)
#define	AGP_TARGET_FLUSH_GTLB	_IO(AGPTARGETIOC_BASE, 35)
#define	AGP_TARGET_CONFIGURE	_IO(AGPTARGETIOC_BASE, 36)
#define	AGP_TARGET_UNCONFIG	_IO(AGPTARGETIOC_BASE, 37)
#define	INTEL_CHIPSET_FLUSH_SETUP	_IO(AGPTARGETIOC_BASE, 38)
#define	INTEL_CHIPSET_FLUSH	_IO(AGPTARGETIOC_BASE, 39)
#define	INTEL_CHIPSET_FLUSH_FREE	_IO(AGPTARGETIOC_BASE, 40)

/* Internal agp info struct */
typedef struct _i_agp_info {
	agp_version_t	iagp_ver;
	uint32_t	iagp_devid;	/* bridge vendor + device */
	uint32_t	iagp_mode;	/* mode of brdige */
	uint64_t	iagp_aperbase;	/* base of aperture */
	size_t		iagp_apersize;	/* aperture range size in bytes */
} i_agp_info_t;


#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AGPTARGET_IO_H */
