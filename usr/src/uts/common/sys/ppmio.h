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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PPMIO_H
#define	_SYS_PPMIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PPMIOC			('p' << 8)
#define	PPMIOCSET		(PPMIOC | 1)
#define	PPMIOCGET		(PPMIOC | 2)
#define	PPMGET_DPWR		(PPMIOC | 3)
#define	PPMGET_DOMBYDEV		(PPMIOC | 4)
#define	PPMGET_DEVBYDOM		(PPMIOC | 5)
/*
 * The following two ioctls are used for testing purposes only.
 */
#if defined(__x86)
#define	PPMGET_NORMAL		(PPMIOC | 6)
#define	PPMSET_NORMAL		(PPMIOC | 7)
#endif

/*
 * PPMIOCGET
 * Note: this ioctl command is available for Excalibur and Grover
 * only, but will be removed in future, replacing with PPMGET_DPWR
 */
typedef struct ppmreq {
	int	ppmdev;
	union ppmop {
		struct idev_power {
			int level;
		} idev_power;
	} ppmop;
} ppmreq_t;

/* definition for ppmdev */
#define	PPM_INTERNAL_DEVICE_POWER	1

/*
 * PPMGET_DPWR
 */
struct ppm_dpwr {
	char *domain;	/* domain name */
	int  level;	/* domain power level */
};

/*
 * PPMGET_DOMBYDEV
 */
struct ppm_bydev {
	char *path;	/* device prom path */
	char *domlist;	/* domain names */
	size_t   size;	/* size of domlist buffer */
};

/*
 * PPMGET_DEVBYDOM
 */
struct ppm_bydom {
	char *domain;	/* domain name */
	char *devlist;	/* domain device list */
	size_t   size;	/* size of devlist buffer */
};

/*
 * PPM[GS]ET_NORM
 */
struct ppm_norm {
	char *path;	/* device prom path */
	int  norm;	/* normal level */
};

#ifdef	_SYSCALL32
/*
 * kernel view of ILP32 data structure
 */
struct ppm_dpwr32 {
	caddr32_t domain;	/* domain name */
	int32_t  level;		/* domain power level */
};

struct ppm_bydev32 {
	caddr32_t path;		/* device prom path */
	caddr32_t domlist;	/* domain names */
	size32_t   size;	/* size of domlist buffer */
};

struct ppm_bydom32 {
	caddr32_t domain;	/* domain name */
	caddr32_t devlist;	/* domain device list */
	size32_t   size;	/* size of devlist buffer */
};

struct ppm_norm32 {
	caddr32_t path;		/* device prom path */
	int32_t  norm;		/* normal level */
};
#endif	/* _SYSCALL32 */

/*
 * .level may be the following
 */
#define	PPMIO_POWER_OFF		0
#define	PPMIO_POWER_ON		1
#define	PPMIO_LED_BLINKING	2
#define	PPMIO_LED_SOLIDON	3
/* (s10) */
#define	PPM_IDEV_POWER_OFF	PPMIO_POWER_OFF
#define	PPM_IDEV_POWER_ON	PPMIO_POWER_ON


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PPMIO_H */
