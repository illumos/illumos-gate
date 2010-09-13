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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _TTYMUXUSER_H
#define	_TTYMUXUSER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/termios.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	TTYMUX_MOD_ID		(0x540d)	/* T^m */
#define	TTYMUX_DRVNAME		"ttymux"

#define	TTYMUX_MAX_LINKS	(16)
/*
 * Generic serial multiplexor ioctls.
 */
#define	_TTYMUXIOC		(TTYMUX_MOD_ID<<8)
#define	TTYMUX_ASSOC		(_TTYMUXIOC | 1)
#define	TTYMUX_DISASSOC		(_TTYMUXIOC | 2)
#define	TTYMUX_LIST		(_TTYMUXIOC | 3)
#define	TTYMUX_GETLINK		(_TTYMUXIOC | 4)
/*
 * Ioctls for serial multiplexors acting as the system console.
 */
#define	TTYMUX_SETABORT		(_TTYMUXIOC | 100)
#define	TTYMUX_GETABORT		(_TTYMUXIOC | 101)
#define	TTYMUX_CONSDEV		(_TTYMUXIOC | 102)
#define	TTYMUX_GETABORTSTR	(_TTYMUXIOC | 103)
#define	TTYMUX_GETCONSOLES	(_TTYMUXIOC | 104)
/*
 * Optional control ioctl.
 */
#define	TTYMUX_SETCTL		(_TTYMUXIOC | 200)
#define	TTYMUX_GETCTL		(_TTYMUXIOC | 201)

typedef	enum {FORINPUT = 1, FOROUTPUT = 2, FORIO = 3} io_mode_t;

/*
 * Create or destroy associations TTYMUX_ASSOC and TTYMUX_DISASSOC
 */
#define	AMSTAG	(0x414d5354)
typedef struct ttymux_association {
	dev_t		ttymux_udev;	/* the upper device to be associated */
				/* the device type of a linked lower stream */
	dev_t		ttymux_ldev;
				/* the linkid of a linked lower stream */
	int		ttymux_linkid;
	ulong_t		ttymux_tag;	/* tagged association */
	io_mode_t	ttymux_ioflag; /* FORINPUT FOROUTPUT FORIO */
					/* OBP device path of ldev */
	char		ttymux_path[MAXPATHLEN];
} ttymux_assoc_t;

/*
 * List all links known to a mux driver TTYMUX_LIST
 * If the user ioctl arg is NULL the return value is the
 * number of links in the driver (to facilitate the user
 * allocating enough space for the link information.
 * Otherwise the ioctl arg should point to the following
 * structure. nlinks indicates how many entries the user
 * has allocated in the array. The return value indicates the
 * number of entries that have been filled in.
 * EINVAL if nlinks is < 1
 * EAGAIN if no resources.
 */
typedef struct ttymux_associations {
	ulong_t		ttymux_nlinks;
	ttymux_assoc_t	*ttymux_assocs;
} ttymux_assocs_t;

/*
 * Enable or disable aborting to the system monitor
 * TTYMUX_SETABORT and TTYMUX_GETABORT
 */
enum ttymux_break_type {SOFTWARE_BREAK, HARDWARE_BREAK, SOFTHARD_BREAK};

typedef struct ttymux_abort {
			/* apply request to this device */
	dev_t			ttymux_ldev;
	enum ttymux_break_type	ttymux_method;
	uint_t			ttymux_enable;
} ttymux_abort_t;

/*
 * Ioctl acknowledgement policies.
 */
#define	FIRSTACK	0
#define	LASTACK		1
#define	CONSENSUS	2
#define	PERIOCTL	3

/*
 * Set or get the ioctl acknowledgement policy and masking of control bits
 * TTYMUX_SETCTL and TTYMUX_GETCTL
 */

struct ttymux_policy {
	dev_t		ttymux_udev;	/* apply the request to this device */
			/* determines the method used to ack M_IOCTLS */
	int		ttymux_policy;
	tcflag_t	ttymux_cmask;	/* never set these control bits */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _TTYMUXUSER_H */
