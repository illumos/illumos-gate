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

#ifndef	_SYS_DLD_H
#define	_SYS_DLD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Driver (public header).
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/mac.h>
#include <sys/dls.h>
#include <sys/ght.h>
#include <net/if.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Data-Link Driver Information (text emitted by modinfo(1m))
 */
#define	DLD_INFO	"Data-Link Driver v%I%"

/*
 * Options: To enable an option set the property name to a non-zero value
 *	    in kernel/drv/dld.conf.
 */

/*
 * Prevent creation of DLPI style 1 provider nodes (thus forcing stacks such
 * as TCP/IP to use style 2 nodes).
 */
#define	DLD_PROP_NO_STYLE1	"no-style-1"

/*
 * Prevent use of the IP fast-path (direct M_DATA transmit).
 */
#define	DLD_PROP_NO_FASTPATH	"no-fastpath"

/*
 * Prevent advertising of the DL_CAPAB_POLL capability.
 */
#define	DLD_PROP_NO_POLL	"no-poll"

/*
 * Prevent advertising of the DL_CAPAB_ZEROCOPY capability.
 */
#define	DLD_PROP_NO_ZEROCOPY	"no-zerocopy"

/*
 * The name of the driver.
 */
#define	DLD_DRIVER_NAME		"dld"

/*
 * The name of the control minor node of dld.
 */
#define	DLD_CONTROL_MINOR_NAME	"ctl"
#define	DLD_CONTROL_MINOR	0
#define	DLD_CONTROL_DEV		"/devices/pseudo/" DLD_DRIVER_NAME "@0:" \
				DLD_CONTROL_MINOR_NAME

/*
 * IOCTL codes and data structures.
 */
#define	DLDIOC		('D' << 24 | 'L' << 16 | 'D' << 8)

#define	DLDIOCCREATE	(DLDIOC | 0x01)

typedef struct dld_ioc_create {
	char		dic_name[IFNAMSIZ];
	char		dic_dev[MAXNAMELEN];
	uint_t		dic_port;
	uint16_t	dic_vid;
} dld_ioc_create_t;

#define	DLDIOCDESTROY	(DLDIOC | 0x02)

typedef struct dld_ioc_destroy {
	char	did_name[IFNAMSIZ];
} dld_ioc_destroy_t;

#define	DLDIOCATTR	(DLDIOC | 0x03)

typedef struct dld_ioc_attr {
	char		dia_name[IFNAMSIZ];
	char		dia_dev[MAXNAMELEN];
	uint_t		dia_port;
	uint16_t	dia_vid;
} dld_ioc_attr_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLD_H */
