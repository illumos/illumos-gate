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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * DCD device structure.
 *
 *	All DCD target drivers will have one of these per target/lun.
 *	It will be created by a parent device and stored as driver private
 *	data in that device's dev_info_t (and thus can be retrieved by
 *	the function ddi_get_driver_private).
 */

#ifndef	_SYS_DCD_CONF_DEVICE_H
#define	_SYS_DCD_CONF_DEVICE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dada/dada_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct dcd_device {
	/*
	 * Routing info for this device.
	 */

	struct dcd_address	*dcd_address;

	/*
	 * Cross-reference to our dev_info_t.
	 */

	dev_info_t		*dcd_dev;

	/*
	 * Mutex for this device, initialized by
	 * parent prior to calling probe or attach
	 * routine.
	 */

	kmutex_t		dcd_mutex;

	/*
	 * Reserved, do not use.
	 */

	void			*dcd_reserved;


	/*
	 * If dcd_probe is used to probe out this device,
	 * a dcd_identify data structure will be allocated
	 * and an IDENTIFY command will be run to fill it in.
	 *
	 */

	struct dcd_identify	*dcd_ident;

	/*
	 * More detailed information is 'private' information, i.e., is
	 * only pertinent to Target drivers.
	 */

	caddr_t			dcd_private;

};


#ifdef	_KERNEL
#ifdef	__STDC__
extern int dcd_probe(struct dcd_device *devp, int (*callback)());
extern void dcd_unprobe(struct dcd_device *devp);
#else	/* __STDC__ */
extern int dcd_probe();
extern void dcd_unprobe();
#endif	/* __STDC__ */
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DCD_CONF_DEVICE_H */
