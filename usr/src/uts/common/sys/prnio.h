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

#ifndef	_SYS_PRNIO_H
#define	_SYS_PRNIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Printing system I/O interface
 */

#include <sys/types.h>
#include <sys/ioccom.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PRNIOC			'p'
#define	PRNIOC_GET_IFCAP	_IOR(PRNIOC, 90, uint_t)
#define	PRNIOC_SET_IFCAP	_IOR(PRNIOC, 91, uint_t)
#define	PRNIOC_GET_IFINFO	_IOWR(PRNIOC, 92, struct prn_interface_info)
#define	PRNIOC_GET_STATUS	_IOR(PRNIOC, 93, uint_t)
#define	PRNIOC_GET_1284_DEVID	_IOWR(PRNIOC, 94, struct prn_1284_device_id)
#define	PRNIOC_GET_1284_STATUS	_IOR(PRNIOC, 95, uchar_t)
#define	PRNIOC_GET_TIMEOUTS	_IOR(PRNIOC, 96, struct prn_timeouts)
#define	PRNIOC_SET_TIMEOUTS	_IOW(PRNIOC, 97, struct prn_timeouts)
#define	PRNIOC_RESET		_IO(PRNIOC, 98)

/*
 * interface capabilities
 */
#define	PRN_BIDI	0x0001	/* bi-directional operation is supported */
#define	PRN_HOTPLUG	0x0002	/* interface allows device hotplugging */
#define	PRN_1284_DEVID	0x0004	/* device can return 1284 device ID */
#define	PRN_1284_STATUS	0x0008	/* device can return status lines state */
#define	PRN_TIMEOUTS	0x0010	/* timeouts are supported */
#define	PRN_STREAMS	0x0020	/* special flush semantics */

/*
 * printer interface info
 */
struct prn_interface_info {
	uint_t		if_len;		/* length of buffer */
	uint_t		if_rlen;	/* actual length of info string */
	char		*if_data;	/* buffer address */
#ifndef _LP64
	int		if_filler;	/* preserve struct size in 32 bit */
#endif
};

/*
 * printer interface info string (recommended values)
 */
#define	PRN_PARALLEL	"parallel"	/* parallel port (Centronics or 1284) */
#define	PRN_SERIAL	"serial"	/* serial port (EIA-232, EIA-485) */
#define	PRN_USB		"USB"		/* USB */
#define	PRN_1394	"1394"		/* IEEE 1394 (Firewire) */

/*
 * status bits for PRNIOC_GET_STATUS
 */
#define	PRN_ONLINE	0x01	/* device is connected */
#define	PRN_READY	0x02	/* device is ready to communicate */

/*
 * 1284 pins status bits
 */
#define	PRN_1284_NOFAULT	0x08	/* device is not in error state */
#define	PRN_1284_SELECT		0x10	/* device selected */
#define	PRN_1284_PE		0x20	/* paper error */
#define	PRN_1284_BUSY		0x80	/* device busy */

/*
 * IEEE 1284 device ID
 */
struct prn_1284_device_id {
	uint_t		id_len;		/* length of buffer */
	uint_t		id_rlen;	/* actual length of device ID string */
	char		*id_data;	/* buffer address */
#ifndef _LP64
	int		id_filler;	/* preserve struct size in 32 bit */
#endif
};

/*
 * printer driver timeouts
 */
struct prn_timeouts {
	uint_t		tmo_forward;	/* forward transfer timeout */
	uint_t		tmo_reverse;	/* reverse transfer timeout */
};

/*
 * driver support for 32-bit applications
 */
#ifdef _KERNEL

struct prn_interface_info32 {
	uint_t		if_len;		/* length of buffer */
	uint_t		if_rlen;	/* actual length of info string */
	caddr32_t	if_data;	/* buffer address */
};

struct prn_1284_device_id32 {
	uint_t		id_len;		/* length of buffer */
	uint_t		id_rlen;	/* actual length of device id string */
	caddr32_t	id_data;	/* buffer address */
};

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PRNIO_H */
