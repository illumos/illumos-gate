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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BSCBUS_H
#define	_SYS_BSCBUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The bscbus nexus driver provides the same client interface as the lombus
 * nexus driver.
 */
#include <sys/lombus.h>

/*
 * Register spaces (as lombus.h but spaces now have a channel
 * value encoded in it too)
 *
 *	Space*	Size	Range		Meaning
 *		(bits)
 *
 *	xx00	8	[0 .. 16383]	LOM virtual registers
 *	xx01	8	[0]		Watchdog pat (on write)
 *	xx02	16	[0]		Async event info (read only)
 *	All	32	[-4 .. -12]	Access handle fault info
 *      * xx is the channel number.
 */

#define	LOMBUS_SPACE_TO_REGSET(rsp)	((rsp) & 0xff)
#define	LOMBUS_SPACE_TO_CHANNEL(rsp)	(((rsp) & 0xff00) >> 8)
#define	LOMBUS_SPACE(regset, channel)	((regset) | ((channel) << 8))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BSCBUS_H */
