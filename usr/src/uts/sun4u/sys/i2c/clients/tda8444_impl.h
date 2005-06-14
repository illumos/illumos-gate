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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TDA844_IMPL_H
#define	_TDA844_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/promif.h>

#define	TDA8444_MAX_DACS	16
#define	TDA8444_CHANS		8
#define	TDA8444_BUSY		0x01
#define	TDA8444_SUSPENDED	0x02

#define	TDA8444_REGBASE		0xf0

#define	TDA8444_UNKNOWN_OUT	-1
#define	TDA8444_MAX_OUT		0x3f
#define	TDA8444_MIN_OUT		0x0

#define	TDA8444_MINOR_TO_DEVINST(x) ((x & 0xf00) >> 8)
#define	TDA8444_MINOR_TO_CHANNEL(x) (x & 0x00f)

#define	TDA8444_CHANNEL_TO_MINOR(x) x
#define	TDA8444_DEVINST_TO_MINOR(x) (x << 8)

#define	TDA8444_NODE_TYPE "ddi_i2c:adio"

/*
 * Defines for debug printing
 */
#define	DPRINTF(print_flag, args)                       \
    if (tda8444_debug & (print_flag)) { prom_printf args; }

#define	RESUME	0x01
#define	IO	0x02

struct tda8444_unit {
	i2c_transfer_t		*tda8444_transfer;
	kmutex_t		tda8444_mutex;
	kcondvar_t		tda8444_cv;
	uint8_t			tda8444_flags;
	int8_t			tda8444_output[TDA8444_MAX_DACS];
	i2c_client_hdl_t	tda8444_hdl;
	char			tda8444_name[12];
	uint16_t		tda8444_oflag[TDA8444_MAX_DACS];
};

#ifdef	__cplusplus
}
#endif

#endif /* _TDA844_IMPL_H */
