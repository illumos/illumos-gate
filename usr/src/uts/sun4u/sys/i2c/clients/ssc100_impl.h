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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SSC100_IMPL_H
#define	_SSC100_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/i2c/clients/i2c_client.h>

/*
 * SSC100_BIT_READ_MASK takes in a byte from the device and the bit that
 * the user wants to read.  I shifts the byte over so that the bit that we
 * want is in the 1's bit and masks out the rest of the byte.
 */
#define	SSC100_BIT_READ_MASK(byte, bit)	((byte >> bit) & 0x01)

/*
 * SSC100_BIT_WRITE_MASK takes in a byte from the device, the bit that the
 * user wants to read write, and the value that the user wants put into that
 * bit. It zero's out the bit that we are writing to in the byte and then or's
 * the value(which was shifted to the bit location we wanted) to fill in only
 * that bit in the byte
 */
#define	SSC100_BIT_WRITE_MASK(byte, bit, value)\
				((value << bit) | (byte & (~(0x01 << bit))))

#define	SSC100_SIZE		8192
#define	SSC100_PAGESIZE		32
#define	SSC100_PAGEMASK		(SSC100_PAGESIZE - 1)

struct ssc100_unit {
	kmutex_t		ssc100_mutex;
	uint8_t			ssc100_flags;
	int			ssc100_oflag;
	int			ssc100_size;
	i2c_client_hdl_t	ssc100_hdl;
	char			ssc100_name[24];
};

#ifdef DEBUG

static int ssc100debug = 0;
#define	D1CMN_ERR(ARGS) if (ssc100debug & 0x1) cmn_err ARGS;
#define	D2CMN_ERR(ARGS) if (ssc100debug & 0x2) cmn_err ARGS;

#else

#define	D1CMN_ERR(ARGS)
#define	D2CMN_ERR(ARGS)

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SSC100_IMPL_H */
