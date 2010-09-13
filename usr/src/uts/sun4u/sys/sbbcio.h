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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SBBCIO_H
#define	_SYS_SBBCIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	SBBC_IOC		('s' << 8)

#define	SBBC_SBBCREG_WR		_IOWR('s', 2, struct ssc_sbbc_regio)
#define	SBBC_SBBCREG_RD		_IOWR('s', 7, struct ssc_sbbc_regio)

/* offset 0x000000 to 0x07FFFF - read write sbbc internal registers */
struct ssc_sbbc_regio {
	uint32_t offset;	/* provided by SSC application SW */
	uint32_t len;		/* provided by SSC application SW */
	uint32_t value;		/* provided by SSC application SW */
	uint32_t retval;	/* return value provided by driver */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBBCIO_H */
