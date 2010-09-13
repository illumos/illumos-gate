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

#ifndef	_MAX1617_H
#define	_MAX1617_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX1617_IOCTL	('A' << 8)

#define	MAX1617_GET_STATUS	(MAX1617_IOCTL |0)
#define	MAX1617_GET_CONFIG	(MAX1617_IOCTL |1)
#define	MAX1617_GET_CONV_RATE	(MAX1617_IOCTL |2)
#define	MAX1617_GET_HIGH_LIMIT	(MAX1617_IOCTL |3)
#define	MAX1617_GET_LOW_LIMIT	(MAX1617_IOCTL |4)
#define	MAX1617_SET_CONFIG	(MAX1617_IOCTL |5)
#define	MAX1617_SET_CONV_RATE	(MAX1617_IOCTL |6)
#define	MAX1617_SET_HIGH_LIMIT	(MAX1617_IOCTL |7)
#define	MAX1617_SET_LOW_LIMIT	(MAX1617_IOCTL |8)
#define	MAX1617_ONE_SHOT_CMD	(MAX1617_IOCTL |9)

#ifdef	__cplusplus
}
#endif

#endif	/* _MAX1617_H */
