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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define L_BITSMAJOR     14      /* # of SVR4 major device bits */
#define L_BITSMINOR     18      /* # of SVR4 minor device bits */
#define L_MAXMIN        0x3ffff /* MAX minor for 3b2 software drivers.
                                ** For 3b2 hardware devices the minor is
                                ** restricted to 256 (0-255)
                                */
#define O_BITSMINOR     8       /* # of SunOS 4.x minor device bits */
#define O_MAXMAJ        0xff    /* SunOS 4.x max major value */
#define O_MAXMIN        0xff    /* SunOS 4.x max minor value */

/* convert to old dev format */

#define cmpdev(x)       (unsigned long)((((x)>>L_BITSMINOR) > O_MAXMAJ || \
                                ((x)&L_MAXMIN) > O_MAXMIN) ? NODEV : \
                                ((((x)>>L_BITSMINOR)<<O_BITSMINOR)|((x)&O_MAXMIN)))
