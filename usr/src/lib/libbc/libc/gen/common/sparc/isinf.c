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
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Recognize an infinity or a NaN when one is presented.
 * This is for keeping various IO routines out of trouble 
 */


int
isinf( d0, d1 )
    unsigned d0,d1;
    /* a lie -- actually its a ``double'' */
{
    if (d1 != 0 ) return 0; /* nope -- low-order must be all zeros */
    if (d0 != 0x7ff00000 && d0 != 0xfff00000) return 0; /* nope */
    return 1;
}

int
isnan( d0,d1 )
    unsigned d0,d1;
    /* a lie -- actually its a ``double'' */
{
#define EXPONENT 0x7ff00000
#define SIGN     0x80000000
    if ((d0 & EXPONENT) != EXPONENT ) return 0; /* exponent wrong */
    if ((d0 & ~(EXPONENT|SIGN)) == 0 && d1 == 0 ) return 0; /* must have bits */
    return 1;
}
