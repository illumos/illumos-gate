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
 *	Copyright 1998,2003 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

#ifndef	__CONV_DOT_H
#define	__CONV_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Local include file for conversion library.
 */
#include <conv.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Various values that can't be matched to a symbolic definition will be
 * converted to a numeric string.  Each function that may require this
 * fallback maintains its own static string buffer, as many conversion
 * routines may be called for one final diagnostic.
 *
 * Most strings are printed as a 10.10s, but the string size is big
 * enough for any 32 bit value.
 */
#define	STRSIZE		12
#define	STRSIZE64	24

#ifdef	__cplusplus
}
#endif

#endif	/* __CONV_DOT_H */
