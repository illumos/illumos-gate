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

#ifndef	_ISO646_H
#define	_ISO646_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Introduced in ISO/IEC 9899:1990/Ammendment 1:1995 (C Standard).
 * In ISO/IEC 14882:1998 (C++ Standard), these tokens are keywords
 * rather than macro names.
 */

#if !defined(__cplusplus) || __cplusplus < 199711L
#define	and	&&
#define	and_eq	&=
#define	bitand	&
#define	bitor	|
#define	compl	~
#define	not	!
#define	not_eq	!=
#define	or	||
#define	or_eq	|=
#define	xor	^
#define	xor_eq	^=
#endif	/* !defined(__cplusplus) || __cplusplus < 199711 */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO646_H */
