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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SMBSRV_CTYPE_H
#define	_SMBSRV_CTYPE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/codepage.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	_mts_between(l, c, u) ((l) <= (c) && (c) <= (u))

/*
 * These macros take non-ascii characters into account.
 * Their behavior depends on the codepage that is used.
 */
#define	mts_islower(c)	codepage_islower((c))
#define	mts_isupper(c)	codepage_isupper((c))
#define	mts_tolower(c)	codepage_tolower((c))
#define	mts_toupper(c)	codepage_toupper((c))

#define	mts_isalpha(c)	(mts_islower(c) || mts_isupper(c))
#define	mts_isdigit(c)	_mts_between('0', (c), '9')
#define	mts_isalnum(c)	(mts_isalpha(c) || mts_isdigit(c))
#define	mts_isxdigit(c)	(mts_isdigit(c) ||			\
    _mts_between('a', (c), 'f') ||				\
    _mts_between('A', (c), 'F'))
#define	mts_isblank(c)	((c) == ' ' || (c) == '\t')
#define	mts_isspace(c)  ((c) == ' ' ||		\
	    (c) == '\t' ||			\
	    (c) == '\n' ||			\
	    (c) == '\r' ||			\
	    (c) == '\f')
#define	mts_isascii(c)	(!((c) &~ 0x7F))

/* These macros only apply to ASCII */
#define	mts_isalpha_ascii(c)	\
	(_mts_between('a', (c), 'z') || _mts_between('A', (c), 'Z'))
#define	mts_isalnum_ascii(c)	(mts_isalpha_ascii(c) || mts_isdigit(c))

/* should it include non-ascii characters ? */
#define	mts_isprint(c)	_mts_between('!', (c), '~')
#define	mts_iscntrl(c)	(((c) >= 0) && ((c) <= 0x1f)) || ((c) == 0x7f))
#define	mts_ispunct(c)  (mts_isprint(c) && !mts_isxdigit(c) && !mts_isspace(c))

#ifdef __cplusplus
}
#endif

#endif	/* _SMBSRV_CTYPE_H */
