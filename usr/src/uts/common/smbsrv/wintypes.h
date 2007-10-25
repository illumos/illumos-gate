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

#ifndef _SMBSRV_WINTYPES_H
#define	_SMBSRV_WINTYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Standard win32 types and definitions.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UNSIGNED_TYPES_DEFINED
#define	UNSIGNED_TYPES_DEFINED

typedef	unsigned char BYTE;
typedef	unsigned short WORD;
typedef	unsigned int DWORD;
/* XXX PGD Shouldn't this be "char *"? */
typedef	unsigned char *LPTSTR;
typedef	unsigned char *LPBYTE;
typedef	unsigned short *LPWORD;
typedef	unsigned int *LPDWORD;

#endif /* UNSIGNED_TYPES_DEFINED */


#ifndef ANY_SIZE_ARRAY
#define	ANY_SIZE_ARRAY  1
#endif /* ANY_SIZE_ARRAY */

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_WINTYPES_H */
