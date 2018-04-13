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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_WINTYPES_H
#define	_SMB_WINTYPES_H

#include <sys/types.h>

/*
 * Standard win32 types and definitions.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UNSIGNED_TYPES_DEFINED
#define	UNSIGNED_TYPES_DEFINED

typedef	uint8_t BYTE;
typedef	uint16_t WORD;
typedef	uint32_t DWORD;
typedef	DWORD ntstatus_t;

/* pointers to those types */
typedef	BYTE *LPBYTE;
typedef	WORD *LPWORD;
typedef	DWORD *LPDWORD;

/* Note: Internally, this is always a UTF-8 string. */
typedef	uint8_t *LPTSTR;

#endif /* UNSIGNED_TYPES_DEFINED */

#ifndef ANY_SIZE_ARRAY
#define	ANY_SIZE_ARRAY  1
#endif /* ANY_SIZE_ARRAY */

/* CONTEXT_HANDLE now in ndrtypes.ndl */

#ifdef __cplusplus
}
#endif

#endif /* _SMB_WINTYPES_H */
