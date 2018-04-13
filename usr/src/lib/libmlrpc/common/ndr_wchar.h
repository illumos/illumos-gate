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

#ifndef _NDR_WCHAR_H
#define	_NDR_WCHAR_H

/*
 * Some ndr_wchar_t support stuff.
 */

#define	NDR_MB_CUR_MAX		3
#define	NDR_MB_CHAR_MAX		NDR_MB_CUR_MAX
#define	NDR_STRING_MAX		4096

size_t ndr__mbstowcs(uint16_t *, const char *, size_t);
size_t ndr__mbstowcs_le(uint16_t *, const char *, size_t);

size_t ndr__wcslen(const uint16_t *);
size_t ndr__wcstombs(char *, const uint16_t *, size_t);

#endif /* _NDR_WCHAR_H */
