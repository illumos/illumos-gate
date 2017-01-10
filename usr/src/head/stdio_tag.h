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

#ifndef _STDIO_TAG_H
#define	_STDIO_TAG_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	__FILE_TAG
#if defined(__cplusplus) && !defined(__GNUC__) && (__cplusplus < 54321L)
#define	__FILE_TAG	FILE
#else
#define	__FILE_TAG	__FILE
#endif
typedef struct __FILE_TAG __FILE;
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _STDIO_TAG_H */
