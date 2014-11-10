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
 * Copyright 2014, Joyent, Inc. All rights reserved.
 */

#ifndef _SNGL_BRAND_H
#define	_SNGL_BRAND_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/brand.h>

#define	SNGL_BRANDNAME		"sngl"

#define	SNGL_VERSION		1

#define	SNGL_LIB_NAME		"sngl_brand.so.1"
#define	SNGL_LIB32		"/system/usr/lib/" SNGL_LIB_NAME
#define	SNGL_LIB64		"/system/usr/lib/64/" SNGL_LIB_NAME

#if defined(_LP64)
#define	SNGL_LIB	SNGL_LIB64
#else /* !_LP64 */
#define	SNGL_LIB	SNGL_LIB32
#endif /* !_LP64 */

#if defined(_KERNEL)

void sngl_brand_syscall_callback(void);
void sngl_brand_sysenter_callback(void);

#if defined(__amd64)
void sngl_brand_syscall32_callback(void);
void sngl_brand_int91_callback(void);
#endif /* __amd64 */

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SNGL_BRAND_H */
