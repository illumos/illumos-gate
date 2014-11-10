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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#ifndef _SN1_BRAND_H
#define	_SN1_BRAND_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/brand.h>

#define	SN1_BRANDNAME		"sn1"

#define	SN1_VERSION_1		1
#define	SN1_VERSION		SN1_VERSION_1

#define	SN1_LIB_NAME		"sn1_brand.so.1"

#define	SN1_LIB32		BRAND_NATIVE_DIR "usr/lib/" SN1_LIB_NAME
#define	SN1_LIB64		BRAND_NATIVE_DIR "usr/lib/64/" SN1_LIB_NAME

#if defined(_LP64)
#define	SN1_LIB		SN1_LIB64
#else /* !_LP64 */
#define	SN1_LIB		SN1_LIB32
#endif /* !_LP64 */

#if defined(_KERNEL)

void sn1_brand_syscall_callback(void);
void sn1_brand_syscall32_callback(void);

#if !defined(sparc)
void sn1_brand_sysenter_callback(void);
#endif /* !sparc */

#if defined(__amd64)
void sn1_brand_int91_callback(void);
#endif /* __amd64 */
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SN1_BRAND_H */
