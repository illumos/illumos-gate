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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1990 Mentat Inc. */

#ifndef _INET_LED_H
#define	_INET_LED_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING: This file contains implementation-specific constants, typedefs
 *	    and macros which may change from release to release.
 *
 * WARNING: This file has nothing to do with things that blink.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * x86 can handle unaligned access. However, the checksum routine
 * assumes that the source is 16 bit aligned so we always make sure
 * that packet headers are 16 bit aligned.
 */
#define	OK_16PTR(p)	(!((uintptr_t)(p) & 0x1))
#if defined(__x86)
#define	OK_32PTR(p)	OK_16PTR(p)
#else
#define	OK_32PTR(p)	(!((uintptr_t)(p) & 0x3))
#endif

#ifdef _KERNEL

typedef	char		*IDP;
typedef	struct msgb	*MBLKP;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_LED_H */
