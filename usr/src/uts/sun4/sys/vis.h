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
 * Copyright 1997-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VIS_H
#define	_SYS_VIS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file is cpu dependent.
 */

#ifdef _KERNEL

#include <sys/asi.h>
#include <sys/machparam.h>

#ifdef _ASM

#define	BSTORE_FPREGS(FP, TEMP) \
	membar	#Sync; \
	stda	%d0, [FP]ASI_BLK_P; \
	add	FP, 64, TEMP; \
	stda	%d16, [TEMP]ASI_BLK_P; \
	add	FP, 128, TEMP; \
	stda	%d32, [TEMP]ASI_BLK_P; \
	add	FP, 192, TEMP; \
	stda	%d48, [TEMP]ASI_BLK_P; \
	membar	#Sync;

#define	BSTORE_V8_FPREGS(FP, TEMP) \
	membar	#Sync; \
	stda	%d0, [FP]ASI_BLK_P; \
	add	FP, 64, TEMP; \
	stda	%d16, [TEMP]ASI_BLK_P; \
	membar	#Sync;

#define	BSTORE_V8P_FPREGS(FP, TEMP) \
	membar	#Sync; \
	add	FP, 128, TEMP; \
	stda	%d32, [TEMP]ASI_BLK_P; \
	add	FP, 192, TEMP; \
	stda	%d48, [TEMP]ASI_BLK_P; \
	membar	#Sync;

#define	BLOAD_FPREGS(FP, TEMP) \
	membar	#Sync; \
	ldda	[FP]ASI_BLK_P, %d0; \
	add	FP, 64, TEMP; \
	ldda	[TEMP]ASI_BLK_P, %d16; \
	add	FP, 128, TEMP; \
	ldda	[TEMP]ASI_BLK_P, %d32; \
	add	FP, 192, TEMP; \
	ldda	[TEMP]ASI_BLK_P, %d48; \
	membar	#Sync;

#define	BLOAD_V8_FPREGS(FP, TEMP) \
	membar	#Sync; \
	ldda	[FP]ASI_BLK_P, %d0; \
	add	FP, 64, TEMP; \
	ldda	[TEMP]ASI_BLK_P, %d16; \
	membar	#Sync;

#define	BLOAD_V8P_FPREGS(FP, TEMP) \
	membar	#Sync; \
	add	FP, 128, TEMP; \
	ldda	[TEMP]ASI_BLK_P, %d32; \
	add	FP, 192, TEMP; \
	ldda	[TEMP]ASI_BLK_P, %d48; \
	membar	#Sync;

#endif

#define	GSR_SIZE 8	/* Graphics Status Register size 64 bits */

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VIS_H */
