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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_CPU_ID_H
#define	_CPU_ID_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	GenuineIntel	0x1
#define	AuthenticAMD	0x2

#define	Genu	0x756e6547
#define	ineI	0x49656e69
#define	ntel	0x6c65746e

#define	Auth	0x68747541
#define	enti	0x69746e65
#define	cAMD	0x444d4163

#ifndef	_ASM

extern int max_std_cpuid_level;
extern unsigned int cpu_vendor;

extern int is486(void);
extern int enable_cpuid(void);
extern int largepage_supported(void);
extern int enable_large_pages(void);
extern int global_bit(void);
extern int enable_global_pages(void);
extern int pae_supported(void);

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _CPU_ID_H */
