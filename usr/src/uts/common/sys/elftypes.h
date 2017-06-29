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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ELFTYPES_H
#define	_SYS_ELFTYPES_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_LP64) || defined(_I32LPx)
typedef unsigned int		Elf32_Addr;
typedef unsigned short		Elf32_Half;
typedef unsigned int		Elf32_Off;
typedef int			Elf32_Sword;
typedef unsigned int		Elf32_Word;
#else
typedef unsigned long		Elf32_Addr;
typedef unsigned short		Elf32_Half;
typedef unsigned long		Elf32_Off;
typedef long			Elf32_Sword;
typedef unsigned long		Elf32_Word;
#endif

#if defined(_LP64)
typedef unsigned long		Elf64_Addr;
typedef unsigned short		Elf64_Half;
typedef unsigned long		Elf64_Off;
typedef int			Elf64_Sword;
typedef long			Elf64_Sxword;
typedef	unsigned int		Elf64_Word;
typedef	unsigned long		Elf64_Xword;
typedef unsigned long		Elf64_Lword;
typedef unsigned long		Elf32_Lword;
#elif defined(_LONGLONG_TYPE)
typedef unsigned long long	Elf64_Addr;
typedef unsigned short		Elf64_Half;
typedef unsigned long long	Elf64_Off;
typedef int			Elf64_Sword;
typedef long long		Elf64_Sxword;
typedef	unsigned int		Elf64_Word;
typedef	unsigned long long	Elf64_Xword;
typedef	unsigned long long	Elf64_Lword;
typedef unsigned long long	Elf32_Lword;
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ELFTYPES_H */
