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
/*
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 */

#ifndef	_SYS_CPUID_DRV_H
#define	_SYS_CPUID_DRV_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * /dev names:
 *	/dev/cpu/			- containing directory
 *		self/			- describes current cpu
 *			cpuid		- cpu identification
 */

#define	CPUID_DRIVER_NAME	"cpuid"
#define	CPUID_DRIVER_SELF_NODE	"self"

#define	CPUID_DIR_NAME		"cpu"
#define	CPUID_SELF_DIR_NAME	"self"
#define	CPUID_NAME		"cpuid"
#define	CPUID_SELF_NAME		\
	CPUID_DIR_NAME "/" CPUID_SELF_DIR_NAME "/" CPUID_NAME

/*
 * This minor number corresponds to the cpu we're running on at
 * the time we invoke its interfaces.
 */
#define	CPUID_SELF_CPUID_MINOR	((minor_t)0x3fffful)

/*
 * ioctl numbers: not an exported interface
 */
#define	CPUID_IOC		(('c'<<24)|('i'<<16)|('d'<<8))

#define	CPUID_GET_HWCAP		(CPUID_IOC|0)

struct cpuid_get_hwcap {
	char *cgh_archname;
	uint_t cgh_hwcap[2];
};

#if defined(_SYSCALL32_IMPL)

#include <sys/types32.h>

struct cpuid_get_hwcap32 {
	caddr32_t cgh_archname;
	uint32_t cgh_hwcap[2];
};

#endif	/* _SYSCALL32_IMPL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_CPUID_DRV_H */
