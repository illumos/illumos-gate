/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Pluribus Networks Inc.
 */

#ifndef _FREEBSD_X86__TYPES_H_
#define	_FREEBSD_X86__TYPES_H_

/*
 * Basic types upon which most other types are built.
 */
typedef signed char		__int8_t;
typedef unsigned char		__uint8_t;
typedef short			__int16_t;
typedef unsigned short		__uint16_t;
typedef int			__int32_t;
typedef unsigned int		__uint32_t;
#ifdef	_LP64
typedef long			__int64_t;
typedef unsigned long		__uint64_t;
#else
typedef long long		__int64_t;
typedef unsigned long long	__uint64_t;
#endif

/* 
 * Standard type definitions.
 */
#ifdef	_LP64
typedef __int64_t	__register_t;
typedef __uint64_t	__vm_offset_t;
typedef __uint64_t	__vm_paddr_t;
typedef __int64_t	__vm_ooffset_t;
#else
typedef __int32_t	__register_t;
typedef __uint32_t	__vm_paddr_t;
#endif

#endif	/* _FREEBSD_X86__TYPES_H_ */
