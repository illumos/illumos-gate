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
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

#ifndef _UNIX_H
#define	_UNIX_H

#ifdef __cplusplus
extern "C" {
#endif

#define	FICL_WANT_PLATFORM (1)

#define	FICL_PLATFORM_OS		"Illumos"
#ifdef __sparc
#define	FICL_PLATFORM_ARCHITECTURE	"sparc"
#else
#define	FICL_PLATFORM_ARCHITECTURE	"i386"
#endif

#define	FICL_PLATFORM_BASIC_TYPES	(1)
#if defined(_LP64)
#define	FICL_PLATFORM_ALIGNMENT		(8)
#else
#define	FICL_PLATFORM_ALIGNMENT		(4)
#endif
#define	FICL_PLATFORM_INLINE		inline

#define	FICL_PLATFORM_HAS_FTRUNCATE	(1)
#if defined(_LP64)
#define	FICL_PLATFORM_HAS_2INTEGER	(0)
#else
#define	FICL_PLATFORM_HAS_2INTEGER	(1)
#endif

typedef int8_t ficlInteger8;
typedef uint8_t ficlUnsigned8;
typedef int16_t ficlInteger16;
typedef uint16_t ficlUnsigned16;
typedef int32_t ficlInteger32;
typedef uint32_t ficlUnsigned32;
typedef int64_t ficlInteger64;
typedef uint64_t ficlUnsigned64;

#if defined(_LP64)
typedef ficlInteger64 ficlInteger;
typedef ficlUnsigned64 ficlUnsigned;

typedef double ficlFloat;
#else /* default */
typedef ficlInteger32 ficlInteger;
typedef ficlUnsigned32 ficlUnsigned;

typedef float ficlFloat;
#endif

#if defined(FICL_PLATFORM_HAS_2INTEGER) && FICL_PLATFORM_HAS_2INTEGER
typedef ficlInteger64 ficl2Integer;
typedef ficlUnsigned64 ficl2Unsigned;
#endif

#ifdef __cplusplus
}
#endif

#endif /* _UNIX_H */
