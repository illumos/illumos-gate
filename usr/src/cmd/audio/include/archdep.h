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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MULTIMEDIA_ARCHDEP_H
#define	_MULTIMEDIA_ARCHDEP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Machine-dependent and implementation-dependent definitions
 * are placed here so that source code can be portable among a wide
 * variety of machines.
 */

/*
 * The following macros are used to generate architecture-specific
 * code for handling byte-ordering correctly.
 *
 * Note that these macros *do not* work for in-place transformations.
 */

#if defined(_BIG_ENDIAN)
#define	DECODE_SHORT(from, to)	*((short *)(to)) = *((short *)(from))
#define	DECODE_LONG(from, to)	*((long *)(to)) = *((long *)(from))
#define	DECODE_FLOAT(from, to)	*((float *)(to)) = *((float *)(from))
#define	DECODE_DOUBLE(from, to)	*((double *)(to)) = *((double *)(from))
#elif defined(_LITTLE_ENDIAN)
#define	DECODE_SHORT(from, to)						\
			    ((char *)(to))[0] = ((char *)(from))[1];	\
			    ((char *)(to))[1] = ((char *)(from))[0];
#define	DECODE_LONG(from, to)						\
			    ((char *)(to))[0] = ((char *)(from))[3];	\
			    ((char *)(to))[1] = ((char *)(from))[2];	\
			    ((char *)(to))[2] = ((char *)(from))[1];	\
			    ((char *)(to))[3] = ((char *)(from))[0];

#define	DECODE_FLOAT(from, to)		DECODE_LONG((to), (from))

#define	DECODE_DOUBLE(from, to)						\
			    ((char *)(to))[0] = ((char *)(from))[7];	\
			    ((char *)(to))[1] = ((char *)(from))[6];	\
			    ((char *)(to))[2] = ((char *)(from))[5];	\
			    ((char *)(to))[3] = ((char *)(from))[4];	\
			    ((char *)(to))[4] = ((char *)(from))[3];	\
			    ((char *)(to))[5] = ((char *)(from))[2];	\
			    ((char *)(to))[6] = ((char *)(from))[1];	\
			    ((char *)(to))[7] = ((char *)(from))[0];
#else /* little-endian */
#error Unknown machine endianness
#endif

#define	ENCODE_SHORT(from, to)		DECODE_SHORT((from), (to))
#define	ENCODE_LONG(from, to)		DECODE_LONG((from), (to))
#define	ENCODE_FLOAT(from, to)		DECODE_FLOAT((from), (to))
#define	ENCODE_DOUBLE(from, to)		DECODE_DOUBLE((from), (to))

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_ARCHDEP_H */
