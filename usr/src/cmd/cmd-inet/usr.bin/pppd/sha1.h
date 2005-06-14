/*
 * Copyright (c) 1998, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SHA1_H
#define	_SHA1_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>		/* for uint_* */

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(sun) && !defined(_SYS_INT_TYPES_H) && !defined(_UINT32_T)
/* Backward compatibility */
typedef uint_t uint32_t;
typedef ushort_t uint16_t;
typedef uchar_t uint8_t;
typedef unsigned long uintptr_t;
#define	_UINT32_T
#endif

#ifdef __linux__
#include <stdint.h>
#endif

/* SHA-1 context. */
typedef struct 	{
	uint32_t state[5];	/* state (ABCDE) */
	uint32_t count[2];	/* number of bits, modulo 2^64 (msb first) */
	union 	{
		uint8_t		buf8[64];	/* undigested input */
		uint32_t	buf32[16];	/* realigned input */
	} buf_un;
} SHA1_CTX;

void SHA1Init(SHA1_CTX *);
void SHA1Update(SHA1_CTX *, const uint8_t *, uint32_t);
void SHA1Final(uint8_t *, SHA1_CTX *);

#ifdef	__cplusplus
}
#endif

#endif /* _SHA1_H */
