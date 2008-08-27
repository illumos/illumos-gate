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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MD5_BYTESWAP_H
#define	_MD5_BYTESWAP_H

/*
 * definitions for inline functions for little-endian loads.
 *
 * This file has special definitions for UltraSPARC architectures,
 * which have a special address space identifier for loading 32 and 16 bit
 * integers in little-endian byte order.
 *
 * This file and common/crypto/md5/sparc/sun4[uv]/byteswap.il implement the
 * same thing and must be changed together.
 */

#include <sys/types.h>
#if defined(__sparc)
#include <v9/sys/asi.h>
#elif defined(_LITTLE_ENDIAN)
#include <sys/byteorder.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_LITTLE_ENDIAN)

/*
 * Little-endian optimization:  I don't need to do any weirdness.   On
 * some little-endian boxen, I'll have to do alignment checks, but I can do
 * that below.
 */

#if !defined(__i386) && !defined(__amd64)
/*
 * i386 and amd64 don't require aligned 4-byte loads.  The symbol
 * _MD5_CHECK_ALIGNMENT indicates below whether the MD5Transform function
 * requires alignment checking.
 */
#define	_MD5_CHECK_ALIGNMENT
#endif /* !__i386 && !__amd64 */

#define	LOAD_LITTLE_32(addr)	(*(uint32_t *)(addr))

#else	/* !_LITTLE_ENDIAN */

/*
 * sparc v9/v8plus optimization:
 *
 * on the sparc v9/v8plus, we can load data little endian.  however, since
 * the compiler doesn't have direct support for little endian, we
 * link to an assembly-language routine `load_little_32' to do
 * the magic.  note that special care must be taken to ensure the
 * address is 32-bit aligned -- in the interest of speed, we don't
 * check to make sure, since careful programming can guarantee this
 * for us.
 */
#if defined(sun4u)

/* Define alignment check because we can 4-byte load as little endian. */
#define	_MD5_CHECK_ALIGNMENT
#define	LOAD_LITTLE_32(addr)    load_little_32((uint32_t *)(addr))

#if !defined(__lint) && defined(__GNUC__)

static __inline__ uint32_t
load_little_32(uint32_t *addr)
{
	uint32_t value;

	__asm__(
	    "lduwa	[%1] %2, %0\n\t"
	    : "=r" (value)
	    : "r" (addr), "i" (ASI_PL));

	return (value);
}
#endif	/* !__lint && __GNUC__ */

#if !defined(__GNUC__)
extern	uint32_t load_little_32(uint32_t *);
#endif	/* !__GNUC__ */

/* Placate lint */
#if defined(__lint)
uint32_t
load_little_32(uint32_t *addr)
{
	return (*addr);
}
#endif	/* __lint */

#elif defined(_LITTLE_ENDIAN)
#define	LOAD_LITTLE_32(addr)	htonl(addr)

#else
/* big endian -- will work on little endian, but slowly */
/* Since we do byte operations, we don't have to check for alignment. */
#define	LOAD_LITTLE_32(addr)	\
	((addr)[0] | ((addr)[1] << 8) | ((addr)[2] << 16) | ((addr)[3] << 24))
#endif	/* sun4u */

#if defined(sun4v)

/*
 * For N1 want to minimize number of arithmetic operations. This is best
 * achieved by using the %asi register to specify ASI for the lduwa operations.
 * Also, have a separate inline template for each word, so can utilize the
 * immediate offset in lduwa, without relying on the compiler to do the right
 * thing.
 *
 * Moving to 64-bit loads might also be beneficial.
 */
#define	LOAD_LITTLE_32_0(addr)	load_little_32_0((uint32_t *)(addr))
#define	LOAD_LITTLE_32_1(addr)	load_little_32_1((uint32_t *)(addr))
#define	LOAD_LITTLE_32_2(addr)	load_little_32_2((uint32_t *)(addr))
#define	LOAD_LITTLE_32_3(addr)	load_little_32_3((uint32_t *)(addr))
#define	LOAD_LITTLE_32_4(addr)	load_little_32_4((uint32_t *)(addr))
#define	LOAD_LITTLE_32_5(addr)	load_little_32_5((uint32_t *)(addr))
#define	LOAD_LITTLE_32_6(addr)	load_little_32_6((uint32_t *)(addr))
#define	LOAD_LITTLE_32_7(addr)	load_little_32_7((uint32_t *)(addr))
#define	LOAD_LITTLE_32_8(addr)	load_little_32_8((uint32_t *)(addr))
#define	LOAD_LITTLE_32_9(addr)	load_little_32_9((uint32_t *)(addr))
#define	LOAD_LITTLE_32_a(addr)	load_little_32_a((uint32_t *)(addr))
#define	LOAD_LITTLE_32_b(addr)	load_little_32_b((uint32_t *)(addr))
#define	LOAD_LITTLE_32_c(addr)	load_little_32_c((uint32_t *)(addr))
#define	LOAD_LITTLE_32_d(addr)	load_little_32_d((uint32_t *)(addr))
#define	LOAD_LITTLE_32_e(addr)	load_little_32_e((uint32_t *)(addr))
#define	LOAD_LITTLE_32_f(addr)	load_little_32_f((uint32_t *)(addr))

#if !defined(__lint) && defined(__GNUC__)

/*
 * This actually sets the ASI register, not necessarily to ASI_PL.
 */
static __inline__ void
set_little(uint8_t asi)
{
	__asm__ __volatile__(
	    "wr	%%g0, %0, %%asi\n\t"
	    : /* Nothing */
	    : "r" (asi));
}

static __inline__ uint8_t
get_little(void)
{
	uint8_t asi;

	__asm__ __volatile__(
	    "rd	%%asi, %0\n\t"
	    : "=r" (asi));

	return (asi);
}

/*
 * We have 16 functions which differ only in the offset from which they
 * load.  Use this preprocessor template to simplify maintenance.  Its
 * argument is the offset in hex, without the 0x.
 */
#define	LL_TEMPLATE(__off)			\
static __inline__ uint32_t			\
load_little_32_##__off(uint32_t *addr)		\
{						\
	uint32_t value;				\
	__asm__(				\
		"lduwa	[%1 + %2]%%asi, %0\n\t"	\
	: "=r" (value)				\
	: "r" (addr), "i" ((0x##__off) << 2));	\
	return (value);				\
}

LL_TEMPLATE(0)
LL_TEMPLATE(1)
LL_TEMPLATE(2)
LL_TEMPLATE(3)
LL_TEMPLATE(4)
LL_TEMPLATE(5)
LL_TEMPLATE(6)
LL_TEMPLATE(7)
LL_TEMPLATE(8)
LL_TEMPLATE(9)
LL_TEMPLATE(a)
LL_TEMPLATE(b)
LL_TEMPLATE(c)
LL_TEMPLATE(d)
LL_TEMPLATE(e)
LL_TEMPLATE(f)
#undef	LL_TEMPLATE

#endif	/* !__lint && __GNUC__ */

#if !defined(__GNUC__)
/*
 * Using the %asi register to achieve little endian loads - register
 * is set using a inline template.
 *
 * Saves a few arithmetic ops as can now use an immediate offset with the
 * lduwa instructions.
 */
extern void set_little(uint32_t);
extern uint32_t get_little(void);

extern	uint32_t load_little_32_0(uint32_t *);
extern	uint32_t load_little_32_1(uint32_t *);
extern	uint32_t load_little_32_2(uint32_t *);
extern	uint32_t load_little_32_3(uint32_t *);
extern	uint32_t load_little_32_4(uint32_t *);
extern	uint32_t load_little_32_5(uint32_t *);
extern	uint32_t load_little_32_6(uint32_t *);
extern	uint32_t load_little_32_7(uint32_t *);
extern	uint32_t load_little_32_8(uint32_t *);
extern	uint32_t load_little_32_9(uint32_t *);
extern	uint32_t load_little_32_a(uint32_t *);
extern	uint32_t load_little_32_b(uint32_t *);
extern	uint32_t load_little_32_c(uint32_t *);
extern	uint32_t load_little_32_d(uint32_t *);
extern	uint32_t load_little_32_e(uint32_t *);
extern	uint32_t load_little_32_f(uint32_t *);
#endif	/* !__GNUC__ */
#endif	/* sun4v */

#endif	/* _LITTLE_ENDIAN */

#ifdef	__cplusplus
}
#endif

#endif	/* !_MD5_BYTESWAP_H */
