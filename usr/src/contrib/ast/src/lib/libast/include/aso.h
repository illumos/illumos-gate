/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped

#ifndef _ASO_H
#define _ASO_H	1

#define ASO_VERSION	20111111L

#include <ast_common.h>

/*
 * ast atomic scalar operations interface definitions
 */

/* asometh() types (ordered mutually exclusive flags) */
#define ASO_NEXT	(-1)
#define ASO_SIGNAL	1
#define ASO_THREAD	2
#define ASO_PROCESS	4
#define ASO_INTRINSIC	8

/* asolock() operations */
#define ASO_UNLOCK	0	/* unlock if key matches  		*/
#define ASO_TRYLOCK	1	/* matched key means successful attempt	*/
#define ASO_LOCK	2	/* matched key first, then spin-lock	*/
#define ASO_SPINLOCK	3	/* no matching of key before locking	*/

/* Asoerror_f types */
#define ASO_EMETHOD	0	/* method specific error		*/
#define ASO_EHUNG	1	/* asoloop() possibly hung		*/

/* for internal use, but standardized for libs such as CDT and Vmalloc */
#define ASO_RELAX	((1<<2)-1) /* cycles between spin-loop yield */
#define ASOLOOP(k)	asoloop(++(k))

#define ASODISC(d,e)	(memset(d,0,sizeof(*(d))),(d)->version=ASO_VERSION,(d)->errorf=(e))

typedef int (*Asoerror_f)(int, const char*);
typedef void* (*Asoinit_f)(void*, const char*);
typedef ssize_t (*Asolock_f)(void*, ssize_t, void volatile*);

typedef struct Asodisc_s
{
	uint32_t	version;
	unsigned int	hung;
	Asoerror_f	errorf;
} Asodisc_t;

typedef struct Asometh_s
{
	const char*	name;
	int		type;
	Asoinit_f	initf;
	Asolock_f	lockf;
	const char*	details;
} Asometh_t;

#if (_BLD_aso || _BLD_taso) && defined(__EXPORT__)
#define extern	extern __EXPORT__
#endif
#if !(_BLD_aso || _BLD_taso) && defined(__IMPORT__)
#define extern	extern __IMPORT__
#endif

extern Asometh_t*		asometh(int, void*);

#undef	extern

#if _BLD_aso && defined(__EXPORT__)
#define extern	extern __EXPORT__
#endif
#if !_BLD_aso && defined(__IMPORT__)
#define extern	extern __IMPORT__
#endif

extern Asometh_t*		_asometh(int, void*);
extern int			asoinit(const char*, Asometh_t*, Asodisc_t*);
extern int			asolock(unsigned int volatile*, unsigned int, int);
extern int			asoloop(uintmax_t);
extern int			asorelax(long);

extern uint8_t			asocas8(uint8_t volatile*, int, int);
extern uint8_t			asoget8(uint8_t volatile*);
extern uint8_t			asoinc8(uint8_t volatile*);
extern uint8_t			asodec8(uint8_t volatile*);

#define asocaschar(p,o,n)	asocas8(p,o,n)
#define asogetchar(p)		asoget8(p)
#define asoincchar(p)		asoinc8(p)
#define asodecchar(p)		asodec8(p)

extern uint16_t			asocas16(uint16_t volatile*, uint16_t, uint16_t);
extern uint16_t			asoget16(uint16_t volatile*);
extern uint16_t			asoinc16(uint16_t volatile*);
extern uint16_t			asodec16(uint16_t volatile*);

#define asocasshort(p,o,n)	asocas16(p,o,n)
#define asogetshort(p)		asoget16(p)
#define asoincshort(p)		asoinc16(p)
#define asodecshort(p)		asodec16(p)

extern uint32_t			asocas32(uint32_t volatile*, uint32_t, uint32_t);
extern uint32_t			asoget32(uint32_t volatile*);
extern uint32_t			asoinc32(uint32_t volatile*);
extern uint32_t			asodec32(uint32_t volatile*);

#if _ast_sizeof_int == 4
#define asocasint(p,o,n)	asocas32((uint32_t volatile*)p,o,n)
#define asogetint(p)		asoget32((uint32_t volatile*)p)
#define asoincint(p)		asoinc32((uint32_t volatile*)p)
#define asodecint(p)		asodec32((uint32_t volatile*)p)
#endif

#if _ast_sizeof_long == 4
#define asocaslong(p,o,n)	asocas32((uint32_t volatile*)p,o,n)
#define asogetlong(p)		asoget32((uint32_t volatile*)p)
#define asoinclong(p)		asoinc32((uint32_t volatile*)p)
#define asodeclong(p)		asodec32((uint32_t volatile*)p)
#endif

#if _ast_sizeof_size_t == 4
#define asocassize(p,o,n)	asocas32((uint32_t volatile*)p,o,n)
#define asogetsize(p)		asoget32((uint32_t volatile*)p)
#define asoincsize(p)		asoinc32((uint32_t volatile*)p)
#define asodecsize(p)		asodec32((uint32_t volatile*)p)
#endif

#ifdef _ast_int8_t

extern uint64_t			asocas64(uint64_t volatile*, uint64_t, uint64_t);
extern uint64_t			asoget64(uint64_t volatile*);
extern uint64_t			asoinc64(uint64_t volatile*);
extern uint64_t			asodec64(uint64_t volatile*);

#if _ast_sizeof_int == 8
#define asocasint(p,o,n)	asocas64((uint64_t volatile*)p,o,n)
#define asogetint(p)		asoget64((uint64_t volatile*)p)
#define asoincint(p)		asoinc64((uint64_t volatile*)p)
#define asodecint(p)		asodec64((uint64_t volatile*)p)
#endif

#if _ast_sizeof_long == 8
#define asocaslong(p,o,n)	asocas64((uint64_t volatile*)p,o,n)
#define asogetlong(p)		asoget64((uint64_t volatile*)p)
#define asoinclong(p)		asoinc64((uint64_t volatile*)p)
#define asodeclong(p)		asodec64((uint64_t volatile*)p)
#endif

#if _ast_sizeof_size_t == 8
#define asocassize(p,o,n)	asocas64((uint64_t volatile*)p,o,n)
#define asogetsize(p)		asoget64((uint64_t volatile*)p)
#define asoincsize(p)		asoinc64((uint64_t volatile*)p)
#define asodecsize(p)		asodec64((uint64_t volatile*)p)
#endif

#endif

extern void*			asocasptr(void volatile*, void*, void*);
extern void*			asogetptr(void volatile*);

#undef	extern

#endif
