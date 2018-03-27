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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_ATOMIC_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_ATOMIC_H_

static __inline u_int
atomic_load_acq_int(volatile u_int *p)
{
	u_int res;

	res = *p;
	__asm volatile("" : : : "memory");

	return (res);
}

static __inline u_long
atomic_load_acq_long(volatile u_long *p)
{
	u_long res;

	res = *p;
	__asm volatile("" : : : "memory");

	return (res);
}

static __inline void
atomic_store_rel_int(volatile u_int *p, u_int v)
{
	__asm volatile("" : : : "memory");
	*p = v;
}

static __inline void
atomic_store_rel_long(volatile u_long *p, u_long v)
{
	__asm volatile("" : : : "memory");
	*p = v;
}

/*
 * Atomic compare and set.
 *
 * if (*dst == expect) *dst = src (all 32 bit words)
 *
 * Returns 0 on failure, non-zero on success
 */
static __inline int
atomic_cmpset_int(volatile u_int *dst, u_int expect, u_int src)
{
	u_char res;

	__asm __volatile(
	"	lock ;			"
	"	cmpxchgl %3,%1 ;	"
	"       sete	%0 ;		"
	"# atomic_cmpset_int"
	: "=q" (res),			/* 0 */
	  "+m" (*dst),			/* 1 */
	  "+a" (expect)			/* 2 */
	: "r" (src)			/* 3 */
	: "memory", "cc");
	return (res);
}

static __inline int
atomic_cmpset_long(volatile u_long *dst, u_long expect, u_long src)
{
	u_char res;

	__asm __volatile(
	"	lock ;			"
	"	cmpxchgq %3,%1 ;	"
	"       sete	%0 ;		"
	"# atomic_cmpset_long"
	: "=q" (res),			/* 0 */
	  "+m" (*dst),			/* 1 */
	  "+a" (expect)			/* 2 */
	: "r" (src)			/* 3 */
	: "memory", "cc");
	return (res);
}

/*
 * Atomically add the value of v to the integer pointed to by p and return
 * the previous value of *p.
 */
static __inline u_int
atomic_fetchadd_int(volatile u_int *p, u_int v)
{

	__asm __volatile(
	"	lock ;			"
	"	xaddl	%0, %1 ;	"
	"# atomic_fetchadd_int"
	: "+r" (v),			/* 0 (result) */
	  "=m" (*p)			/* 1 */
	: "m" (*p)			/* 2 */
	: "cc");
	return (v);
}

static __inline void
atomic_set_int(volatile u_int *p, u_int v)
{
	__asm volatile(
	"lock ; " "orl %1,%0"
	: "=m" (*p)
	: "ir" (v), "m" (*p)
	: "cc");
}

static __inline void
atomic_clear_int(volatile u_int *p, u_int v)
{
	__asm volatile(
	"lock ; " "andl %1,%0"
	: "=m" (*p)
	: "ir" (~v), "m" (*p)
	: "cc");
}

static __inline void
atomic_subtract_int(volatile u_int *p, u_int v)
{
	__asm volatile(
	"lock ; " "subl %1,%0"
	: "=m" (*p)
	: "ir" (v), "m" (*p)
	: "cc");
}

static __inline void
atomic_set_long(volatile u_long *p, u_long v)
{
	__asm volatile(
	"lock ; " "orq %1,%0"
	: "+m" (*p)
	: "ir" (v)
	: "cc");
}

static __inline void
atomic_clear_long(volatile u_long *p, u_long v)
{
	__asm volatile("lock ; " "andq %1,%0"
	: "+m" (*p)
	: "ir" (~v)
	: "cc");
}

static __inline u_int
atomic_swap_int(volatile u_int *p, u_int v)
{

	__asm __volatile(
	"	xchgl	%1,%0 ;		"
	"# atomic_swap_int"
	: "+r" (v),			/* 0 */
	  "+m" (*p));			/* 1 */
	return (v);
}

static __inline u_long
atomic_swap_long(volatile u_long *p, u_long v)
{

	__asm __volatile(
	"	xchgq	%1,%0 ;		"
	"# atomic_swap_long"
	: "+r" (v),			/* 0 */
	  "+m" (*p));			/* 1 */
	return (v);
}

#define	atomic_readandclear_int(p)	atomic_swap_int(p, 0)
#define	atomic_readandclear_long(p)	atomic_swap_long(p, 0)

/* Operations on 32-bit double words. */
#define	atomic_load_acq_32	atomic_load_acq_int
#define	atomic_store_rel_32	atomic_store_rel_int
#define	atomic_cmpset_32	atomic_cmpset_int

/* Operations on 64-bit quad words. */
#define	atomic_cmpset_64	atomic_cmpset_long
#define	atomic_readandclear_64	atomic_readandclear_long

/* Operations on pointers. */
#define	atomic_cmpset_ptr	atomic_cmpset_long

#define      mb()    __asm __volatile("mfence;" : : : "memory")

#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_ATOMIC_H_ */
