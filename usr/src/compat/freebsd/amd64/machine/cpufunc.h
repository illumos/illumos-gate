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
 */

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_CPUFUNC_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_CPUFUNC_H_

static __inline u_long
bsfq(u_long mask)
{
	u_long	result;

	__asm __volatile("bsfq %1,%0" : "=r" (result) : "rm" (mask));
	return (result);
}

static __inline u_int
bsrl(u_int mask)
{
	u_int	result;

	__asm __volatile("bsrl %1,%0" : "=r" (result) : "rm" (mask));
	return (result);
}

static __inline u_long
bsrq(u_long mask)
{
	u_long	result;

	__asm __volatile("bsrq %1,%0" : "=r" (result) : "rm" (mask));
	return (result);
}

static __inline void
clts(void)
{
	__asm __volatile("clts");
}

static __inline void
do_cpuid(u_int ax, u_int *p)
{
	__asm __volatile("cpuid"
			 : "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
			 :  "0" (ax));
}

static __inline void
cpuid_count(u_int ax, u_int cx, u_int *p)
{
	__asm __volatile("cpuid"
			 : "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
			 :  "0" (ax), "c" (cx));
}

static __inline void
enable_intr(void)
{
	__asm __volatile("sti");
}

static __inline int
ffsl(long mask)
{
	return (mask == 0 ? mask : (int)bsfq((u_long)mask) + 1);
}

static __inline int
fls(int mask)
{
	return (mask == 0 ? mask : (int)bsrl((u_int)mask) + 1);
}

static __inline int
flsl(long mask)
{
	return (mask == 0 ? mask : (int)bsrq((u_long)mask) + 1);
}

static __inline int
flsll(long long mask)
{
	return (flsl((long)mask));
}

static __inline uint64_t
rdmsr(u_int msr)
{
	uint32_t low, high;
 
	__asm __volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
	return (low | ((uint64_t)high << 32));
}

static __inline uint64_t
rdtsc(void)
{
	uint32_t low, high;
 
	__asm __volatile("rdtsc" : "=a" (low), "=d" (high));
	return (low | ((uint64_t)high << 32));
}

static __inline void
wrmsr(u_int msr, uint64_t newval)
{
	uint32_t low, high;

	low = newval;
	high = newval >> 32;
	__asm __volatile("wrmsr" : : "a" (low), "d" (high), "c" (msr));
}

static __inline void
load_cr0(u_long data)
{
	__asm __volatile("movq %0,%%cr0" : : "r" (data));
}

static __inline u_long
rcr0(void)
{
	u_long  data;
 
	__asm __volatile("movq %%cr0,%0" : "=r" (data));
	return (data);
}

static __inline u_long
rcr3(void)
{
	u_long  data;

	__asm __volatile("movq %%cr3,%0" : "=r" (data));
	return (data);
}

static __inline void
load_cr4(u_long data)
{
	__asm __volatile("movq %0,%%cr4" : : "r" (data));
}

static __inline u_long
rcr4(void)
{
	u_long  data;
 
	__asm __volatile("movq %%cr4,%0" : "=r" (data));
	return (data);
}

#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_CPUFUNC_H_ */
