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

#ifndef _SYS_PTE_H
#define	_SYS_PTE_H

#ifndef _ASM
#include <sys/types.h>
#endif /* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
/*
 * The tte struct is a 64 bit data type.  Since we currently plan to
 * use a V8 compiler all manipulations in C will be done using the bit fields
 * or as 2 integers.  In assembly code we will deal with it as a double (using
 * ldx and stx).  The structure is defined to force a double alignment.
 */
typedef union {
	struct tte {
		unsigned int	v:1;		/* <63> valid */
		unsigned int	nfo:1;		/* <62> non-fault only */
		unsigned int	hmenum:3;	/* <61:59> sw hmenum */
		unsigned int	no_sync:1;	/* <58> sw - ghost unload */
		unsigned int	lock:1;		/* <57> sw - locked */
		unsigned int	susp:1;		/* <56> sw - suspend? */
		unsigned int	pahi:24;	/* <55:32> pa */
		/* ------------------- */
		unsigned int	palo:19;	/* <31:13> pa */
		unsigned int	ie:1;		/* <12> 1=invert endianness */
		unsigned int	e:1;		/* <11> side effect */
		unsigned int	cp:1;		/* <10> physically cache */
		unsigned int	cv:1;		/* <9> virtually cache */
		unsigned int	p:1;		/* <8> privilege required */
		unsigned int	x:1;		/* <7> execute perm */
		unsigned int	w:1;		/* <6> write perm */
		unsigned int	ref:1;		/* <5> sw - ref */
		unsigned int	wr_perm:1;	/* <4> sw - write perm */
		unsigned int	xsoft:1;	/* <3> sw - soft execute */
		unsigned int	sz:3;		/* <2:0> pagesize */
	} tte_bit;
	struct {
		int32_t		inthi;
		uint32_t	intlo;
	} tte_int;
	uint64_t		ll;
} tte_t;

#define	tte_val 	tte_bit.v		/* use < 0 check in asm */
#define	tte_size	tte_bit.sz
#define	tte_nfo		tte_bit.nfo
#define	tte_ie		tte_bit.ie		/* XXX? */
#define	tte_hmenum	tte_bit.hmenum
#define	tte_pahi	tte_bit.pahi
#define	tte_palo	tte_bit.palo
#define	tte_ref		tte_bit.ref
#define	tte_wr_perm	tte_bit.wr_perm
#define	tte_no_sync	tte_bit.no_sync
#define	tte_suspend	tte_bit.susp
#define	tte_exec_perm	tte_bit.x
#define	tte_soft_exec	tte_bit.xsoft
#define	tte_lock	tte_bit.lock
#define	tte_cp		tte_bit.cp
#define	tte_cv		tte_bit.cv
#define	tte_se		tte_bit.e
#define	tte_priv	tte_bit.p
#define	tte_hwwr	tte_bit.w

#define	tte_inthi	tte_int.inthi
#define	tte_intlo	tte_int.intlo

#endif /* !_ASM */

/* Defines for sz field in tte */
#define	TTE8K			0x0
#define	TTE64K			0x1
#define	TTE512K			0x2
#define	TTE4M			0x3
#define	TTE32M			0x4
#define	TTE256M			0x5
#define	TTE2G			0x6
#define	TTE16G			0x7

#define	TTE_SZ_SHFT		0
#define	TTE_SZ_BITS		0x7

#define	TTE_CSZ(ttep)	((ttep)->tte_size)

#define	TTE_BSZS_SHIFT(sz)	((sz) * 3)
#define	TTEBYTES(sz)	(MMU_PAGESIZE << TTE_BSZS_SHIFT(sz))
#define	TTEPAGES(sz)	(1 << TTE_BSZS_SHIFT(sz))
#define	TTE_PAGE_SHIFT(sz)	(MMU_PAGESHIFT + TTE_BSZS_SHIFT(sz))
#define	TTE_PAGE_OFFSET(sz)	(TTEBYTES(sz) - 1)
#define	TTE_PAGEMASK(sz)	(~TTE_PAGE_OFFSET(sz))
#define	TTE_PFNMASK(sz)	(~(TTE_PAGE_OFFSET(sz) >> MMU_PAGESHIFT))

#define	TTE_PA_LSHIFT	8	/* used to do sllx on tte to get pa */

#ifndef _ASM

#define	TTE_PASHIFT	19	/* used to manage pahi and palo */
#define	TTE_PALOMASK	((1 << TTE_PASHIFT) -1)
/* PFN is defined as bits [40-13] of the physical address */
#define	TTE_TO_TTEPFN(ttep)						\
	((((ttep)->tte_pahi << TTE_PASHIFT) | (ttep)->tte_palo) &	\
	TTE_PFNMASK(TTE_CSZ(ttep)))
/*
 * This define adds the vaddr page offset to obtain a correct pfn
 */
#define	TTE_TO_PFN(vaddr, ttep)						\
	(sfmmu_ttetopfn(ttep, vaddr))

#define	PFN_TO_TTE(entry, pfn) {			\
	entry.tte_pahi = pfn >> TTE_PASHIFT;	\
	entry.tte_palo = pfn & TTE_PALOMASK;	\
	}

#endif /* !_ASM */

/*
 * The tte defines are separated into integers because the compiler doesn't
 * support 64bit defines.
 */
/* Defines for tte using inthi */
#define	TTE_VALID_INT			0x80000000
#define	TTE_NFO_INT			0x40000000
#define	TTE_NOSYNC_INT			0x04000000
#define	TTE_SUSPEND			0x01000000
#define	TTE_SUSPEND_SHIFT		32

/* Defines for tte using intlo */
#define	TTE_IE_INT			0x00001000
#define	TTE_SIDEFF_INT			0x00000800
#define	TTE_CP_INT			0x00000400
#define	TTE_CV_INT			0x00000200
#define	TTE_PRIV_INT			0x00000100
#define	TTE_EXECPRM_INT			0x00000080
#define	TTE_HWWR_INT			0x00000040
#define	TTE_REF_INT			0x00000020
#define	TTE_WRPRM_INT			0x00000010
#define	TTE_SOFTEXEC_INT		0x00000008

#define	TTE_PROT_INT			(TTE_WRPRM_INT | TTE_PRIV_INT)

#ifndef ASM

/* Defines to help build ttes using inthi */
#define	TTE_SZ_INTLO(sz)		((sz) & TTE_SZ_BITS)
#define	TTE_HMENUM_INT(hmenum)		((hmenum) << 27)

/* PFN is defined as bits [40-13] of the physical address */
#define	TTE_PFN_INTHI(pfn)		((pfn) >> TTE_PASHIFT)
#define	TTE_VALID_CHECK(attr)	\
	(((attr) & PROT_ALL) ? TTE_VALID_INT : 0)
#define	TTE_NFO_CHECK(attr)	\
	(((attr) & HAT_NOFAULT) ? TTE_NFO_INT : 0)

/* Defines to help build ttes using intlo */
#define	TTE_PFN_INTLO(pfn)		(((pfn) & TTE_PALOMASK) << 13)
#define	TTE_IE_CHECK(attr)	\
	(((attr) & HAT_STRUCTURE_LE) ? TTE_IE_INT : 0)
#define	TTE_WRPRM_CHECK(attr)	 \
	(((attr) & PROT_WRITE) ? TTE_WRPRM_INT : 0)
#define	TTE_EXECPRM_CHECK(attr)	 \
	(((attr) & PROT_EXEC) ? TTE_EXECPRM_INT : 0)
#define	TTE_NOSYNC_CHECK(attr)	 \
	(((attr) & HAT_NOSYNC) ? TTE_NOSYNC_INT : 0)
#define	TTE_CP_CHECK(attr)	\
	(((attr) & SFMMU_UNCACHEPTTE) ? 0: TTE_CP_INT)
#define	TTE_CV_CHECK(attr)	\
	(((attr) & SFMMU_UNCACHEVTTE) ? 0: TTE_CV_INT)
#define	TTE_SE_CHECK(attr)	\
	(((attr) & SFMMU_SIDEFFECT) ? TTE_SIDEFF_INT : 0)
#define	TTE_PRIV_CHECK(attr)	\
	(((attr) & PROT_USER) ? 0 : TTE_PRIV_INT)

#define	MAKE_TTEATTR_INTHI(attr)				\
	(TTE_VALID_CHECK(attr) | TTE_NFO_CHECK(attr))

#define	MAKE_TTE_INTHI(pfn, attr, sz, hmenum)			\
	(MAKE_TTEATTR_INTHI(attr) | TTE_HMENUM_INT(hmenum) |	\
	TTE_NOSYNC_CHECK(attr) | TTE_PFN_INTHI(pfn))

#define	MAKE_TTEATTR_INTLO(attr)					\
	(TTE_WRPRM_CHECK(attr) | TTE_CP_CHECK(attr) | TTE_CV_CHECK(attr) | \
	TTE_SE_CHECK(attr) | TTE_PRIV_CHECK(attr) | TTE_EXECPRM_CHECK(attr) | \
	TTE_IE_CHECK(attr))

#define	MAKE_TTE_INTLO(pfn, attr, sz, hmenum)				\
	(TTE_PFN_INTLO(pfn) | TTE_REF_INT | MAKE_TTEATTR_INTLO(attr) | \
	TTE_SZ_INTLO(sz))

#define	TTEINTHI_ATTR	(TTE_VALID_INT | TTE_NFO_INT | TTE_NOSYNC_INT)

#define	TTEINTLO_ATTR							\
	(TTE_IE_INT | TTE_WRPRM_INT | TTE_CP_INT | TTE_CV_INT |		\
	TTE_SIDEFF_INT | TTE_PRIV_INT | TTE_EXECPRM_INT)

#define	MAKE_TTE_MASK(ttep)				\
	{						\
		(ttep)->tte_bit.v = 1;			\
		(ttep)->tte_bit.nfo = 1;		\
		(ttep)->tte_bit.pahi = 0xffffff;	\
		(ttep)->tte_bit.palo = 0x7ffff;		\
		(ttep)->tte_bit.ie = 1;			\
		(ttep)->tte_bit.e = 1;			\
		(ttep)->tte_bit.cp = 1;			\
		(ttep)->tte_bit.cv = 1;			\
		(ttep)->tte_bit.p = 1;			\
		(ttep)->tte_bit.x = 1;			\
		(ttep)->tte_bit.w = 1;			\
		(ttep)->tte_bit.sz = 7;			\
	}

/*
 * Defines to check/set TTE bits.
 */
#define	TTE_IS_VALID(ttep)	((ttep)->tte_inthi < 0)
#define	TTE_SET_INVALID(ttep)	((ttep)->tte_val = 0)
#define	TTE_IS_8K(ttep)		(TTE_CSZ(ttep) == TTE8K)
#define	TTE_IS_WRITABLE(ttep)	((ttep)->tte_wr_perm)
#define	TTE_IS_EXECUTABLE(ttep)	((ttep)->tte_exec_perm)
#define	TTE_IS_SOFTEXEC(ttep)	((ttep)->tte_soft_exec)
#define	TTE_IS_PRIVILEGED(ttep)	((ttep)->tte_priv)
#define	TTE_IS_NOSYNC(ttep)	((ttep)->tte_no_sync)
#define	TTE_IS_LOCKED(ttep)	((ttep)->tte_lock)
#define	TTE_IS_SIDEFFECT(ttep)	((ttep)->tte_se)
#define	TTE_IS_NFO(ttep)	((ttep)->tte_nfo)

#define	TTE_IS_REF(ttep)	((ttep)->tte_ref)
#define	TTE_IS_MOD(ttep)	((ttep)->tte_hwwr)
#define	TTE_IS_IE(ttep)		((ttep)->tte_ie)
#define	TTE_SET_SUSPEND(ttep)	((ttep)->tte_suspend = 1)
#define	TTE_CLR_SUSPEND(ttep)	((ttep)->tte_suspend = 0)
#define	TTE_IS_SUSPEND(ttep)	((ttep)->tte_suspend)
#define	TTE_SET_REF(ttep)	((ttep)->tte_ref = 1)
#define	TTE_CLR_REF(ttep)	((ttep)->tte_ref = 0)
#define	TTE_SET_LOCKED(ttep)	((ttep)->tte_lock = 1)
#define	TTE_CLR_LOCKED(ttep)	((ttep)->tte_lock = 0)
#define	TTE_SET_MOD(ttep)	((ttep)->tte_hwwr = 1)
#define	TTE_CLR_MOD(ttep)	((ttep)->tte_hwwr = 0)
#define	TTE_SET_RM(ttep)						\
	(((ttep)->tte_intlo) =						\
	(ttep)->tte_intlo | TTE_HWWR_INT | TTE_REF_INT)
#define	TTE_CLR_RM(ttep)						\
	(((ttep)->tte_intlo) =						\
	(ttep)->tte_intlo & ~(TTE_HWWR_INT | TTE_REF_INT))

#define	TTE_SET_WRT(ttep)	((ttep)->tte_wr_perm = 1)
#define	TTE_CLR_WRT(ttep)	((ttep)->tte_wr_perm = 0)
#define	TTE_SET_EXEC(ttep)	((ttep)->tte_exec_perm = 1)
#define	TTE_CLR_EXEC(ttep)	((ttep)->tte_exec_perm = 0)
#define	TTE_SET_SOFTEXEC(ttep)	((ttep)->tte_soft_exec = 1)
#define	TTE_CLR_SOFTEXEC(ttep)	((ttep)->tte_soft_exec = 0)
#define	TTE_SET_PRIV(ttep)	((ttep)->tte_priv = 1)
#define	TTE_CLR_PRIV(ttep)	((ttep)->tte_priv = 0)

#define	TTE_IS_VCACHEABLE(ttep)		((ttep)->tte_cv)
#define	TTE_SET_VCACHEABLE(ttep)	((ttep)->tte_cv = 1)
#define	TTE_CLR_VCACHEABLE(ttep)	((ttep)->tte_cv = 0)
#define	TTE_IS_PCACHEABLE(ttep)		((ttep)->tte_cp)
#define	TTE_SET_PCACHEABLE(ttep)	((ttep)->tte_cp = 1)
#define	TTE_CLR_PCACHEABLE(ttep)	((ttep)->tte_cp = 0)


#define	KPM_TTE_VCACHED(tte64, pfn, tte_sz)				\
	tte64 = ((uint64_t)TTE_VALID_INT << 32) |			\
	    ((uint64_t)((tte_sz) << TTE_SZ_SHFT)) |			\
	    (((pfn) >> TTE_BSZS_SHIFT(tte_sz)) <<			\
	    (TTE_BSZS_SHIFT(tte_sz) + MMU_PAGESHIFT)) |			\
	    (TTE_CP_INT | TTE_CV_INT | TTE_PRIV_INT | TTE_HWWR_INT)

#define	KPM_TTE_VUNCACHED(tte64, pfn, tte_sz)				\
	tte64 = ((uint64_t)TTE_VALID_INT << 32) |			\
	    ((uint64_t)((tte_sz) << TTE_SZ_SHFT)) |			\
	    (((pfn) >> TTE_BSZS_SHIFT(tte_sz)) <<			\
	    (TTE_BSZS_SHIFT(tte_sz) + MMU_PAGESHIFT)) |			\
	    (TTE_CP_INT | TTE_PRIV_INT | TTE_HWWR_INT)


/*
 * This define provides a generic method to set and clear multiple tte flags.
 * A bitmask of all flags to be affected is passed in "flags" and a bitmask
 * of the new values is passed in "newflags".
 */
#define	TTE_SET_LOFLAGS(ttep, flags, newflags)				\
	((ttep)->tte_intlo = ((ttep)->tte_intlo & ~(flags)) | (newflags))

#define	TTE_GET_LOFLAGS(ttep, flags)	((ttep)->tte_intlo & flags)

#endif /* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif /* !_SYS_PTE_H */
