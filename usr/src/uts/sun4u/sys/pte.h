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
 * Note that USIIi uses bits [47:41] for diag, and [49:48] are reserved.
 * Note that pa[46:32] includes USIIi diag bits [46:41] and USIII reserved
 * bits [46:43].
 */
typedef union {
	struct tte {
		uint32_t	v:1;		/* 1=valid mapping */
		uint32_t	sz:2;		/* 0=8k 1=64k 2=512k 3=4m */
		uint32_t	nfo:1;		/* 1=no-fault access only */

		uint32_t	ie:1;		/* 1=invert endianness */
		uint32_t	hmenum:3;	/* sw - # of hment in hme_blk */

		uint32_t	rsv:7;		/* former rsv:1 lockcnt:6 */
		uint32_t	sz2:1;		/* sz2[48] Panther, Olympus-C */
		uint32_t	diag:1;		/* See USII Note above. */
		uint32_t	pahi:15;	/* pa[46:32] See Note above */
		uint32_t	palo:19;	/* pa[31:13] */
		uint32_t	no_sync:1;	/* sw - ghost unload */

		uint32_t	suspend:1;	/* sw bits - suspended */
		uint32_t	ref:1;		/* sw - reference */
		uint32_t	wr_perm:1;	/* sw - write permission */
		uint32_t	exec_synth:1;	/* sw bits - itlb synthesis */

		uint32_t	exec_perm:1;	/* sw - execute permission */
		uint32_t	l:1;		/* 1=lock in tlb */
		uint32_t	cp:1;		/* 1=cache in ecache, icache */
		uint32_t	cv:1;		/* 1=cache in dcache */

		uint32_t	e:1;		/* 1=side effect */
		uint32_t	p:1;		/* 1=privilege required */
		uint32_t	w:1;		/* 1=writes allowed */
		uint32_t	g:1;		/* 1=any context matches */
	} tte_bit;
	struct {
		int32_t		inthi;
		uint32_t	intlo;
	} tte_int;
	uint64_t		ll;
} tte_t;

#define	tte_val 	tte_bit.v		/* use < 0 check in asm */
#define	tte_size	tte_bit.sz
#define	tte_size2	tte_bit.sz2
#define	tte_nfo		tte_bit.nfo
#define	tte_ie		tte_bit.ie		/* XXX? */
#define	tte_hmenum	tte_bit.hmenum
#define	tte_pahi	tte_bit.pahi
#define	tte_palo	tte_bit.palo
#define	tte_no_sync	tte_bit.no_sync
#define	tte_suspend	tte_bit.suspend
#define	tte_ref		tte_bit.ref
#define	tte_wr_perm	tte_bit.wr_perm
#define	tte_exec_synth	tte_bit.exec_synth
#define	tte_exec_perm	tte_bit.exec_perm
#define	tte_lock	tte_bit.l
#define	tte_cp		tte_bit.cp
#define	tte_cv		tte_bit.cv
#define	tte_se		tte_bit.e
#define	tte_priv	tte_bit.p
#define	tte_hwwr	tte_bit.w
#define	tte_glb		tte_bit.g

#define	tte_inthi	tte_int.inthi
#define	tte_intlo	tte_int.intlo

#endif /* !_ASM */

/*
 * Defines for valid, sz, sz2 fields in tte.
 * The TTE_CSZ macro combines the sz and sz2 fields.
 */
#define	TTE8K			0x0
#define	TTE64K			0x1
#define	TTE512K			0x2
#define	TTE4M			0x3
#define	TTE32M			0x4
#define	TTE256M			0x5
#define	TTESZ_VALID		0x4

#define	TTE_SZ_SHFT_INT		29
#define	TTE_SZ_SHFT		32+29
#define	TTE_SZ_BITS		0x3

#define	TTE_SZ2_SHFT_INT	14
#define	TTE_SZ2_SHFT		32+14
#define	TTE_SZ2_BITS		0x4
#define	TTE_CSZ_BITS		0x7
#define	TTE_CSZ(ttep)	(((ttep)->tte_size2 << 2) | ((ttep)->tte_size))

/*
 * the tte lock cnt now lives in the hme blk and is 16 bits long. See
 * comments in hme_blk declaration.
 */
#define	MAX_TTE_LCKCNT		(0x10000 - 1)

#define	TTE_BSZS_SHIFT(sz)	((sz) * 3)
#define	TTEBYTES(sz)		(MMU_PAGESIZE << TTE_BSZS_SHIFT(sz))
#define	TTEPAGES(sz)		(1 << TTE_BSZS_SHIFT(sz))
#define	TTE_PAGE_SHIFT(sz)	(MMU_PAGESHIFT + TTE_BSZS_SHIFT(sz))
#define	TTE_PAGE_OFFSET(sz)	(TTEBYTES(sz) - 1)
#define	TTE_PAGEMASK(sz)	(~TTE_PAGE_OFFSET(sz))
#define	TTE_PFNMASK(sz)		(~(TTE_PAGE_OFFSET(sz) >> MMU_PAGESHIFT))

#define	TTE_PA_LSHIFT		17	/* used to do sllx on tte to get pa */

#ifndef _ASM

#define	TTE_PASHIFT		19	/* used to manage pahi and palo */
#define	TTE_PALOMASK		((1 << TTE_PASHIFT) -1)
/*
 * Spitfire PFN is defined as bits [40:13] of the physical address.
 * Cheetah PFN is defined as bits [42:13] of the physical address.
 * Olympus-C PFN is defined as bits [46:13] of the physical address.
 */
#define	TTE_TO_TTEPFN(ttep)						\
	(((((pfn_t)((ttep)->tte_pahi)) << TTE_PASHIFT) |		\
	(ttep)->tte_palo) & TTE_PFNMASK(TTE_CSZ(ttep)))
/*
 * This define adds the vaddr page offset to obtain a correct pfn
 */
#define	TTE_TO_PFN(vaddr, ttep)						\
	(sfmmu_ttetopfn(ttep, vaddr))

#define	PFN_TO_TTE(entry, pfn) {		\
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
#define	TTE_NFO_INT			0x10000000
#define	TTE_NFO_SHIFT			0x3	/* makes for an easy check */
#define	TTE_IE_INT			0x08000000

/* Defines for tte using intlo */
#define	TTE_SUSPEND_SHIFT		0
#define	TTE_NOSYNC_INT			0x00001000
#define	TTE_SUSPEND			0x00000800
#define	TTE_REF_INT			0x00000400
#define	TTE_WRPRM_INT			0x00000200
#define	TTE_E_SYNTH_INT			0x00000100
#define	TTE_EXECPRM_INT			0x00000080
#define	TTE_LCK_INT			0x00000040
#define	TTE_CP_INT			0x00000020
#define	TTE_CV_INT			0x00000010
#define	TTE_SIDEFF_INT			0x00000008
#define	TTE_PRIV_INT			0x00000004
#define	TTE_HWWR_INT			0x00000002
#define	TTE_GLB_INT			0x00000001

#define	TTE_PROT_INT			(TTE_WRPRM_INT | TTE_PRIV_INT)

/*
 * Define to clear the high-order 6 bits of the 47-bit PA in a tte.  The
 * Spitfire tte has PFN in [40:13] and uses [46:41] as part of Diag bits.
 */
#define	TTE_SPITFIRE_PFNHI_CLEAR	0x3f
#define	TTE_SPITFIRE_PFNHI_SHIFT	41

#ifndef ASM

/* Defines to help build ttes using inthi */
#define	TTE_SZ_INT(sz)	\
	((sz & TTE_SZ_BITS) << TTE_SZ_SHFT_INT) | \
	((sz & TTE_SZ2_BITS) << TTE_SZ2_SHFT_INT)
#define	TTE_HMENUM_INT(hmenum)		((hmenum) << 24)
/* XXX PFN is defined as bits [40-13] of the physical address */
#define	TTE_PFN_INTHI(pfn)		((pfn) >> TTE_PASHIFT)
#define	TTE_VALID_CHECK(attr)	\
	(((attr) & PROT_ALL) ? TTE_VALID_INT : 0)
#define	TTE_IE_CHECK(attr)	\
	(((attr) & HAT_STRUCTURE_LE) ? TTE_IE_INT : 0)
#define	TTE_NFO_CHECK(attr)	\
	(((attr) & HAT_NOFAULT) ? TTE_NFO_INT : 0)

/* Defines to help build ttes using intlo */
#define	TTE_PFN_INTLO(pfn)		(((pfn) & TTE_PALOMASK) << 13)
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
	(TTE_VALID_CHECK(attr) | TTE_NFO_CHECK(attr) | TTE_IE_CHECK(attr))

#define	MAKE_TTE_INTHI(pfn, attr, sz, hmenum)			\
	(MAKE_TTEATTR_INTHI(attr) | TTE_SZ_INT(sz) |		\
	TTE_HMENUM_INT(hmenum) | TTE_PFN_INTHI(pfn))

#define	MAKE_TTEATTR_INTLO(attr)					\
	(TTE_WRPRM_CHECK(attr) | TTE_NOSYNC_CHECK(attr) |		\
	TTE_CP_CHECK(attr) | TTE_CV_CHECK(attr) | TTE_SE_CHECK(attr) |	\
	TTE_PRIV_CHECK(attr) | TTE_EXECPRM_CHECK(attr))

#define	MAKE_TTE_INTLO(pfn, attr, sz, hmenum)				\
	(TTE_PFN_INTLO(pfn) | TTE_REF_INT | MAKE_TTEATTR_INTLO(attr))

#define	TTEINTHI_ATTR	(TTE_VALID_INT | TTE_IE_INT | TTE_NFO_INT)

#define	TTEINTLO_ATTR							\
	(TTE_WRPRM_INT | TTE_NOSYNC_INT | TTE_CP_INT | TTE_CV_INT |	\
	TTE_SIDEFF_INT | TTE_PRIV_INT | TTE_EXECPRM_INT)

#define	MAKE_TTE_MASK(ttep)			\
	{					\
		(ttep)->tte_bit.v = 1;		\
		(ttep)->tte_bit.sz = 3;		\
		(ttep)->tte_bit.nfo = 1;	\
		(ttep)->tte_bit.ie = 1;		\
		(ttep)->tte_bit.sz2 = 1;	\
		(ttep)->tte_bit.pahi = 0x7fff;	\
		(ttep)->tte_bit.palo = 0x7ffff;	\
		(ttep)->tte_bit.exec_perm = 1;	\
		(ttep)->tte_bit.l = 1;		\
		(ttep)->tte_bit.cp = 1;		\
		(ttep)->tte_bit.cv = 1;		\
		(ttep)->tte_bit.e = 1;		\
		(ttep)->tte_bit.p = 1;		\
		(ttep)->tte_bit.w = 1;		\
		(ttep)->tte_bit.g = 1;		\
	}

/*
 * Defines to check/set TTE bits.
 */
#define	TTE_IS_VALID(ttep)	((ttep)->tte_inthi < 0)
#define	TTE_SET_INVALID(ttep)	((ttep)->tte_val = 0)
#define	TTE_IS_8K(ttep)		(TTE_CSZ(ttep) == TTE8K)
#define	TTE_IS_WRITABLE(ttep)	((ttep)->tte_wr_perm)
#define	TTE_IS_EXECUTABLE(ttep)	((ttep)->tte_exec_perm)
#define	TTE_IS_PRIVILEGED(ttep)	((ttep)->tte_priv)
#define	TTE_IS_NOSYNC(ttep)	((ttep)->tte_no_sync)
#define	TTE_IS_LOCKED(ttep)	((ttep)->tte_lock)
#define	TTE_IS_GLOBAL(ttep)	((ttep)->tte_glb)
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
	(((ttep)->tte_intlo) = (ttep)->tte_intlo | TTE_HWWR_INT | TTE_REF_INT)
#define	TTE_CLR_RM(ttep)						\
	(((ttep)->tte_intlo) = (ttep)->tte_intlo &			\
	~(TTE_HWWR_INT | TTE_REF_INT))

#define	TTE_SET_WRT(ttep)	((ttep)->tte_wr_perm = 1)
#define	TTE_CLR_WRT(ttep)	((ttep)->tte_wr_perm = 0)
#define	TTE_SET_EXEC(ttep)	((ttep)->tte_exec_perm = 1)
#define	TTE_CLR_EXEC(ttep)	((ttep)->tte_exec_perm = 0)
#define	TTE_SET_PRIV(ttep)	((ttep)->tte_priv = 1)
#define	TTE_CLR_PRIV(ttep)	((ttep)->tte_priv = 0)

#define	TTE_IS_VCACHEABLE(ttep)		((ttep)->tte_cv)
#define	TTE_SET_VCACHEABLE(ttep)	((ttep)->tte_cv = 1)
#define	TTE_CLR_VCACHEABLE(ttep)	((ttep)->tte_cv = 0)
#define	TTE_IS_PCACHEABLE(ttep)		((ttep)->tte_cp)
#define	TTE_SET_PCACHEABLE(ttep)	((ttep)->tte_cp = 1)
#define	TTE_CLR_PCACHEABLE(ttep)	((ttep)->tte_cp = 0)


#define	KPM_TTE_VCACHED(tte64, pfn, tte_sz)				\
	tte64 = (((uint64_t)(TTE_VALID_INT |				\
	    (tte_sz) << TTE_SZ_SHFT_INT)) << 32) |			\
	    (((pfn) >> TTE_BSZS_SHIFT(tte_sz)) <<			\
	    (TTE_BSZS_SHIFT(tte_sz) + MMU_PAGESHIFT)) |			\
	    (TTE_CP_INT | TTE_CV_INT | TTE_PRIV_INT | TTE_HWWR_INT)

#define	KPM_TTE_VUNCACHED(tte64, pfn, tte_sz)				\
	tte64 = (((uint64_t)(TTE_VALID_INT |				\
	    (tte_sz) << TTE_SZ_SHFT_INT)) << 32) |			\
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

/*
 * There is no support for non-coherent I-cache in sun4u
 */
#define	TTE_SOFTEXEC_INT	0x00000000
#ifndef _ASM
#ifdef lint
/* fix lint warnings about constant conditionals and empty if */
#define	TTE_IS_SOFTEXEC(ttep)	TTE_IS_EXECUTABLE(ttep)
#define	TTE_SET_SOFTEXEC(ttep)	TTE_SET_EXEC(ttep)
#define	TTE_CLR_SOFTEXEC(ttep)	TTE_CLR_EXEC(ttep)
#else
#define	TTE_IS_SOFTEXEC(ttep)	(0)
#define	TTE_SET_SOFTEXEC(ttep)
#define	TTE_CLR_SOFTEXEC(ttep)
#endif	/* lint */
#endif /* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif /* !_SYS_PTE_H */
