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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _SYS_AMDZEN_CCD_H
#define	_SYS_AMDZEN_CCD_H

/*
 * SMN registers that are CCD-specific (core complex die) but are spread across
 * multiple functional units. This could be combined with <sys/amdzen/ccx.h>
 * once the duplication between that and <sys/controlregs.h> is dealt with.
 *
 * Currently this covers two different groups:
 *
 * SMU::PWR	This group describes information about the CCD and, unlike the
 *		DF CCM entries, this is only present if an actual die is
 *		present in the package. These registers are always present
 *		starting in Zen 2.
 *
 * L3::SCFCTP	The Scalable Control Fabric, Clocks, Test, and Power Gating
 *		registers exist on a per-core basis within each CCD. The first
 *		point that we can find that this exists started in Zen 3.
 *
 * The register naming and fields generally follows the conventions that the DF
 * and UMC have laid out. The one divergence right now is that the functional
 * blocks only exist starting in a given Zen uarch (e.g. Zen 2). Once we have
 * divergences from that introduction point then like the MSRs and others we
 * will introduce the generation-specific part of the name.
 */

#include <sys/bitext.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/amdzen/smn.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SMU::PWR registers, per-CCD.  This functional unit is present starting in Zen
 * based platforms.  Note that there is another aperture at 0x4008_1000 that is
 * documented to alias CCD 0.  It's not really clear what if any utility that's
 * supposed to have, except that the name given to these aliases contains
 * "LOCAL" which implies that perhaps rather than aliasing CCD 0 it instead is
 * decoded by the unit on the originating CCD.  We don't use that in any case.
 *
 * Because Genoa supports up to 12 CCDs, they did add a second aperture that
 * starts at 4a08_1000h and uses the same shifts. This leads to some awkwardness
 * below. This does make it harder to get at this. We should investigate to
 * include the uarch to determine limits at some point in the future like we
 * have done with some of our DF registers.
 */
static inline smn_reg_t
amdzen_smupwr_smn_reg(const uint8_t ccdno, const smn_reg_def_t def,
    const uint16_t reginst)
{
	const uint32_t APERTURE_BASE = 0x30081000;
	const uint32_t APERTURE_HI_BASE = 0x4a081000;
	const uint32_t APERTURE_MASK = 0xfffff000;
	CTASSERT((APERTURE_BASE & ~APERTURE_MASK) == 0);
	CTASSERT((APERTURE_HI_BASE & ~APERTURE_MASK) == 0);

	const uint32_t ccdno32 = (const uint32_t)ccdno;
	const uint32_t reginst32 = (const uint32_t)reginst;
	const uint32_t size32 = (def.srd_size == 0) ? 4 :
	    (const uint32_t)def.srd_size;

	const uint32_t stride = (def.srd_stride == 0) ? size32 : def.srd_stride;
	const uint32_t nents = (def.srd_nents == 0) ? 1 :
	    (const uint32_t)def.srd_nents;

	ASSERT(size32 == 1 || size32 == 2 || size32 == 4);
	ASSERT3S(def.srd_unit, ==, SMN_UNIT_SMUPWR);
	ASSERT3U(ccdno32, <, 12);
	ASSERT3U(nents, >, reginst32);

	uint32_t aperture_base, aperture_off;
	if (ccdno >= 8) {
		aperture_base = APERTURE_HI_BASE;
		aperture_off = (ccdno32 - 8) << 25;
	} else {
		aperture_base = APERTURE_BASE;
		aperture_off = ccdno32 << 25;
	}
	ASSERT3U(aperture_off, <=, UINT32_MAX - aperture_base);

	const uint32_t aperture = aperture_base + aperture_off;
	ASSERT0(aperture & ~APERTURE_MASK);

	const uint32_t reg = def.srd_reg + reginst32 * stride;
	ASSERT0(reg & APERTURE_MASK);

	return (SMN_MAKE_REG_SIZED(aperture + reg, size32));
}

/*
 * SMU::PWR::CCD_DIE_ID - does what it says.
 */
/*CSTYLED*/
#define	D_SMUPWR_CCD_DIE_ID	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_SMUPWR,			\
	.srd_reg = 0x00					\
}
#define	SMUPWR_CCD_DIE_ID(c)	\
    amdzen_smupwr_smn_reg(c, D_SMUPWR_CCD_DIE_ID, 0)
#define	SMUPWR_CCD_DIE_ID_GET(_r)	bitx32(_r, 3, 0)

/*
 * SMU::PWR::THREAD_ENABLE - also does what it says; this is a bitmap of each of
 * the possible threads.  If the bit is set, the thread runs.  Clearing bits
 * is not allowed.  A bit set in here corresponds to a logical thread, though
 * the exact layout is a bit tricky in the multi-CCX case.  When there are two
 * core complexes on the die, all of CCX0's possible threads will come first,
 * followed by all of CCX1's.  However, while this always describes _logical_
 * threads, the spacing is based upon the width of the total possible physical
 * cores in the CCX.
 *
 * For example, consider a Zen 2 system. It has 2 core complexes with 4 cores
 * each. Regardless of how many logical cores and threads are enabled in each
 * complex, CCX0 logical thread 0 always starts at bit 0 and CCX1 logical thread
 * 0 always starts at bit 8. In a system that only has 3/4 cores enabled then
 * we'd see this register set to 0x3f3f.  In Zen 3 and non-Bergamo Zen 4, this
 * is the same width, but there is only one core complex.  In Bergamo, this is
 * instead 32-bits wide with CCX1 thread 0 starting at bit 16.  All of this is
 * to say that even though these bits correspond to logical threads, the CCX
 * resets the bit position.
 *
 * However, if we move to a case where SMT is disabled then the CCX starting
 * point is still the same, but the there will not be a gap for threads within
 * the CCX. So bit 0 will be logical CPU 0 thread 0, bit 1 logical CPU 1 thread
 * 0, etc.
 */
/*CSTYLED*/
#define	D_SMUPWR_THREAD_EN	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_SMUPWR,			\
	.srd_reg = 0x18					\
}
#define	SMUPWR_THREAD_EN(c)	\
    amdzen_smupwr_smn_reg(c, D_SMUPWR_THREAD_EN, 0)
#define	SMUPWR_THREAD_EN_GET_T(_r, _t)	bitx32(_r, _t, _t)
#define	SMUPWR_THREAD_EN_SET_T(_r, _t)	bitset32(_r, _t, _t, 1)

/*
 * SMU::PWR::THREAD_CONFIGURATION - provides core and CCX counts for the die as
 * well as whether SMT is enabled, and a bit to enable or disable SMT *after the
 * next warm reset* (which we don't use).
 */
/*CSTYLED*/
#define	D_SMUPWR_THREAD_CFG	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_SMUPWR,			\
	.srd_reg = 0x1c					\
}
#define	SMUPWR_THREAD_CFG(c)	\
    amdzen_smupwr_smn_reg(c, D_SMUPWR_THREAD_CFG, 0)
#define	SMUPWR_THREAD_CFG_GET_SMT_MODE(_r)	bitx32(_r, 8, 8)
#define	SMUPWR_THREAD_CFG_SMT_MODE_1T		1
#define	SMUPWR_THREAD_CFG_SMT_MODE_SMT		0
#define	SMUPWR_THREAD_CFG_GET_COMPLEX_COUNT(_r)	bitx32(_r, 7, 4)
#define	SMUPWR_THREAD_CFG_GET_CORE_COUNT(_r)	bitx32(_r, 3, 0)

/*
 * SMU::PWR::SOFT_DOWNCORE - provides a bitmap of cores that may exist; setting
 * each bit disables the corresponding core.  Presumably after a warm reset.
 */
/*CSTYLED*/
#define	D_SMUPWR_SOFT_DOWNCORE	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_SMUPWR,			\
	.srd_reg = 0x20					\
}
#define	SMUPWR_SOFT_DOWNCORE(c)	\
    amdzen_smupwr_smn_reg(c, D_SMUPWR_SOFT_DOWNCORE, 0)
#define	SMUPWR_SOFT_DOWNCORE_GET_DISCORE(_r)		bitx32(_r, 7, 0)
#define	SMUPWR_SOFT_DOWNCORE_GET_DISCORE_C(_r, _c)	bitx32(_r, _c, _c)
#define	SMUPWR_SOFT_DOWNCORE_SET_DISCORE(_r, _v)	bitset32(_r, 7, 0, _v)
#define	SMUPWR_SOFT_DOWNCORE_SET_DISCORE_C(_r, _c)	bitset32(_r, _c, _c, 1)

/*
 * SMU::PWR::CORE_ENABLE - nominally writable, this register contains a bitmap
 * of cores; a bit that is set means the core whose physical ID is that bit
 * position is enabled.  The effect of modifying this register, if any, is
 * undocumented and unknown.
 */
/*CSTYLED*/
#define	D_SMUPWR_CORE_EN	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_SMUPWR,			\
	.srd_reg = 0x24					\
}
#define	SMUPWR_CORE_EN(c)	\
    amdzen_smupwr_smn_reg(c, D_SMUPWR_CORE_EN, 0)
#define	SMUPWR_CORE_EN_GET(_r)		bitx32(_r, 7, 0)
#define	SMUPWR_CORE_EN_GET_C(_r, _c)	bitx32(_r, _c, _c)
#define	SMUPWR_CORE_EN_SET(_r, _v)	bitset32(_r, 7, 0, _v)
#define	SMUPWR_CORE_EN_SET_C(_r, _c)	bitset32(_r, _c, _c, 1)

/*
 * SCFCTP registers. A copy of these exists for each core. One thing to be aware
 * of is that not all cores are enabled and this requires like at the SMU::PWR
 * registers above or the DF::CoreEnable. The aperture for these starts at
 * 2000_0000h. Each core is then spaced 2_0000h apart while each CCD has a
 * 23-bit stride and each CCX has a 22 bit stride. The number of cores per CCX
 * still caps at 8, which is what the various .srd_nents entries should be for
 * all registers in this space. The number of CCDs does vary per platform, but
 * we size this for the current largest number of 12 in Genoa and two CCXs.
 *
 * In the future, it'd be good to have a way to constrain the values we accept
 * to something less than the maximum across all products, but this is often
 * used before we have fully flushed out the uarchrev part of CPUID making it
 * challenging at the moment.
 */
#define	SCFCTP_CORE_STRIDE	0x20000
static inline smn_reg_t
amdzen_scfctp_smn_reg(const uint8_t ccdno, const uint8_t ccxno,
    const smn_reg_def_t def, const uint16_t reginst)
{
	const uint32_t APERTURE_BASE = 0x20000000;
	const uint32_t APERTURE_MASK = SMN_APERTURE_MASK;
	CTASSERT((APERTURE_BASE & ~APERTURE_MASK) == 0);

	const uint32_t ccdno32 = (const uint32_t)ccdno;
	const uint32_t ccxno32 = (const uint32_t)ccxno;
	const uint32_t reginst32 = (const uint32_t)reginst;
	const uint32_t size32 = (def.srd_size == 0) ? 4 :
	    (const uint32_t)def.srd_size;

	const uint32_t stride = (def.srd_stride == 0) ? 4 : def.srd_stride;
	const uint32_t nents = (def.srd_nents == 0) ? 1 :
	    (const uint32_t)def.srd_nents;

	ASSERT(size32 == 1 || size32 == 2 || size32 == 4);
	ASSERT3S(def.srd_unit, ==, SMN_UNIT_SCFCTP);
	ASSERT3U(stride, ==, SCFCTP_CORE_STRIDE);
	ASSERT3U(nents, ==, 8);
	ASSERT3U(ccdno32, <, 12);
	ASSERT3U(ccxno32, <, 2);
	ASSERT3U(nents, >, reginst32);

	const uint32_t aperture_off = (ccdno32 << 23) + (ccxno << 22);
	ASSERT3U(aperture_off, <=, UINT32_MAX - APERTURE_BASE);

	const uint32_t aperture = APERTURE_BASE + aperture_off;
	ASSERT0(aperture & ~APERTURE_MASK);

	const uint32_t reg = def.srd_reg + reginst32 * stride;
	ASSERT0(reg & APERTURE_MASK);

	return (SMN_MAKE_REG_SIZED(aperture + reg, size32));
}

/*
 * L3::SCFCTP::PMREG_INITPKG0 - Nominally writable, this register contains
 * information allowing us to discover where this core fits into the logical and
 * physical topology of the processor.
 */
/*CSTYLED*/
#define	D_SCFCTP_PMREG_INITPKG0	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_SCFCTP,			\
	.srd_reg = 0x2fd0,				\
	.srd_nents = 8,					\
	.srd_stride = SCFCTP_CORE_STRIDE		\
}
#define	SCFCTP_PMREG_INITPKG0(ccd, ccx, core)	\
    amdzen_scfctp_smn_reg(ccd, ccx, D_SCFCTP_PMREG_INITPKG0, core)
#define	SCFCTP_PMREG_INITPKG0_GET_LOG_DIE(_r)	bitx32(_r, 22, 19)
#define	SCFCTP_PMREG_INITPKG0_GET_LOG_CCX(_r)	bitx32(_r, 18, 18)
#define	SCFCTP_PMREG_INITPKG0_GET_LOG_CORE(_r)	bitx32(_r, 17, 14)
#define	SCFCTP_PMREG_INITPKG0_GET_SOCKET(_r)	bitx32(_r, 13, 12)
#define	SCFCTP_PMREG_INITPKG0_GET_PHYS_DIE(_r)	bitx32(_r, 11, 8)
#define	SCFCTP_PMREG_INITPKG0_GET_PHYS_CCX(_r)	bitx32(_r, 7, 7)
#define	SCFCTP_PMREG_INITPKG0_GET_PHYS_CORE(_r)	bitx32(_r, 6, 3)
#define	SCFCTP_PMREG_INITPKG0_GET_SMTEN(_r)	bitx32(_r, 2, 0)

/*
 * L3::SCFCTP::PMREG_INITPKG7 - Similarly, this register describes this
 * processor's overall internal core topology. The most notable addition to this
 * register has been the addition of a bit which causes the APIC ID for the CCX
 * to be shifted and covered by at least 4 bits. That is, if the number of bits
 * required to cover SCFCTP_PMREG_INITPKG7_GET_N_CCXS is less than 4, it should
 * be assumed to require 4 bits.
 */
/*CSTYLED*/
#define	D_SCFCTP_PMREG_INITPKG7	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_SCFCTP,			\
	.srd_reg = 0x2fec,				\
	.srd_nents = 8,					\
	.srd_stride = SCFCTP_CORE_STRIDE		\
}
#define	SCFCTP_PMREG_INITPKG7(ccd, ccx, core)	\
    amdzen_scfctp_smn_reg(ccd, ccx, D_SCFCTP_PMREG_INITPKG7, core)
#define	SCFCTP_PMREG_INITPKG7_GET_N_SOCKETS(_r)		bitx32(_r, 26, 25)
#define	SCFCTP_PMREG_INITPKG7_GET_N_DIES(_r)		bitx32(_r, 24, 21)
#define	SCFCTP_PMREG_INITPKG7_GET_N_CCXS(_r)		bitx32(_r, 20, 20)
#define	SCFCTP_PMREG_INITPKG7_GET_N_CORES(_r)		bitx32(_r, 19, 16)
#define	SCFCTP_PMREG_INITPKG7_ZEN4_GET_16TAPIC(_r)	bitx32(_r, 11, 11)
#define	SCFCTP_PMREG_INITPKG7_GET_CHIDXHASHEN(_r)	bitx32(_r, 10, 10)
#define	SCFCTP_PMREG_INITPKG7_GET_S3(_r)		bitx32(_r, 9, 9)
#define	SCFCTP_PMREG_INITPKG7_ZEN3_GET_S0I3(_r)		bitx32(_r, 8, 8)
#define	SCFCTP_PMREG_INITPKG7_GET_CORETYPEISARM(_r)	bitx32(_r, 7, 7)
#define	SCFCTP_PMREG_INITPKG7_GET_SOCID(_r)		bitx32(_r, 6, 3)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AMDZEN_CCD_H */
