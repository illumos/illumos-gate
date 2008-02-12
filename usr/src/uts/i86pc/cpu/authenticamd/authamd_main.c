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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * "Generic AMD" model-specific support.  If no more-specific support can
 * be found, or such modules declines to initialize, then for AuthenticAMD
 * cpus this module can have a crack at providing some AMD model-specific
 * support that at least goes beyond common MCA architectural features
 * if not down to the nitty-gritty level for a particular model.  We
 * are layered on top of a cpu module, likely cpu.generic, so there is no
 * need for us to perform common architecturally-accessible functions.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/cpu_module.h>
#include <sys/mca_x86.h>
#include <sys/pci_cfgspace.h>
#include <sys/x86_archext.h>
#include <sys/mc_amd.h>
#include <sys/fm/protocol.h>
#include <sys/fm/cpu/GENAMD.h>
#include <sys/nvpair.h>
#include <sys/controlregs.h>
#include <sys/pghw.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/cpu_module_ms_impl.h>

#include "authamd.h"

int authamd_ms_support_disable = 0;

#define	AUTHAMD_F_REVS_BCDE \
	(X86_CHIPREV_AMD_F_REV_B | X86_CHIPREV_AMD_F_REV_C0 | \
	X86_CHIPREV_AMD_F_REV_CG | X86_CHIPREV_AMD_F_REV_D | \
	X86_CHIPREV_AMD_F_REV_E)

#define	AUTHAMD_F_REVS_FG \
	(X86_CHIPREV_AMD_F_REV_F | X86_CHIPREV_AMD_F_REV_G)

#define	AUTHAMD_10_REVS_AB \
	(X86_CHIPREV_AMD_10_REV_A | X86_CHIPREV_AMD_10_REV_B)

/*
 * Bitmasks of support for various features.  Try to enable features
 * via inclusion in one of these bitmasks and check that at the
 * feature imlementation - that way new family support may often simply
 * simply need to update these bitmasks.
 */

/*
 * Families that this module will provide some model-specific
 * support for (if no more-specific module claims it first).
 * We try to support whole families rather than differentiate down
 * to revision.
 */
#define	AUTHAMD_SUPPORTED(fam) \
	((fam) == AUTHAMD_FAMILY_6 || (fam) == AUTHAMD_FAMILY_F || \
	(fam) == AUTHAMD_FAMILY_10)

/*
 * Models that include an on-chip NorthBridge.
 */
#define	AUTHAMD_NBONCHIP(rev) \
	(X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_B) || \
	X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_10_REV_A))

/*
 * Families/revisions for which we can recognise main memory ECC errors.
 */
#define	AUTHAMD_MEMECC_RECOGNISED(rev) \
	(X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_B) || \
	X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_10_REV_A))

/*
 * Families/revisions that have an Online Spare Control Register
 */
#define	AUTHAMD_HAS_ONLINESPARECTL(rev) \
	(X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_F) || \
	X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_10_REV_A))

/*
 * Families/revisions for which we will perform NB MCA Config changes
 */
#define	AUTHAMD_DO_NBMCACFG(rev) \
	(X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_B) || \
	X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_10_REV_A))

/*
 * Families/revisions that have chip cache scrubbers.
 */
#define	AUTHAMD_HAS_CHIPSCRUB(rev) \
	(X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_B) || \
	X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_10_REV_A))

/*
 * Families/revisions that have a NB misc register or registers -
 * evaluates to 0 if no support, otherwise the number of MC4_MISCj.
 */
#define	AUTHAMD_NBMISC_NUM(rev) \
	(X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_F)? 1 : \
	(X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_10_REV_A) ? 3 : 0))

/*
 * Families/revision for which we wish not to machine check for GART
 * table walk errors - bit 10 of NB CTL.
 */
#define	AUTHAMD_NOGARTTBLWLK_MC(rev) \
	(X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_B) || \
	X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_10_REV_A))

/*
 * Families/revisions that are potentially L3 capable
 */
#define	AUTHAMD_L3CAPABLE(rev) \
	(X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_10_REV_A))

/*
 * We recognise main memory ECC errors for AUTHAMD_MEMECC_RECOGNISED
 * revisions as:
 *
 *	- being reported by the NB
 *	- being a compound bus/interconnect error (external to chip)
 *	- having LL of LG
 *	- having II of MEM (but could still be a master/target abort)
 *	- having CECC or UECC set
 *
 * We do not check the extended error code (first nibble of the
 * model-specific error code on AMD) since this has changed from
 * family 0xf to family 0x10 (ext code 0 now reserved on family 0x10).
 * Instead we use CECC/UECC to separate off the master/target
 * abort cases.
 *
 * We insist that the detector be the NorthBridge bank;  although
 * IC/DC can report some main memory errors, they do not capture
 * an address at sufficient resolution to be useful and the NB will
 * report most errors.
 */
#define	AUTHAMD_IS_MEMECCERR(bank, status) \
	((bank) == AMD_MCA_BANK_NB && \
	MCAX86_ERRCODE_ISBUS_INTERCONNECT(MCAX86_ERRCODE(status)) && \
	MCAX86_ERRCODE_LL(MCAX86_ERRCODE(status)) == MCAX86_ERRCODE_LL_LG && \
	MCAX86_ERRCODE_II(MCAX86_ERRCODE(status)) == MCAX86_ERRCODE_II_MEM && \
	((status) & (AMD_BANK_STAT_CECC | AMD_BANK_STAT_UECC)))

static authamd_error_disp_t authamd_memce_disp = {
	FM_EREPORT_CPU_GENAMD,
	FM_EREPORT_CPU_GENAMD_MEM_CE,
	FM_EREPORT_GENAMD_PAYLOAD_FLAGS_MEM_CE
};

static authamd_error_disp_t authamd_memue_disp = {
	FM_EREPORT_CPU_GENAMD,
	FM_EREPORT_CPU_GENAMD_MEM_UE,
	FM_EREPORT_GENAMD_PAYLOAD_FLAGS_MEM_UE
};

static authamd_error_disp_t authamd_ckmemce_disp = {
	FM_EREPORT_CPU_GENAMD,
	FM_EREPORT_CPU_GENAMD_CKMEM_CE,
	FM_EREPORT_GENAMD_PAYLOAD_FLAGS_CKMEM_CE
};

static authamd_error_disp_t authamd_ckmemue_disp = {
	FM_EREPORT_CPU_GENAMD,
	FM_EREPORT_CPU_GENAMD_CKMEM_UE,
	FM_EREPORT_GENAMD_PAYLOAD_FLAGS_CKMEM_UE
};

/*
 * We recognise GART walk errors as:
 *
 *	- being reported by the NB
 *	- being a compound TLB error
 *	- having LL of LG and TT of GEN
 *	- having UC set
 *	- possibly having PCC set (if source CPU)
 */
#define	AUTHAMD_IS_GARTERR(bank, status) \
	((bank) == AMD_MCA_BANK_NB && \
	MCAX86_ERRCODE_ISTLB(MCAX86_ERRCODE(status)) && \
	MCAX86_ERRCODE_LL(MCAX86_ERRCODE(status)) == MCAX86_ERRCODE_LL_LG && \
	MCAX86_ERRCODE_TT(MCAX86_ERRCODE(status)) == MCAX86_ERRCODE_TT_GEN && \
	(status) & MSR_MC_STATUS_UC)

static authamd_error_disp_t authamd_gart_disp = {
	FM_EREPORT_CPU_GENAMD,			/* use generic subclass */
	FM_EREPORT_CPU_GENADM_GARTTBLWLK,	/* use generic leafclass */
	0					/* no additional payload */
};


static struct authamd_chipshared *authamd_shared[AUTHAMD_MAX_CHIPS];

static int
authamd_chip_once(authamd_data_t *authamd, enum authamd_cfgonce_bitnum what)
{
	return (atomic_set_long_excl(&authamd->amd_shared->acs_cfgonce,
	    what) == 0 ?  B_TRUE : B_FALSE);
}

static void
authamd_pcicfg_write(uint_t chipid, uint_t func, uint_t reg, uint32_t val)
{
	ASSERT(chipid + 24 <= 31);
	ASSERT((func & 7) == func);
	ASSERT((reg & 3) == 0 && reg < 256);

	cmi_pci_putl(0, chipid + 24, func, reg, 0, val);
}

static uint32_t
authamd_pcicfg_read(uint_t chipid, uint_t func, uint_t reg)
{
	ASSERT(chipid + 24 <= 31);
	ASSERT((func & 7) == func);
	ASSERT((reg & 3) == 0 && reg < 256);

	return (cmi_pci_getl(0, chipid + 24, func, reg, 0, 0));
}

void
authamd_bankstatus_prewrite(cmi_hdl_t hdl, authamd_data_t *authamd)
{
	uint64_t hwcr;

	if (cmi_hdl_rdmsr(hdl, MSR_AMD_HWCR, &hwcr) != CMI_SUCCESS)
		return;

	authamd->amd_hwcr = hwcr;

	if (!(hwcr & AMD_HWCR_MCI_STATUS_WREN)) {
		hwcr |= AMD_HWCR_MCI_STATUS_WREN;
		(void) cmi_hdl_wrmsr(hdl, MSR_AMD_HWCR, hwcr);
	}
}

void
authamd_bankstatus_postwrite(cmi_hdl_t hdl, authamd_data_t *authamd)
{
	uint64_t hwcr = authamd->amd_hwcr;

	if (!(hwcr & AMD_HWCR_MCI_STATUS_WREN)) {
		hwcr &= ~AMD_HWCR_MCI_STATUS_WREN;
		(void) cmi_hdl_wrmsr(hdl, MSR_AMD_HWCR, hwcr);
	}
}

/*
 * Read EccCnt repeatedly for all possible channel/chip-select combos:
 *
 *	- read sparectl register
 *	- if EccErrCntWrEn is set, clear that bit in the just-read value
 *	  and write it back to sparectl;  this *may* clobber the EccCnt
 *	  for the channel/chip-select combination currently selected, so
 *	  we leave this bit clear if we had to clear it
 *	- cycle through all channel/chip-select combinations writing each
 *	  combination to sparectl before reading the register back for
 *	  EccCnt for that combination;  since EccErrCntWrEn is clear
 *	  the writes to select what count to read will not themselves
 *	  zero any counts
 */
static int
authamd_read_ecccnt(authamd_data_t *authamd, struct authamd_logout *msl)
{
	union mcreg_sparectl sparectl;
	uint_t chipid = authamd->amd_shared->acs_chipid;
	uint_t family = authamd->amd_shared->acs_family;
	uint32_t rev = authamd->amd_shared->acs_rev;
	int chan, cs;

	/*
	 * Check for feature support;  this macro will test down to the
	 * family revision number, whereafter we'll switch on family
	 * assuming that future revisions will use the same register
	 * format.
	 */
	if (!AUTHAMD_HAS_ONLINESPARECTL(rev)) {
		bzero(&msl->aal_eccerrcnt, sizeof (msl->aal_eccerrcnt));
		return (0);
	}

	MCREG_VAL32(&sparectl) =
	    authamd_pcicfg_read(chipid, MC_FUNC_MISCCTL, MC_CTL_REG_SPARECTL);

	switch (family) {
	case AUTHAMD_FAMILY_F:
		MCREG_FIELD_F_revFG(&sparectl, EccErrCntWrEn) = 0;
		break;

	case AUTHAMD_FAMILY_10:
		MCREG_FIELD_10_revAB(&sparectl, EccErrCntWrEn) = 0;
		break;
	}

	for (chan = 0; chan < AUTHAMD_DRAM_NCHANNEL; chan++) {
		switch (family) {
		case AUTHAMD_FAMILY_F:
			MCREG_FIELD_F_revFG(&sparectl, EccErrCntDramChan) =
			    chan;
			break;

		case AUTHAMD_FAMILY_10:
			MCREG_FIELD_10_revAB(&sparectl, EccErrCntDramChan) =
			    chan;
			break;
		}

		for (cs = 0; cs < AUTHAMD_DRAM_NCS; cs++) {
			switch (family) {
			case AUTHAMD_FAMILY_F:
				MCREG_FIELD_F_revFG(&sparectl,
				    EccErrCntDramCs) = cs;
				break;

			case AUTHAMD_FAMILY_10:
				MCREG_FIELD_10_revAB(&sparectl,
				    EccErrCntDramCs) = cs;
				break;
			}

			authamd_pcicfg_write(chipid, MC_FUNC_MISCCTL,
			    MC_CTL_REG_SPARECTL, MCREG_VAL32(&sparectl));

			MCREG_VAL32(&sparectl) = authamd_pcicfg_read(chipid,
			    MC_FUNC_MISCCTL, MC_CTL_REG_SPARECTL);

			switch (family) {
			case AUTHAMD_FAMILY_F:
				msl->aal_eccerrcnt[chan][cs] =
				    MCREG_FIELD_F_revFG(&sparectl, EccErrCnt);
				break;
			case AUTHAMD_FAMILY_10:
				msl->aal_eccerrcnt[chan][cs] =
				    MCREG_FIELD_10_revAB(&sparectl, EccErrCnt);
				break;
			}
		}
	}

	return (1);
}

/*
 * Clear EccCnt for all possible channel/chip-select combos:
 *
 *	- set EccErrCntWrEn in sparectl, if necessary
 *	- write 0 to EccCnt for all channel/chip-select combinations
 *	- clear EccErrCntWrEn
 *
 * If requested also disable the interrupts taken on counter overflow
 * and on swap done.
 */
static void
authamd_clear_ecccnt(authamd_data_t *authamd, boolean_t clrint)
{
	union mcreg_sparectl sparectl;
	uint_t chipid = authamd->amd_shared->acs_chipid;
	uint_t family = authamd->amd_shared->acs_family;
	uint32_t rev = authamd->amd_shared->acs_rev;
	int chan, cs;

	if (!AUTHAMD_HAS_ONLINESPARECTL(rev))
		return;

	MCREG_VAL32(&sparectl) =
	    authamd_pcicfg_read(chipid, MC_FUNC_MISCCTL, MC_CTL_REG_SPARECTL);

	switch (family) {
	case AUTHAMD_FAMILY_F:
		MCREG_FIELD_F_revFG(&sparectl, EccErrCntWrEn) = 1;
		if (clrint) {
			MCREG_FIELD_F_revFG(&sparectl, EccErrInt) = 0;
			MCREG_FIELD_F_revFG(&sparectl, SwapDoneInt) = 0;
		}
		break;

	case AUTHAMD_FAMILY_10:
		MCREG_FIELD_10_revAB(&sparectl, EccErrCntWrEn) = 1;
		if (clrint) {
			MCREG_FIELD_10_revAB(&sparectl, EccErrInt) = 0;
			MCREG_FIELD_10_revAB(&sparectl, SwapDoneInt) = 0;
		}
		break;
	}

	authamd_pcicfg_write(chipid, MC_FUNC_MISCCTL,
	    MC_CTL_REG_SPARECTL, MCREG_VAL32(&sparectl));

	for (chan = 0; chan < AUTHAMD_DRAM_NCHANNEL; chan++) {
		switch (family) {
		case AUTHAMD_FAMILY_F:
			MCREG_FIELD_F_revFG(&sparectl, EccErrCntDramChan) =
			    chan;
			break;

		case AUTHAMD_FAMILY_10:
			MCREG_FIELD_10_revAB(&sparectl, EccErrCntDramChan) =
			    chan;
			break;
		}

		for (cs = 0; cs < AUTHAMD_DRAM_NCS; cs++) {
			switch (family) {
			case AUTHAMD_FAMILY_F:
				MCREG_FIELD_F_revFG(&sparectl,
				    EccErrCntDramCs) = cs;
				MCREG_FIELD_F_revFG(&sparectl,
				    EccErrCnt) = 0;
				break;

			case AUTHAMD_FAMILY_10:
				MCREG_FIELD_10_revAB(&sparectl,
				    EccErrCntDramCs) = cs;
				MCREG_FIELD_10_revAB(&sparectl,
				    EccErrCnt) = 0;
				break;
			}

			authamd_pcicfg_write(chipid, MC_FUNC_MISCCTL,
			    MC_CTL_REG_SPARECTL, MCREG_VAL32(&sparectl));
		}
	}
}

/*
 * cms_init entry point.
 *
 * This module provides broad model-specific support for AMD families
 * 0x6, 0xf and 0x10.  Future families will have to be evaluated once their
 * documentation is available.
 */
int
authamd_init(cmi_hdl_t hdl, void **datap)
{
	uint_t chipid = cmi_hdl_chipid(hdl);
	struct authamd_chipshared *sp, *osp;
	uint_t family = cmi_hdl_family(hdl);
	authamd_data_t *authamd;
	uint64_t cap;

	if (authamd_ms_support_disable || !AUTHAMD_SUPPORTED(family))
		return (ENOTSUP);

	if (!(x86_feature & X86_MCA))
		return (ENOTSUP);

	if (cmi_hdl_rdmsr(hdl, IA32_MSR_MCG_CAP, &cap) != CMI_SUCCESS)
		return (ENOTSUP);

	if (!(cap & MCG_CAP_CTL_P))
		return (ENOTSUP);

	authamd = *datap = kmem_zalloc(sizeof (authamd_data_t), KM_SLEEP);
	cmi_hdl_hold(hdl);	/* release in fini */
	authamd->amd_hdl = hdl;

	if ((sp = authamd_shared[chipid]) == NULL) {
		sp = kmem_zalloc(sizeof (struct authamd_chipshared), KM_SLEEP);
		sp->acs_chipid = chipid;
		sp->acs_family = family;
		sp->acs_rev = cmi_hdl_chiprev(hdl);
		membar_producer();

		osp = atomic_cas_ptr(&authamd_shared[chipid], NULL, sp);
		if (osp != NULL) {
			kmem_free(sp, sizeof (struct authamd_chipshared));
			sp = osp;
		}
	}
	authamd->amd_shared = sp;

	return (0);
}

/*
 * cms_logout_size entry point.
 */
/*ARGSUSED*/
size_t
authamd_logout_size(cmi_hdl_t hdl)
{
	return (sizeof (struct authamd_logout));
}

/*
 * cms_mcgctl_val entry point
 *
 * Instead of setting all bits to 1 we can set just those for the
 * error detector banks known to exist.
 */
/*ARGSUSED*/
uint64_t
authamd_mcgctl_val(cmi_hdl_t hdl, int nbanks, uint64_t proposed)
{
	return (nbanks < 64 ? (1ULL << nbanks) - 1 : proposed);
}

/*
 * cms_bankctl_skipinit entry point
 *
 * On K6 we do not initialize MC0_CTL since, reportedly, this bank (for DC)
 * may produce spurious machine checks.
 *
 * Only allow a single core to setup the NorthBridge MCi_CTL register.
 */
/*ARGSUSED*/
boolean_t
authamd_bankctl_skipinit(cmi_hdl_t hdl, int bank)
{
	authamd_data_t *authamd = cms_hdl_getcmsdata(hdl);
	uint32_t rev = authamd->amd_shared->acs_rev;

	if (authamd->amd_shared->acs_family == AUTHAMD_FAMILY_6)
		return (bank == 0 ?  B_TRUE : B_FALSE);

	if (AUTHAMD_NBONCHIP(rev) && bank == AMD_MCA_BANK_NB) {
		return (authamd_chip_once(authamd, AUTHAMD_CFGONCE_NBMCA) ==
		    B_TRUE ? B_FALSE : B_TRUE);
	}

	return (B_FALSE);
}

/*
 * cms_bankctl_val entry point
 */
uint64_t
authamd_bankctl_val(cmi_hdl_t hdl, int bank, uint64_t proposed)
{
	authamd_data_t *authamd = cms_hdl_getcmsdata(hdl);
	uint32_t rev = authamd->amd_shared->acs_rev;
	uint64_t val = proposed;

	/*
	 * The Intel MCA says we can write all 1's to enable #MC for
	 * all errors, and AMD docs say much the same.  But, depending
	 * perhaps on other config registers, taking machine checks
	 * for some errors such as GART TLB errors and master/target
	 * aborts may be bad - they set UC and sometime also PCC, but
	 * we should not always panic for these error types.
	 *
	 * Our cms_error_action entry point can suppress such panics,
	 * however we can also use the cms_bankctl_val entry point to
	 * veto enabling of some of the known villains in the first place.
	 */
	if (bank == AMD_MCA_BANK_NB && AUTHAMD_NOGARTTBLWLK_MC(rev))
		val &= ~AMD_NB_EN_GARTTBLWK;

	return (val);
}

/*
 * Bits to add to NB MCA config (after watchdog config).
 */
uint32_t authamd_nb_mcacfg_add = AMD_NB_CFG_ADD_CMN;

/*
 * Bits to remove from NB MCA config (after watchdog config)
 */
uint32_t authamd_nb_mcacfg_remove = AMD_NB_CFG_REMOVE_CMN;

/*
 * NB Watchdog policy, and rate we use if enabling.
 */
enum {
	AUTHAMD_NB_WDOG_LEAVEALONE,
	AUTHAMD_NB_WDOG_DISABLE,
	AUTHAMD_NB_WDOG_ENABLE_IF_DISABLED,
	AUTHAMD_NB_WDOG_ENABLE_FORCE_RATE
} authamd_nb_watchdog_policy = AUTHAMD_NB_WDOG_ENABLE_IF_DISABLED;

uint32_t authamd_nb_mcacfg_wdog = AMD_NB_CFG_WDOGTMRCNTSEL_4095 |
    AMD_NB_CFG_WDOGTMRBASESEL_1MS;

/*
 * Per-core cache scrubbing policy and rates.
 */
enum {
	AUTHAMD_SCRUB_BIOSDEFAULT,	/* leave as BIOS configured */
	AUTHAMD_SCRUB_FIXED,		/* assign our chosen rate */
	AUTHAMD_SCRUB_MAX		/* use higher of ours and BIOS rate */
} authamd_scrub_policy = AUTHAMD_SCRUB_MAX;

uint32_t authamd_scrub_rate_dcache = 0xf;	/* 64K per 0.67 seconds */
uint32_t authamd_scrub_rate_l2cache = 0xe;	/* 1MB per 5.3 seconds */
uint32_t authamd_scrub_rate_l3cache = 0xd;	/* 1MB per 2.7 seconds */

static uint32_t
authamd_scrubrate(uint32_t osrate, uint32_t biosrate, const char *varnm)
{
	uint32_t rate;

	if (osrate > AMD_NB_SCRUBCTL_RATE_MAX) {
		cmn_err(CE_WARN, "%s is too large, resetting to 0x%x\n",
		    varnm, AMD_NB_SCRUBCTL_RATE_MAX);
		osrate = AMD_NB_SCRUBCTL_RATE_MAX;
	}

	switch (authamd_scrub_policy) {
	case AUTHAMD_SCRUB_FIXED:
		rate = osrate;
		break;

	default:
		cmn_err(CE_WARN, "Unknown authamd_scrub_policy %d - "
		    "using default policy of AUTHAMD_SCRUB_MAX",
		    authamd_scrub_policy);
		/*FALLTHRU*/

	case AUTHAMD_SCRUB_MAX:
		if (osrate != 0 && biosrate != 0)
			rate = MIN(osrate, biosrate);	/* small is fast */
		else
			rate = osrate ? osrate : biosrate;
	}

	return (rate);
}

/*
 * cms_mca_init entry point.
 */
/*ARGSUSED*/
void
authamd_mca_init(cmi_hdl_t hdl, int nbanks)
{
	authamd_data_t *authamd = cms_hdl_getcmsdata(hdl);
	uint32_t rev = authamd->amd_shared->acs_rev;
	uint_t chipid = authamd->amd_shared->acs_chipid;

	/*
	 * On chips with a NB online spare control register take control
	 * and clear ECC counts.
	 */
	if (AUTHAMD_HAS_ONLINESPARECTL(rev) &&
	    authamd_chip_once(authamd, AUTHAMD_CFGONCE_ONLNSPRCFG)) {
		authamd_clear_ecccnt(authamd, B_TRUE);
	}

	/*
	 * And since we are claiming the telemetry stop the BIOS receiving
	 * an SMI on NB threshold overflow.
	 */
	if (AUTHAMD_NBMISC_NUM(rev) &&
	    authamd_chip_once(authamd, AUTHAMD_CFGONCE_NBTHRESH)) {
		union mcmsr_nbmisc nbm;
		int i;

		authamd_bankstatus_prewrite(hdl, authamd);

		for (i = 0; i < AUTHAMD_NBMISC_NUM(rev); i++) {
			if (cmi_hdl_rdmsr(hdl, MC_MSR_NB_MISC(i),
			    (uint64_t *)&nbm) != CMI_SUCCESS)
				continue;

			if (X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_F) &&
			    MCMSR_FIELD_F_revFG(&nbm, mcmisc_Valid) &&
			    MCMSR_FIELD_F_revFG(&nbm, mcmisc_CntP)) {
				MCMSR_FIELD_F_revFG(&nbm, mcmisc_IntType) = 0;
			} else if (X86_CHIPREV_ATLEAST(rev,
			    X86_CHIPREV_AMD_10_REV_A) &&
			    MCMSR_FIELD_10_revAB(&nbm, mcmisc_Valid) &&
			    MCMSR_FIELD_10_revAB(&nbm, mcmisc_CntP)) {
				MCMSR_FIELD_10_revAB(&nbm, mcmisc_IntType) = 0;
			}

			(void) cmi_hdl_wrmsr(hdl, MC_MSR_NB_MISC(i),
			    MCMSR_VAL(&nbm));
		}

		authamd_bankstatus_postwrite(hdl, authamd);
	}

	/*
	 * NB MCA Configuration Register.
	 */
	if (AUTHAMD_DO_NBMCACFG(rev) &&
	    authamd_chip_once(authamd, AUTHAMD_CFGONCE_NBMCACFG)) {
		uint32_t val = authamd_pcicfg_read(chipid, MC_FUNC_MISCCTL,
		    MC_CTL_REG_NBCFG);

		switch (authamd_nb_watchdog_policy) {
		case AUTHAMD_NB_WDOG_LEAVEALONE:
			break;

		case AUTHAMD_NB_WDOG_DISABLE:
			val &= ~(AMD_NB_CFG_WDOGTMRBASESEL_MASK |
			    AMD_NB_CFG_WDOGTMRCNTSEL_MASK);
			val |= AMD_NB_CFG_WDOGTMRDIS;
			break;

		default:
			cmn_err(CE_NOTE, "authamd_nb_watchdog_policy=%d "
			    "unrecognised, using default policy",
			    authamd_nb_watchdog_policy);
			/*FALLTHRU*/

		case AUTHAMD_NB_WDOG_ENABLE_IF_DISABLED:
			if (!(val & AMD_NB_CFG_WDOGTMRDIS))
				break;	/* if enabled leave rate intact */
			/*FALLTHRU*/

		case AUTHAMD_NB_WDOG_ENABLE_FORCE_RATE:
			val &= ~(AMD_NB_CFG_WDOGTMRBASESEL_MASK |
			    AMD_NB_CFG_WDOGTMRCNTSEL_MASK |
			    AMD_NB_CFG_WDOGTMRDIS);
			val |= authamd_nb_mcacfg_wdog;
			break;
		}

		/*
		 * Bit 0 of the NB MCA Config register is reserved on family
		 * 0x10.
		 */
		if (X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_10_REV_A))
			authamd_nb_mcacfg_add &= ~AMD_NB_CFG_CPUECCERREN;

		val &= ~authamd_nb_mcacfg_remove;
		val |= authamd_nb_mcacfg_add;

		authamd_pcicfg_write(chipid, MC_FUNC_MISCCTL, MC_CTL_REG_NBCFG,
		    val);
	}

	/*
	 * Cache scrubbing.  We can't enable DRAM scrubbing since
	 * we don't know the DRAM base for this node.
	 */
	if (AUTHAMD_HAS_CHIPSCRUB(rev) &&
	    authamd_scrub_policy != AUTHAMD_SCRUB_BIOSDEFAULT &&
	    authamd_chip_once(authamd, AUTHAMD_CFGONCE_CACHESCRUB)) {
		uint32_t val = authamd_pcicfg_read(chipid, MC_FUNC_MISCCTL,
		    MC_CTL_REG_SCRUBCTL);
		int l3cap = 0;

		if (AUTHAMD_L3CAPABLE(rev)) {
			l3cap = (authamd_pcicfg_read(chipid, MC_FUNC_MISCCTL,
			    MC_CTL_REG_NBCAP) & MC_NBCAP_L3CAPABLE) != 0;
		}

		authamd_scrub_rate_dcache =
		    authamd_scrubrate(authamd_scrub_rate_dcache,
		    (val & AMD_NB_SCRUBCTL_DC_MASK) >> AMD_NB_SCRUBCTL_DC_SHIFT,
		    "authamd_scrub_rate_dcache");

		authamd_scrub_rate_l2cache =
		    authamd_scrubrate(authamd_scrub_rate_l2cache,
		    (val & AMD_NB_SCRUBCTL_L2_MASK) >> AMD_NB_SCRUBCTL_L2_SHIFT,
		    "authamd_scrub_rate_l2cache");

		authamd_scrub_rate_l3cache = l3cap ?
		    authamd_scrubrate(authamd_scrub_rate_l3cache,
		    (val & AMD_NB_SCRUBCTL_L3_MASK) >> AMD_NB_SCRUBCTL_L3_SHIFT,
		    "authamd_scrub_rate_l3cache") : 0;

		val = AMD_NB_MKSCRUBCTL(authamd_scrub_rate_l3cache,
		    authamd_scrub_rate_dcache, authamd_scrub_rate_l2cache,
		    val & AMD_NB_SCRUBCTL_DRAM_MASK);

		authamd_pcicfg_write(chipid, MC_FUNC_MISCCTL,
		    MC_CTL_REG_SCRUBCTL, val);
	}

}

/*
 * cms_poll_ownermask entry point.
 */
uint64_t
authamd_poll_ownermask(cmi_hdl_t hdl, hrtime_t pintvl)
{
	authamd_data_t *authamd = cms_hdl_getcmsdata(hdl);
	struct authamd_chipshared *acsp = authamd->amd_shared;
	hrtime_t now = gethrtime_waitfree();
	hrtime_t last = acsp->acs_poll_timestamp;
	int dopoll = 0;

	if (now - last > 2 * pintvl || last == 0) {
		acsp->acs_pollowner = hdl;
		dopoll = 1;
	} else if (acsp->acs_pollowner == hdl) {
		dopoll = 1;
	}

	if (dopoll)
		acsp->acs_poll_timestamp = now;

	return (dopoll ? -1ULL : ~(1 << AMD_MCA_BANK_NB));

}

/*
 * cms_bank_logout entry point.
 */
/*ARGSUSED*/
void
authamd_bank_logout(cmi_hdl_t hdl, int bank, uint64_t status,
    uint64_t addr, uint64_t misc, void *mslogout)
{
	authamd_data_t *authamd = cms_hdl_getcmsdata(hdl);
	struct authamd_logout *msl = mslogout;
	uint32_t rev = authamd->amd_shared->acs_rev;

	if (msl == NULL)
		return;

	/*
	 * For main memory ECC errors on revisions with an Online Spare
	 * Control Register grab the ECC counts by channel and chip-select
	 * and reset them to 0.
	 */
	if (AUTHAMD_MEMECC_RECOGNISED(rev) &&
	    AUTHAMD_IS_MEMECCERR(bank, status) &&
	    AUTHAMD_HAS_ONLINESPARECTL(rev)) {
		if (authamd_read_ecccnt(authamd, msl))
			authamd_clear_ecccnt(authamd, B_FALSE);
	}
}

/*
 * cms_error_action entry point
 */

int authamd_forgive_uc = 0;	/* For test/debug only */
int authamd_forgive_pcc = 0;	/* For test/debug only */
int authamd_fake_poison = 0;	/* For test/debug only */

/*ARGSUSED*/
uint32_t
authamd_error_action(cmi_hdl_t hdl, int ismc, int bank,
    uint64_t status, uint64_t addr, uint64_t misc, void *mslogout)
{
	authamd_error_disp_t *disp;
	uint32_t rv = 0;

	if (authamd_forgive_uc)
		rv |= CMS_ERRSCOPE_CLEARED_UC;

	if (authamd_forgive_pcc)
		rv |= CMS_ERRSCOPE_CURCONTEXT_OK;

	if (authamd_fake_poison && status & MSR_MC_STATUS_UC)
		rv |= CMS_ERRSCOPE_POISONED;

	if (rv)
		return (rv);

	disp = authamd_disp_match(hdl, bank, status, addr, misc, mslogout);

	if (disp == &authamd_gart_disp) {
		/*
		 * GART walk errors set UC and possibly PCC (if source CPU)
		 * but should not be regarded as terminal.
		 */
		return (CMS_ERRSCOPE_IGNORE_ERR);
	}

	/*
	 * May also want to consider master abort and target abort.  These
	 * also set UC and PCC (if src CPU) but the requester gets -1
	 * and I believe the IO stuff in Solaris will handle that.
	 */

	return (rv);
}

/*
 * cms_disp_match entry point
 */
/*ARGSUSED*/
cms_cookie_t
authamd_disp_match(cmi_hdl_t hdl, int bank, uint64_t status,
    uint64_t addr, uint64_t misc, void *mslogout)
{
	authamd_data_t *authamd = cms_hdl_getcmsdata(hdl);
	/* uint16_t errcode = MCAX86_ERRCODE(status); */
	uint16_t exterrcode = AMD_EXT_ERRCODE(status);
	uint32_t rev = authamd->amd_shared->acs_rev;

	/*
	 * Recognise main memory ECC errors
	 */
	if (AUTHAMD_MEMECC_RECOGNISED(rev) &&
	    AUTHAMD_IS_MEMECCERR(bank, status)) {
		if (status & AMD_BANK_STAT_CECC) {
			return (exterrcode == 0 ? &authamd_memce_disp :
			    &authamd_ckmemce_disp);
		} else if (status & AMD_BANK_STAT_UECC) {
			return (exterrcode == 0 ? &authamd_memue_disp :
			    &authamd_ckmemue_disp);
		}
	}

	/*
	 * Recognise GART walk errors
	 */
	if (AUTHAMD_NOGARTTBLWLK_MC(rev) && AUTHAMD_IS_GARTERR(bank, status))
		return (&authamd_gart_disp);

	return (NULL);
}

/*
 * cms_ereport_class entry point
 */
/*ARGSUSED*/
void
authamd_ereport_class(cmi_hdl_t hdl, cms_cookie_t mscookie,
    const char **cpuclsp, const char **leafclsp)
{
	const authamd_error_disp_t *aed = mscookie;

	if (aed == NULL)
		return;

	if (aed->aad_subclass != NULL)
		*cpuclsp = aed->aad_subclass;
	if (aed->aad_leafclass != NULL)
		*leafclsp = aed->aad_leafclass;
}

/*ARGSUSED*/
static void
authamd_ereport_add_resource(cmi_hdl_t hdl, authamd_data_t *authamd,
    nvlist_t *ereport, nv_alloc_t *nva, void *mslogout)
{
	nvlist_t *elems[AUTHAMD_DRAM_NCHANNEL * AUTHAMD_DRAM_NCS];
	uint8_t counts[AUTHAMD_DRAM_NCHANNEL * AUTHAMD_DRAM_NCS];
	authamd_logout_t *msl;
	nvlist_t *nvl;
	int nelems = 0;
	int i, chan, cs;

	if ((msl = mslogout) == NULL)
		return;

	for (chan = 0; chan < AUTHAMD_DRAM_NCHANNEL; chan++) {
		for (cs = 0; cs < AUTHAMD_DRAM_NCS; cs++) {
			if (msl->aal_eccerrcnt[chan][cs] == 0)
				continue;

			if ((nvl = fm_nvlist_create(nva)) == NULL)
				continue;

			elems[nelems] = nvl;
			counts[nelems++] = msl->aal_eccerrcnt[chan][cs];

			fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, NULL, 5,
			    "motherboard", 0,
			    "chip", authamd->amd_shared->acs_chipid,
			    "memory-controller", 0,
			    "dram-channel", chan,
			    "chip-select", cs);
		}
	}

	if (nelems == 0)
		return;

	fm_payload_set(ereport, FM_EREPORT_GENAMD_PAYLOAD_NAME_RESOURCE,
	    DATA_TYPE_NVLIST_ARRAY, nelems, elems,
	    NULL);

	fm_payload_set(ereport, FM_EREPORT_GENAMD_PAYLOAD_NAME_RESOURCECNT,
	    DATA_TYPE_UINT8_ARRAY, nelems, &counts[0],
	    NULL);

	for (i = 0; i < nelems; i++)
		fm_nvlist_destroy(elems[i], nva ? FM_NVA_RETAIN : FM_NVA_FREE);
}

/*
 * cms_ereport_add_logout entry point
 */
/*ARGSUSED*/
void
authamd_ereport_add_logout(cmi_hdl_t hdl, nvlist_t *ereport, nv_alloc_t *nva,
    int bank, uint64_t status, uint64_t addr, uint64_t misc,
    void *mslogout, cms_cookie_t mscookie)
{
	authamd_data_t *authamd = cms_hdl_getcmsdata(hdl);
	const authamd_error_disp_t *aed = mscookie;
	uint64_t members;

	if (aed == NULL)
		return;

	members = aed->aad_ereport_members;

	if (members & FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYND) {
		fm_payload_set(ereport, FM_EREPORT_GENAMD_PAYLOAD_NAME_SYND,
		    DATA_TYPE_UINT16, (uint16_t)AMD_BANK_SYND(status),
		    NULL);

		if (members & FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYNDTYPE) {
			fm_payload_set(ereport,
			    FM_EREPORT_GENAMD_PAYLOAD_NAME_SYNDTYPE,
			    DATA_TYPE_STRING, "E",
			    NULL);
		}
	}

	if (members & FM_EREPORT_GENAMD_PAYLOAD_FLAG_CKSYND) {
		fm_payload_set(ereport, FM_EREPORT_GENAMD_PAYLOAD_NAME_CKSYND,
		    DATA_TYPE_UINT16, (uint16_t)AMD_NB_STAT_CKSYND(status),
		    NULL);

		if (members & FM_EREPORT_GENAMD_PAYLOAD_FLAG_SYNDTYPE) {
			fm_payload_set(ereport,
			    FM_EREPORT_GENAMD_PAYLOAD_NAME_SYNDTYPE,
			    DATA_TYPE_STRING, "C",
			    NULL);
		}
	}

	if (members & FM_EREPORT_GENAMD_PAYLOAD_FLAG_RESOURCE &&
	    status & MSR_MC_STATUS_ADDRV) {
		authamd_ereport_add_resource(hdl, authamd, ereport, nva,
		    mslogout);
	}
}

/*
 * cms_msrinject entry point
 */
cms_errno_t
authamd_msrinject(cmi_hdl_t hdl, uint_t msr, uint64_t val)
{
	authamd_data_t *authamd = cms_hdl_getcmsdata(hdl);
	cms_errno_t rv = CMSERR_BADMSRWRITE;

	authamd_bankstatus_prewrite(hdl, authamd);
	if (cmi_hdl_wrmsr(hdl, msr, val) == CMI_SUCCESS)
		rv = CMS_SUCCESS;
	authamd_bankstatus_postwrite(hdl, authamd);

	return (rv);
}

cms_api_ver_t _cms_api_version = CMS_API_VERSION_0;

const cms_ops_t _cms_ops = {
	authamd_init,			/* cms_init */
	NULL,				/* cms_post_startup */
	NULL,				/* cms_post_mpstartup */
	authamd_logout_size,		/* cms_logout_size */
	authamd_mcgctl_val,		/* cms_mcgctl_val */
	authamd_bankctl_skipinit,	/* cms_bankctl_skipinit */
	authamd_bankctl_val,		/* cms_bankctl_val */
	NULL,				/* cms_bankstatus_skipinit */
	NULL,				/* cms_bankstatus_val */
	authamd_mca_init,		/* cms_mca_init */
	authamd_poll_ownermask,		/* cms_poll_ownermask */
	authamd_bank_logout,		/* cms_bank_logout */
	authamd_error_action,		/* cms_error_action */
	authamd_disp_match,		/* cms_disp_match */
	authamd_ereport_class,		/* cms_ereport_class */
	NULL,				/* cms_ereport_detector */
	NULL,				/* cms_ereport_includestack */
	authamd_ereport_add_logout,	/* cms_ereport_add_logout */
	authamd_msrinject,		/* cms_msrinject */
	NULL,				/* cms_fini */
};

static struct modlcpu modlcpu = {
	&mod_cpuops,
	"Generic AMD model-specific MCA"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcpu,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
