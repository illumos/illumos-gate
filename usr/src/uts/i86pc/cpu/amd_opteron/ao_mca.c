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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/pci_impl.h>
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/chip.h>
#include <sys/cyclic.h>
#include <sys/cpu_module_impl.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/sysevent.h>
#include <sys/smbios.h>
#include <sys/mca_x86.h>
#include <sys/mca_amd.h>
#include <sys/mc.h>
#include <sys/mc_amd.h>
#include <sys/psw.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sdt.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/fm/cpu/AMD.h>
#include <sys/acpi/acpi.h>
#include <sys/acpi/acpi_pci.h>
#include <sys/acpica.h>

#include "ao.h"
#include "ao_mca_disp.h"

#define	AO_REVS_FG (X86_CHIPREV_AMD_F_REV_F | X86_CHIPREV_AMD_F_REV_G)

errorq_t *ao_mca_queue;			/* machine-check ereport queue */
int ao_mca_stack_flag = 0;		/* record stack trace in ereports */
int ao_mca_smi_disable = 1;		/* attempt to disable SMI polling */

ao_bank_regs_t ao_bank_regs[AMD_MCA_BANK_COUNT] = {
	{ AMD_MSR_DC_STATUS, AMD_MSR_DC_ADDR, AMD_MSR_DC_MISC },
	{ AMD_MSR_IC_STATUS, AMD_MSR_IC_ADDR, AMD_MSR_IC_MISC },
	{ AMD_MSR_BU_STATUS, AMD_MSR_BU_ADDR, AMD_MSR_BU_MISC },
	{ AMD_MSR_LS_STATUS, AMD_MSR_LS_ADDR, AMD_MSR_LS_MISC },
	{ AMD_MSR_NB_STATUS, AMD_MSR_NB_ADDR, AMD_MSR_NB_MISC }
};

struct ao_ctl_init {
	uint32_t ctl_revmask;	/* rev(s) to which this applies */
	uint64_t ctl_bits;	/* mca ctl reg bitmask to set */
};

/*
 * Additional NB MCA ctl initialization for revs F and G
 */
static const struct ao_ctl_init ao_nb_ctl_init[] = {
	{ AO_REVS_FG, AMD_NB_CTL_INIT_REV_FG },
	{ X86_CHIPREV_UNKNOWN, 0 }
};

typedef struct ao_bank_cfg {
	uint_t bank_ctl;
	uint_t bank_ctl_mask;
	uint64_t bank_ctl_init_cmn;			/* Common init value */
	const struct ao_ctl_init *bank_ctl_init_extra;	/* Extra for each rev */
	void (*bank_misc_initfunc)(ao_data_t *, uint32_t);
	uint_t bank_status;
	uint_t bank_addr;
} ao_bank_cfg_t;

static void nb_mcamisc_init(ao_data_t *, uint32_t);

static const ao_bank_cfg_t ao_bank_cfgs[] = {
	{ AMD_MSR_DC_CTL, AMD_MSR_DC_MASK, AMD_DC_CTL_INIT_CMN,
	    NULL, NULL, AMD_MSR_DC_STATUS, AMD_MSR_DC_ADDR },
	{ AMD_MSR_IC_CTL, AMD_MSR_IC_MASK, AMD_IC_CTL_INIT_CMN,
	    NULL, NULL, AMD_MSR_IC_STATUS, AMD_MSR_IC_ADDR },
	{ AMD_MSR_BU_CTL, AMD_MSR_BU_MASK, AMD_BU_CTL_INIT_CMN,
	    NULL, NULL, AMD_MSR_BU_STATUS, AMD_MSR_BU_ADDR },
	{ AMD_MSR_LS_CTL, AMD_MSR_LS_MASK, AMD_LS_CTL_INIT_CMN,
	    NULL, NULL, AMD_MSR_LS_STATUS, AMD_MSR_LS_ADDR },
	{ AMD_MSR_NB_CTL, AMD_MSR_NB_MASK, AMD_NB_CTL_INIT_CMN,
	    &ao_nb_ctl_init[0], nb_mcamisc_init,
	    AMD_MSR_NB_STATUS, AMD_MSR_NB_ADDR }
};

static const ao_error_disp_t ao_disp_unknown = {
	FM_EREPORT_CPU_AMD_UNKNOWN,
	FM_EREPORT_PAYLOAD_FLAGS_CPU_AMD_UNKNOWN
};

/*
 * This is quite awful but necessary to work around x86 system vendor's view of
 * the world.  Other operating systems (you know who you are) don't understand
 * Opteron-specific error handling, so BIOS and system vendors often hide these
 * conditions from them by using SMI polling to copy out any errors from the
 * machine-check registers.  When Solaris runs on a system with this feature,
 * we want to disable the SMI polling so we can use FMA instead.  Sadly, there
 * isn't even a standard self-describing way to express the whole situation,
 * so we have to resort to hard-coded values.  This should all be changed to
 * be a self-describing vendor-specific SMBIOS structure in the future.
 */
static const struct ao_smi_disable {
	const char *asd_sys_vendor;	/* SMB_TYPE_SYSTEM vendor prefix */
	const char *asd_sys_product;	/* SMB_TYPE_SYSTEM product prefix */
	const char *asd_bios_vendor;	/* SMB_TYPE_BIOS vendor prefix */
	uint8_t asd_code;		/* output code for SMI disable */
} ao_smi_disable[] = {
	{ "Sun Microsystems", "Galaxy12",
	    "American Megatrends", 0x59 },
	{ "Sun Microsystems", "Sun Fire X4100 Server",
	    "American Megatrends", 0x59 },
	{ "Sun Microsystems", "Sun Fire X4200 Server",
	    "American Megatrends", 0x59 },
	{ NULL, NULL, NULL, 0 }
};

static int
ao_disp_match_r4(uint16_t ref, uint8_t r4)
{
	static const uint16_t ao_r4_map[] = {
		AO_MCA_R4_BIT_GEN,	/* AMD_ERRCODE_R4_GEN */
		AO_MCA_R4_BIT_RD,	/* AMD_ERRCODE_R4_RD */
		AO_MCA_R4_BIT_WR,	/* AMD_ERRCODE_R4_WR */
		AO_MCA_R4_BIT_DRD,	/* AMD_ERRCODE_R4_DRD */
		AO_MCA_R4_BIT_DWR,	/* AMD_ERRCODE_R4_DWR */
		AO_MCA_R4_BIT_IRD,	/* AMD_ERRCODE_R4_IRD */
		AO_MCA_R4_BIT_PREFETCH,	/* AMD_ERRCODE_R4_PREFETCH */
		AO_MCA_R4_BIT_EVICT,	/* AMD_ERRCODE_R4_EVICT */
		AO_MCA_R4_BIT_SNOOP	/* AMD_ERRCODE_R4_SNOOP */
	};

	ASSERT(r4 < sizeof (ao_r4_map) / sizeof (uint16_t));

	return ((ref & ao_r4_map[r4]) != 0);
}

static int
ao_disp_match_pp(uint8_t ref, uint8_t pp)
{
	static const uint8_t ao_pp_map[] = {
		AO_MCA_PP_BIT_SRC,	/* AMD_ERRCODE_PP_SRC */
		AO_MCA_PP_BIT_RSP,	/* AMD_ERRCODE_PP_RSP */
		AO_MCA_PP_BIT_OBS,	/* AMD_ERRCODE_PP_OBS */
		AO_MCA_PP_BIT_GEN	/* AMD_ERRCODE_PP_GEN */
	};

	ASSERT(pp < sizeof (ao_pp_map) / sizeof (uint8_t));

	return ((ref & ao_pp_map[pp]) != 0);
}

static int
ao_disp_match_ii(uint8_t ref, uint8_t ii)
{
	static const uint8_t ao_ii_map[] = {
		AO_MCA_II_BIT_MEM,	/* AMD_ERRCODE_II_MEM */
		0,
		AO_MCA_II_BIT_IO,	/* AMD_ERRCODE_II_IO */
		AO_MCA_II_BIT_GEN	/* AMD_ERRCODE_II_GEN */
	};

	ASSERT(ii < sizeof (ao_ii_map) / sizeof (uint8_t));

	return ((ref & ao_ii_map[ii]) != 0);
}

static uint8_t
bit_strip(uint16_t *codep, uint16_t mask, uint16_t shift)
{
	uint8_t val = (*codep & mask) >> shift;
	*codep &= ~mask;
	return (val);
}

#define	BIT_STRIP(codep, name) \
	bit_strip(codep, AMD_ERRCODE_##name##_MASK, AMD_ERRCODE_##name##_SHIFT)

static int
ao_disp_match_one(const ao_error_disp_t *aed, uint64_t status, uint32_t rev,
    int bankno)
{
	uint16_t code = status & AMD_ERRCODE_MASK;
	uint8_t extcode = (status & AMD_ERREXT_MASK) >> AMD_ERREXT_SHIFT;
	uint64_t stat_mask = aed->aed_stat_mask;
	uint64_t stat_mask_res = aed->aed_stat_mask_res;

	/*
	 * If the bank's status register indicates overflow, then we can no
	 * longer rely on the value of CECC: our experience with actual fault
	 * injection has shown that multiple CE's overwriting each other shows
	 * AMD_BANK_STAT_CECC and AMD_BANK_STAT_UECC both set to zero.  This
	 * should be clarified in a future BKDG or by the Revision Guide.
	 * This behaviour is fixed in revision F.
	 */
	if (bankno == AMD_MCA_BANK_NB &&
	    !X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_F) &&
	    status & AMD_BANK_STAT_OVER) {
		stat_mask &= ~AMD_BANK_STAT_CECC;
		stat_mask_res &= ~AMD_BANK_STAT_CECC;
	}

	if ((status & stat_mask) != stat_mask_res)
		return (0);

	/*
	 * r4 and pp bits are stored separately, so we mask off and compare them
	 * for the code types that use them.  Once we've taken the r4 and pp
	 * bits out of the equation, we can directly compare the resulting code
	 * with the one stored in the ao_error_disp_t.
	 */
	if (AMD_ERRCODE_ISMEM(code)) {
		uint8_t r4 = BIT_STRIP(&code, R4);

		if (!ao_disp_match_r4(aed->aed_stat_r4_bits, r4))
			return (0);

	} else if (AMD_ERRCODE_ISBUS(code)) {
		uint8_t r4 = BIT_STRIP(&code, R4);
		uint8_t pp = BIT_STRIP(&code, PP);
		uint8_t ii = BIT_STRIP(&code, II);

		if (!ao_disp_match_r4(aed->aed_stat_r4_bits, r4) ||
		    !ao_disp_match_pp(aed->aed_stat_pp_bits, pp) ||
		    !ao_disp_match_ii(aed->aed_stat_ii_bits, ii))
			return (0);
	}

	return (code == aed->aed_stat_code && extcode == aed->aed_stat_extcode);
}

static const ao_error_disp_t *
ao_disp_match(uint_t bankno, uint64_t status, uint32_t rev)
{
	const ao_error_disp_t *aed;

	for (aed = ao_error_disp[bankno]; aed->aed_stat_mask != 0; aed++) {
		if (ao_disp_match_one(aed, status, rev, bankno))
			return (aed);
	}

	return (&ao_disp_unknown);
}

void
ao_pcicfg_write(uint_t chipid, uint_t func, uint_t reg, uint32_t val)
{
	ASSERT(chipid + 24 <= 31);
	ASSERT((func & 7) == func);
	ASSERT((reg & 3) == 0 && reg < 256);

	pci_mech1_putl(0, chipid + 24, func, reg, val);
}

uint32_t
ao_pcicfg_read(uint_t chipid, uint_t func, uint_t reg)
{
	ASSERT(chipid + 24 <= 31);
	ASSERT((func & 7) == func);
	ASSERT((reg & 3) == 0 && reg < 256);

	return (pci_mech1_getl(0, chipid + 24, func, reg));
}

/*
 * ao_chip_once returns 1 if the caller should perform the operation for
 * this chip, or 0 if some other core has already performed the operation.
 */

int
ao_chip_once(ao_data_t *ao, enum ao_cfgonce_bitnum what)
{
	return (atomic_set_long_excl(&ao->ao_shared->aos_cfgonce, what) == 0 ?
	    1 : 0);
}

/*
 * Setup individual bank detectors after stashing their bios settings.
 * The 'donb' argument indicates whether this core should configured
 * the shared NorthBridhe MSRs.
 */
static void
ao_bank_cfg(ao_data_t *ao, uint32_t rev, int donb)
{
	ao_mca_t *mca = &ao->ao_mca;
	struct ao_chipshared *aos = ao->ao_shared;
	ao_bios_cfg_t *bcfg = &mca->ao_mca_bios_cfg;
	const ao_bank_cfg_t *bankcfg = ao_bank_cfgs;
	const struct ao_ctl_init *extrap;
	uint64_t mcictl;
	int i;

	for (i = 0; i < AMD_MCA_BANK_COUNT; i++, bankcfg++) {
		if (i == AMD_MCA_BANK_NB && donb == 0) {
			bcfg->bcfg_bank_ctl[i] = 0xbaddcafe;
			bcfg->bcfg_bank_mask[i] = 0xbaddcafe;
			continue;
		} else  if (i == AMD_MCA_BANK_NB) {
			aos->aos_bcfg_nb_ctl = rdmsr(bankcfg->bank_ctl);
			aos->aos_bcfg_nb_mask = rdmsr(bankcfg->bank_ctl_mask);
		} else {
			bcfg->bcfg_bank_ctl[i] = rdmsr(bankcfg->bank_ctl);
			bcfg->bcfg_bank_mask[i] = rdmsr(bankcfg->bank_ctl_mask);
		}

		/* Initialize MCi_CTL register for this bank */
		mcictl = bankcfg->bank_ctl_init_cmn;
		if ((extrap = bankcfg->bank_ctl_init_extra) != NULL) {
			while (extrap->ctl_revmask != X86_CHIPREV_UNKNOWN) {
				if (X86_CHIPREV_MATCH(rev, extrap->ctl_revmask))
					mcictl |= extrap->ctl_bits;
				extrap++;
			}
		}
		wrmsr(bankcfg->bank_ctl, mcictl);

		/* Initialize the MCi_MISC register for this bank */
		if (bankcfg->bank_misc_initfunc != NULL)
			(bankcfg->bank_misc_initfunc)(ao, rev);
	}
}

/*
 * This knob exists in case any platform has a problem with our default
 * policy of disabling any interrupt registered in the NB MC4_MISC
 * register.  Setting this may cause Solaris and external entities
 * who also have an interest in this register to argue over available
 * telemetry (so setting it is generally not recommended).
 */
int ao_nb_cfg_mc4misc_noseize = 0;

/*
 * The BIOS may have setup to receive SMI on counter overflow.  It may also
 * have locked various fields or made them read-only.  We will clear any
 * SMI request and leave the register locked.  We will also clear the
 * counter and enable counting - while we don't use the counter it is nice
 * to have it enabled for verification and debug work.
 */
static void
nb_mcamisc_init(ao_data_t *ao, uint32_t rev)
{
	uint64_t hwcr, oldhwcr;
	uint64_t val;
	int locked;

	if (!X86_CHIPREV_MATCH(rev, AO_REVS_FG))
		return;

	ao->ao_shared->aos_bcfg_nb_misc = val = rdmsr(AMD_MSR_NB_MISC);

	if (ao_nb_cfg_mc4misc_noseize)
		return;		/* stash BIOS value, but no changes */

	locked = val & AMD_NB_MISC_LOCKED;

	/*
	 * The Valid bit tells us whether the CtrP bit is defined; if it
	 * is the CtrP bit tells us whether an ErrCount field is present.
	 * If not then there is nothing for us to do.
	 */
	if (!(val & AMD_NB_MISC_VALID) || !(val & AMD_NB_MISC_CTRP))
		return;

	if (locked) {
		oldhwcr = rdmsr(MSR_AMD_HWCR);
		hwcr = oldhwcr | AMD_HWCR_MCI_STATUS_WREN;
		wrmsr(MSR_AMD_HWCR, hwcr);
	}

	val |= AMD_NB_MISC_CNTEN;		/* enable ECC error counting */
	val &= ~AMD_NB_MISC_ERRCOUNT_MASK;	/* clear ErrCount */
	val &= ~AMD_NB_MISC_OVRFLW;		/* clear Ovrflw */
	val &= ~AMD_NB_MISC_INTTYPE_MASK;	/* no interrupt on overflow */
	val |= AMD_NB_MISC_LOCKED;

	wrmsr(AMD_MSR_NB_MISC, val);

	if (locked)
		wrmsr(MSR_AMD_HWCR, oldhwcr);
}

/*
 * NorthBridge (NB) Configuration.
 *
 * We add and remove bits from the BIOS-configured value, rather than
 * writing an absolute value.  The variables ao_nb_cfg_{add,remove}_cmn and
 * ap_nb_cfg_{add,remove}_revFG are available for modification via kmdb
 * and /etc/system.  The revision-specific adds and removes are applied
 * after the common changes, and one write is made to the config register.
 * These are not intended for watchdog configuration via these variables -
 * use the watchdog policy below.
 */

/*
 * Bits to be added to the NB configuration register - all revs.
 */
uint32_t ao_nb_cfg_add_cmn = AMD_NB_CFG_ADD_CMN;

/*
 * Bits to be cleared from the NB configuration register - all revs.
 */
uint32_t ao_nb_cfg_remove_cmn = AMD_NB_CFG_REMOVE_CMN;

/*
 * Bits to be added to the NB configuration register - revs F and G.
 */
uint32_t ao_nb_cfg_add_revFG = AMD_NB_CFG_ADD_REV_FG;

/*
 * Bits to be cleared from the NB configuration register - revs F and G.
 */
uint32_t ao_nb_cfg_remove_revFG = AMD_NB_CFG_REMOVE_REV_FG;

struct ao_nb_cfg {
	uint32_t cfg_revmask;
	uint32_t *cfg_add_p;
	uint32_t *cfg_remove_p;
};

static const struct ao_nb_cfg ao_cfg_extra[] = {
	{ AO_REVS_FG, &ao_nb_cfg_add_revFG, &ao_nb_cfg_remove_revFG },
	{ X86_CHIPREV_UNKNOWN, NULL, NULL }
};

/*
 * Bits to be used if we configure the NorthBridge (NB) Watchdog.  The watchdog
 * triggers a machine check exception when no response to an NB system access
 * occurs within a specified time interval.
 */
uint32_t ao_nb_cfg_wdog =
    AMD_NB_CFG_WDOGTMRCNTSEL_4095 |
    AMD_NB_CFG_WDOGTMRBASESEL_1MS;

/*
 * The default watchdog policy is to enable it (at the above rate) if it
 * is disabled;  if it is enabled then we leave it enabled at the rate
 * chosen by the BIOS.
 */
enum {
	AO_NB_WDOG_LEAVEALONE,		/* Don't touch watchdog config */
	AO_NB_WDOG_DISABLE,		/* Always disable watchdog */
	AO_NB_WDOG_ENABLE_IF_DISABLED,	/* If disabled, enable at our rate */
	AO_NB_WDOG_ENABLE_FORCE_RATE	/* Enable and set our rate */
} ao_nb_watchdog_policy = AO_NB_WDOG_ENABLE_IF_DISABLED;

static void
ao_nb_cfg(ao_data_t *ao, uint32_t rev)
{
	const struct ao_nb_cfg *nbcp = &ao_cfg_extra[0];
	uint_t chipid = chip_plat_get_chipid(CPU);
	uint32_t val;

	/*
	 * Read the NorthBridge (NB) configuration register in PCI space,
	 * modify the settings accordingly, and store the new value back.
	 */
	ao->ao_shared->aos_bcfg_nb_cfg = val =
	    ao_pcicfg_read(chipid, AMD_NB_FUNC, AMD_NB_REG_CFG);

	switch (ao_nb_watchdog_policy) {
	case AO_NB_WDOG_LEAVEALONE:
		break;

	case AO_NB_WDOG_DISABLE:
		val &= ~AMD_NB_CFG_WDOGTMRBASESEL_MASK;
		val &= ~AMD_NB_CFG_WDOGTMRCNTSEL_MASK;
		val |= AMD_NB_CFG_WDOGTMRDIS;
		break;

	default:
		cmn_err(CE_NOTE, "ao_nb_watchdog_policy=%d unrecognised, "
		    "using default policy", ao_nb_watchdog_policy);
		/*FALLTHRU*/

	case AO_NB_WDOG_ENABLE_IF_DISABLED:
		if (val & AMD_NB_CFG_WDOGTMRDIS)
			break;	/* if enabled leave rate intact */
		/*FALLTHRU*/

	case AO_NB_WDOG_ENABLE_FORCE_RATE:
		val &= ~AMD_NB_CFG_WDOGTMRBASESEL_MASK;
		val &= ~AMD_NB_CFG_WDOGTMRCNTSEL_MASK;
		val &= ~AMD_NB_CFG_WDOGTMRDIS;
		val |= ao_nb_cfg_wdog;
		break;
	}

	/*
	 * Now apply bit adds and removes, first those common to all revs
	 * and then the revision-specific ones.
	 */
	val &= ~ao_nb_cfg_remove_cmn;
	val |= ao_nb_cfg_add_cmn;

	while (nbcp->cfg_revmask != X86_CHIPREV_UNKNOWN) {
		if (X86_CHIPREV_MATCH(rev, nbcp->cfg_revmask)) {
			val &= ~(*nbcp->cfg_remove_p);
			val |= *nbcp->cfg_add_p;
		}
		nbcp++;
	}

	ao_pcicfg_write(chipid, AMD_NB_FUNC, AMD_NB_REG_CFG, val);
}

/*
 * This knob exists in case any platform has a problem with our default
 * policy of disabling any interrupt registered in the online spare
 * control register.  Setting this may cause Solaris and external entities
 * who also have an interest in this register to argue over available
 * telemetry (so setting it is generally not recommended).
 */
int ao_nb_cfg_sparectl_noseize = 0;

/*
 * Setup the online spare control register (revs F and G).  We disable
 * any interrupt registered by the BIOS and zero all error counts.
 */
static void
ao_sparectl_cfg(ao_data_t *ao)
{
	uint_t chipid = chip_plat_get_chipid(CPU);
	union mcreg_sparectl sparectl;
	int chan, cs;

	ao->ao_shared->aos_bcfg_nb_sparectl = MCREG_VAL32(&sparectl) =
	    ao_pcicfg_read(chipid, AMD_NB_FUNC, AMD_NB_REG_SPARECTL);

	if (ao_nb_cfg_sparectl_noseize)
		return;	/* stash BIOS value, but no changes */

	/*
	 * If the BIOS has requested SMI interrupt type for ECC count
	 * overflow for a chip-select or channel force those off.
	 */
	MCREG_FIELD_revFG(&sparectl, EccErrInt) = 0;
	MCREG_FIELD_revFG(&sparectl, SwapDoneInt) = 0;

	/* Enable writing to the EccErrCnt field */
	MCREG_FIELD_revFG(&sparectl, EccErrCntWrEn) = 1;

	/* First write, preparing for writes to EccErrCnt */
	ao_pcicfg_write(chipid, AMD_NB_FUNC, AMD_NB_REG_SPARECTL,
	    MCREG_VAL32(&sparectl));

	/*
	 * Zero EccErrCnt and write this back to all chan/cs combinations.
	 */
	MCREG_FIELD_revFG(&sparectl, EccErrCnt) = 0;
	for (chan = 0; chan < MC_CHIP_NDRAMCHAN; chan++) {
		MCREG_FIELD_revFG(&sparectl, EccErrCntDramChan) = chan;

		for (cs = 0; cs < MC_CHIP_NCS; cs++) {
			MCREG_FIELD_revFG(&sparectl, EccErrCntDramCs) = cs;
			ao_pcicfg_write(chipid, AMD_NB_FUNC,
			    AMD_NB_REG_SPARECTL, MCREG_VAL32(&sparectl));
		}
	}
}

/*
 * Capture the machine-check exception state into our per-CPU logout area, and
 * dispatch a copy of the logout area to our error queue for ereport creation.
 * If 'rp' is non-NULL, we're being called from trap context; otherwise we're
 * being polled or poked by the injector.  We return the number of errors
 * found through 'np', and a boolean indicating whether the error is fatal.
 * The caller is expected to call fm_panic() if we return fatal (non-zero).
 */
int
ao_mca_logout(ao_cpu_logout_t *acl, struct regs *rp, int *np, int skipnb,
    uint32_t rev)
{
	uint64_t mcg_status = rdmsr(IA32_MSR_MCG_STATUS);
	int i, fatal = 0, n = 0;

	acl->acl_timestamp = gethrtime_waitfree();
	acl->acl_mcg_status = mcg_status;
	acl->acl_ip = rp ? rp->r_pc : 0;
	acl->acl_flags = 0;

	/*
	 * Iterate over the banks of machine-check registers, read the address
	 * and status registers into the logout area, and clear status as we go.
	 * Also read the MCi_MISC register if MCi_STATUS.MISCV indicates that
	 * there is valid info there (as it will in revisions F and G for
	 * NorthBridge ECC errors).
	 */
	for (i = 0; i < AMD_MCA_BANK_COUNT; i++) {
		ao_bank_logout_t *abl = &acl->acl_banks[i];

		if (i == AMD_MCA_BANK_NB && skipnb) {
			abl->abl_status = 0;
			continue;
		}

		abl->abl_addr = rdmsr(ao_bank_regs[i].abr_addr);
		abl->abl_status = rdmsr(ao_bank_regs[i].abr_status);

		if (abl->abl_status & AMD_BANK_STAT_MISCV)
			abl->abl_misc = rdmsr(ao_bank_regs[i].abr_misc);
		else
			abl->abl_misc = 0;

		if (abl->abl_status & AMD_BANK_STAT_VALID)
			wrmsr(ao_bank_regs[i].abr_status, 0);
	}

	if (rp == NULL || !USERMODE(rp->r_cs))
		acl->acl_flags |= AO_ACL_F_PRIV;

	if (ao_mca_stack_flag)
		acl->acl_stackdepth = getpcstack(acl->acl_stack, FM_STK_DEPTH);
	else
		acl->acl_stackdepth = 0;

	/*
	 * Clear MCG_STATUS, indicating that machine-check trap processing is
	 * complete.  Once we do this, another machine-check trap can occur
	 * (if another occurs up to this point then the system will reset).
	 */
	if (mcg_status & MCG_STATUS_MCIP)
		wrmsr(IA32_MSR_MCG_STATUS, 0);

	/*
	 * If we took a machine-check trap, then the error is fatal if the
	 * return instruction pointer is not valid in the global register.
	 */
	if (rp != NULL && !(acl->acl_mcg_status & MCG_STATUS_RIPV))
		fatal++;

	/*
	 * Now iterate over the saved logout area, determining whether the
	 * error that we saw is fatal or not based upon our dispositions
	 * and the hardware's indicators of whether or not we can resume.
	 */
	for (i = 0; i < AMD_MCA_BANK_COUNT; i++) {
		ao_bank_logout_t *abl = &acl->acl_banks[i];
		const ao_error_disp_t *aed;
		uint8_t when;

		if (!(abl->abl_status & AMD_BANK_STAT_VALID))
			continue;

		aed = ao_disp_match(i, abl->abl_status, rev);
		if ((when = aed->aed_panic_when) != AO_AED_PANIC_NEVER) {
			if ((when & AO_AED_PANIC_ALWAYS) ||
			    ((when & AO_AED_PANIC_IFMCE) && rp != NULL)) {
					fatal++;
			}
		}

		/*
		 * If we are taking a machine-check exception and our context
		 * is corrupt, then we must die.
		 */
		if (rp != NULL && abl->abl_status & AMD_BANK_STAT_PCC)
			fatal++;

		/*
		 * The overflow bit is set if the bank detects an error but
		 * the valid bit of its status register is already set
		 * (software has not yet read and cleared it).  Enabled
		 * (for mc# reporting) errors overwrite disabled errors,
		 * uncorrectable errors overwrite correctable errors,
		 * uncorrectable errors are not overwritten.
		 *
		 * For the NB detector bank the overflow bit will not be
		 * set for repeated correctable errors on revisions D and
		 * earlier; it will be set on revisions E and later.
		 * On revision E, however, the CorrECC bit does appear
		 * to clear in these circumstances.  Since we can enable
		 * machine-check exception on NB correctables we need to
		 * be careful here; we never enable mc# for correctable from
		 * other banks.
		 *
		 * Our solution will be to declare a machine-check exception
		 * fatal if the overflow bit is set except in the case of
		 * revision F on the NB detector bank for which CorrECC
		 * is indicated.  Machine-check exception for NB correctables
		 * on rev E is explicitly not supported.
		 */
		if (rp != NULL && abl->abl_status & AMD_BANK_STAT_OVER &&
		    !(i == AMD_MCA_BANK_NB &&
		    X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_F) &&
		    abl->abl_status & AMD_BANK_STAT_CECC))
			fatal++;

		/*
		 * If we are taking a machine-check exception and we don't
		 * recognize the error case at all, then assume it's fatal.
		 * This will need to change if we eventually use the Opteron
		 * Rev E exception mechanism for detecting correctable errors.
		 */
		if (rp != NULL && aed == &ao_disp_unknown)
			fatal++;

		abl->abl_addr_type = aed->aed_flags & AO_AED_FLAGS_ADDRTYPE;
		abl->abl_addr_valid_hi = aed->aed_addrvalid_hi;
		abl->abl_addr_valid_lo = aed->aed_addrvalid_lo;
		n++;
	}

	if (n > 0) {
		errorq_dispatch(ao_mca_queue, acl, sizeof (ao_cpu_logout_t),
		    fatal && cmi_panic_on_uncorrectable_error ?
		    ERRORQ_SYNC : ERRORQ_ASYNC);
	}

	if (np != NULL)
		*np = n; /* return number of errors found to caller */

	return (fatal != 0);
}

static uint_t
ao_ereport_synd(ao_data_t *ao, const ao_bank_logout_t *abl, uint_t *typep,
    int is_nb)
{
	if (is_nb) {
		if (ao->ao_shared->aos_bcfg_nb_cfg & AMD_NB_CFG_CHIPKILLECCEN) {
			*typep = AMD_SYNDTYPE_CHIPKILL;
			return (AMD_NB_STAT_CKSYND(abl->abl_status));
		} else {
			*typep = AMD_SYNDTYPE_ECC;
			return (AMD_BANK_SYND(abl->abl_status));
		}
	} else {
		*typep = AMD_SYNDTYPE_ECC;
		return (AMD_BANK_SYND(abl->abl_status));
	}
}

static void
ao_ereport_create_resource_elem(nvlist_t **nvlp, nv_alloc_t *nva,
    mc_unum_t *unump, int dimmnum)
{
	nvlist_t *snvl;
	*nvlp = fm_nvlist_create(nva);		/* freed by caller */

	snvl = fm_nvlist_create(nva);

	(void) nvlist_add_uint64(snvl, FM_FMRI_HC_SPECIFIC_OFFSET,
	    unump->unum_offset);

	fm_fmri_hc_set(*nvlp, FM_HC_SCHEME_VERSION, NULL, snvl, 5,
	    "motherboard", unump->unum_board,
	    "chip", unump->unum_chip,
	    "memory-controller", unump->unum_mc,
	    "dimm", unump->unum_dimms[dimmnum],
	    "rank", unump->unum_rank);

	fm_nvlist_destroy(snvl, nva ? FM_NVA_RETAIN : FM_NVA_FREE);
}

static void
ao_ereport_add_resource(nvlist_t *payload, nv_alloc_t *nva, mc_unum_t *unump)
{

	nvlist_t *elems[MC_UNUM_NDIMM];
	int nelems = 0;
	int i;

	for (i = 0; i < MC_UNUM_NDIMM; i++) {
		if (unump->unum_dimms[i] == MC_INVALNUM)
			break;
		ao_ereport_create_resource_elem(&elems[nelems++], nva,
		    unump, i);
	}

	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RESOURCE,
	    DATA_TYPE_NVLIST_ARRAY, nelems, elems, NULL);

	for (i = 0; i < nelems; i++)
		fm_nvlist_destroy(elems[i], nva ? FM_NVA_RETAIN : FM_NVA_FREE);
}

static void
ao_ereport_add_logout(ao_data_t *ao, nvlist_t *payload, nv_alloc_t *nva,
    const ao_cpu_logout_t *acl, uint_t bankno, const ao_error_disp_t *aed)
{
	uint64_t members = aed->aed_ereport_members;
	const ao_bank_logout_t *abl = &acl->acl_banks[bankno];
	uint_t synd, syndtype;

	synd = ao_ereport_synd(ao, abl, &syndtype, bankno == AMD_MCA_BANK_NB);

	if (members & FM_EREPORT_PAYLOAD_FLAG_BANK_STAT) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BANK_STAT,
		    DATA_TYPE_UINT64, abl->abl_status, NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_BANK_NUM) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BANK_NUM,
		    DATA_TYPE_UINT8, bankno, NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_ADDR) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ADDR,
		    DATA_TYPE_UINT64, abl->abl_addr, NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_ADDR_VALID) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_ADDR_VALID,
		    DATA_TYPE_BOOLEAN_VALUE, (abl->abl_status &
		    AMD_BANK_STAT_ADDRV) ? B_TRUE : B_FALSE, NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_BANK_MISC) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_BANK_MISC,
		    DATA_TYPE_UINT64, abl->abl_misc, NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_SYND) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SYND,
		    DATA_TYPE_UINT16, synd, NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_SYND_TYPE) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_SYND_TYPE,
		    DATA_TYPE_STRING, (syndtype == AMD_SYNDTYPE_CHIPKILL ?
		    "C" : "E"), NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_IP) {
		uint64_t ip = (acl->acl_mcg_status & MCG_STATUS_EIPV) ?
		    acl->acl_ip : 0;
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_IP,
		    DATA_TYPE_UINT64, ip, NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_PRIV) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_PRIV,
		    DATA_TYPE_BOOLEAN_VALUE, (acl->acl_flags & AO_ACL_F_PRIV) ?
		    B_TRUE : B_FALSE, NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_RESOURCE) {
		mc_unum_t unum;
		int addrvalid = 0;

		if (abl->abl_addr_type & AO_AED_F_PHYSICAL) {
			addrvalid = (members & FM_EREPORT_PAYLOAD_FLAG_ADDR) &&
			    (members & FM_EREPORT_PAYLOAD_FLAG_ADDR_VALID) &&
			    (abl->abl_status & AMD_BANK_STAT_ADDRV);
		}

		if (addrvalid && ao_mc_patounum(ao, abl->abl_addr,
		    abl->abl_addr_valid_hi, abl->abl_addr_valid_lo,
		    synd, syndtype, &unum))
			ao_ereport_add_resource(payload, nva, &unum);
	}

	if (ao_mca_stack_flag && members & FM_EREPORT_PAYLOAD_FLAG_STACK) {
		fm_payload_stack_add(payload, acl->acl_stack,
		    acl->acl_stackdepth);
	}
}

static void
ao_ereport_post(const ao_cpu_logout_t *acl,
    int bankno, const ao_error_disp_t *aed)
{
	ao_data_t *ao = acl->acl_ao;
	errorq_elem_t *eqep, *scr_eqep;
	nvlist_t *ereport, *detector;
	nv_alloc_t *nva = NULL;
	char buf[FM_MAX_CLASS];

	if (panicstr) {
		if ((eqep = errorq_reserve(ereport_errorq)) == NULL)
			return;
		ereport = errorq_elem_nvl(ereport_errorq, eqep);

		/*
		 * Now try to allocate another element for scratch space and
		 * use that for further scratch space (eg for constructing
		 * nvlists to add the main ereport).  If we can't reserve
		 * a scratch element just fallback to working within the
		 * element we already have, and hope for the best.  All this
		 * is necessary because the fixed buffer nv allocator does
		 * not reclaim freed space and nvlist construction is
		 * expensive.
		 */
		if ((scr_eqep = errorq_reserve(ereport_errorq)) != NULL)
			nva = errorq_elem_nva(ereport_errorq, scr_eqep);
		else
			nva = errorq_elem_nva(ereport_errorq, eqep);
	} else {
		ereport = fm_nvlist_create(NULL);
	}

	/*
	 * Create the "hc" scheme detector FMRI identifying this cpu
	 */
	detector = ao_fmri_create(ao, nva);

	/*
	 * Encode all the common data into the ereport.
	 */
	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s.%s",
	    FM_ERROR_CPU, "amd", aed->aed_class);

	fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
	    fm_ena_generate_cpu(acl->acl_timestamp, ao->ao_cpu->cpu_id,
	    FM_ENA_FMT1), detector, NULL);

	/*
	 * We're done with 'detector' so reclaim the scratch space.
	 */
	if (panicstr) {
		fm_nvlist_destroy(detector, FM_NVA_RETAIN);
		nv_alloc_reset(nva);
	} else {
		fm_nvlist_destroy(detector, FM_NVA_FREE);
	}

	/*
	 * Encode the error-specific data that was saved in the logout area.
	 */
	ao_ereport_add_logout(ao, ereport, nva, acl, bankno, aed);

	if (panicstr) {
		errorq_commit(ereport_errorq, eqep, ERRORQ_SYNC);
		if (scr_eqep)
			errorq_cancel(ereport_errorq, scr_eqep);
	} else {
		(void) fm_ereport_post(ereport, EVCH_TRYHARD);
		fm_nvlist_destroy(ereport, FM_NVA_FREE);
	}
}

/*ARGSUSED*/
void
ao_mca_drain(void *ignored, const void *data, const errorq_elem_t *eqe)
{
	const ao_cpu_logout_t *acl = data;
	uint32_t rev = acl->acl_ao->ao_shared->aos_chiprev;
	int i;

	for (i = 0; i < AMD_MCA_BANK_COUNT; i++) {
		const ao_bank_logout_t *abl = &acl->acl_banks[i];
		const ao_error_disp_t *aed;

		if (abl->abl_status & AMD_BANK_STAT_VALID) {
			aed = ao_disp_match(i, abl->abl_status, rev);
			ao_ereport_post(acl, i, aed);
		}
	}
}

/*
 * Machine check interrupt handler - we jump here from mcetrap.
 *
 * A sibling core may attempt to poll the NorthBridge during the
 * time we are performing the logout.  So we coordinate NB access
 * of all cores of the same chip via a per-chip lock.  If the lock
 * is held on a sibling core then we spin for it here; if the
 * lock is held by the thread we have interrupted then we do
 * not acquire the lock but can proceed safe in the knowledge that
 * the lock owner can't actually perform any NB accesses.  This
 * requires that threads that take the aos_nb_poll_lock do not
 * block and that they disable preemption while they hold the lock.
 * It also requires that the lock be adaptive since mutex_owner does
 * not work for spin locks.
 */
static int ao_mca_path1, ao_mca_path2;
int
ao_mca_trap(void *data, struct regs *rp)
{
	ao_data_t *ao = data;
	ao_mca_t *mca = &ao->ao_mca;
	ao_cpu_logout_t *acl = &mca->ao_mca_logout[AO_MCA_LOGOUT_EXCEPTION];
	kmutex_t *nblock = NULL;
	int tooklock = 0;
	int rv;

	if (ao->ao_shared != NULL)
		nblock = &ao->ao_shared->aos_nb_poll_lock;

	if (nblock && !mutex_owned(nblock)) {
		/*
		 * The mutex is not owned by the thread we have interrupted
		 * (since the holder may not block or be preempted once the
		 * lock is acquired).  We will spin for this adaptive lock.
		 */
		++ao_mca_path1;
		while (!mutex_tryenter(nblock)) {
			while (mutex_owner(nblock) != NULL)
				;
		}
		tooklock = 1;
	} else {
		++ao_mca_path2;
	}

	rv = ao_mca_logout(acl, rp, NULL, 0, ao->ao_shared->aos_chiprev);

	if (tooklock)
		mutex_exit(&ao->ao_shared->aos_nb_poll_lock);

	return (rv);
}

/*ARGSUSED*/
int
ao_mca_inject(void *data, cmi_mca_regs_t *regs, uint_t nregs)
{
	uint64_t hwcr, oldhwcr;
	int i;

	oldhwcr = rdmsr(MSR_AMD_HWCR);
	hwcr = oldhwcr | AMD_HWCR_MCI_STATUS_WREN;
	wrmsr(MSR_AMD_HWCR, hwcr);

	for (i = 0; i < nregs; i++)
		wrmsr(regs[i].cmr_msrnum, regs[i].cmr_msrval);

	wrmsr(MSR_AMD_HWCR, oldhwcr);
	return (0);
}

void
ao_mca_init(void *data)
{
	ao_data_t *ao = data;
	ao_mca_t *mca = &ao->ao_mca;
	uint64_t cap;
	uint32_t rev;
	int donb;
	int i;

	ASSERT(x86_feature & X86_MCA);
	cap = rdmsr(IA32_MSR_MCG_CAP);
	ASSERT(cap & MCG_CAP_CTL_P);

	/*
	 * If the hardware's bank count is different than what we expect, then
	 * we're running on some Opteron variant that we don't understand yet.
	 */
	if ((cap & MCG_CAP_COUNT_MASK) != AMD_MCA_BANK_COUNT) {
		cmn_err(CE_WARN, "CPU %d has %llu MCA banks; expected %u: "
		    "disabling MCA on this CPU", ao->ao_cpu->cpu_id,
		    (u_longlong_t)cap & MCG_CAP_COUNT_MASK, AMD_MCA_BANK_COUNT);
		return;
	}

	/*
	 * Configure the logout areas.  We preset every logout area's acl_ao
	 * pointer to refer back to our per-CPU state for errorq drain usage.
	 */
	for (i = 0; i < AO_MCA_LOGOUT_NUM; i++)
		mca->ao_mca_logout[i].acl_ao = ao;

	/* LINTED: logical expression always true */
	ASSERT(sizeof (ao_bank_cfgs) / sizeof (ao_bank_cfg_t) ==
	    AMD_MCA_BANK_COUNT);

	rev = ao->ao_shared->aos_chiprev = cpuid_getchiprev(ao->ao_cpu);

	/*
	 * Must this core perform NB MCA configuration?  This must be done
	 * by just one core.
	 */
	donb = ao_chip_once(ao, AO_CFGONCE_NBMCA);

	/*
	 * Initialize poller data, but don't start polling yet.
	 */
	ao_mca_poll_init(ao, donb);

	/*
	 * Configure the bank MCi_CTL register to nominate which error
	 * types for each bank will produce a machine-check (we'll poll
	 * for others).  Correctable error types mentioned in these MCi_CTL
	 * settings won't actually produce an exception unless an additional
	 * (and undocumented) bit is set elsewhere - the poller must still
	 * handle these.
	 */
	ao_bank_cfg(ao, rev, donb);

	/*
	 * Modify the MCA NB Configuration Register.
	 */
	if (donb)
		ao_nb_cfg(ao, rev);

	/*
	 * Setup the Online Spare Control Register
	 */
	if (donb && X86_CHIPREV_MATCH(rev, AO_REVS_FG)) {
		ao_sparectl_cfg(ao);
	}

	/*
	 * Enable all error reporting banks (icache, dcache, ...).  This
	 * enables error detection, as opposed to error reporting above.
	 */
	wrmsr(IA32_MSR_MCG_CTL, AMD_MCG_EN_ALL);

	/*
	 * Throw away all existing bank state.  We do this because some BIOSes,
	 * perhaps during POST, do things to the machine that cause MCA state
	 * to be updated.  If we interpret this state as an actual error, we
	 * may end up indicting something that's not actually broken.
	 */
	for (i = 0; i < AMD_MCA_BANK_COUNT; i++) {
		if (!donb)
			continue;

		wrmsr(ao_bank_cfgs[i].bank_status, 0ULL);
	}

	wrmsr(IA32_MSR_MCG_STATUS, 0ULL);
	membar_producer();

	setcr4(getcr4() | CR4_MCE); /* enable #mc exceptions */
}

/*
 * Note that although this cpu module is loaded before the PSMs are
 * loaded (and hence before acpica is loaded), this function is
 * called from post_startup(), after PSMs are initialized and acpica
 * is loaded.
 */
static int
ao_acpi_find_smicmd(int *asd_port)
{
	FADT_DESCRIPTOR *fadt = NULL;

	/*
	 * AcpiGetFirmwareTable works even if ACPI is disabled, so a failure
	 * here means we weren't able to retreive a pointer to the FADT.
	 */
	if (AcpiGetFirmwareTable(FADT_SIG, 1, ACPI_LOGICAL_ADDRESSING,
	    (ACPI_TABLE_HEADER **)&fadt) != AE_OK)
		return (-1);

	ASSERT(fadt != NULL);

	*asd_port = fadt->SmiCmd;
	return (0);
}

/*ARGSUSED*/
void
ao_mca_post_init(void *data)
{
	const struct ao_smi_disable *asd;
	id_t id;
	int rv = -1, asd_port;

	smbios_system_t sy;
	smbios_bios_t sb;
	smbios_info_t si;

	/*
	 * Fetch the System and BIOS vendor strings from SMBIOS and see if they
	 * match a value in our table.  If so, disable SMI error polling.  This
	 * is grotesque and should be replaced by self-describing vendor-
	 * specific SMBIOS data or a specification enhancement instead.
	 */
	if (ao_mca_smi_disable && ksmbios != NULL &&
	    smbios_info_bios(ksmbios, &sb) != SMB_ERR &&
	    (id = smbios_info_system(ksmbios, &sy)) != SMB_ERR &&
	    smbios_info_common(ksmbios, id, &si) != SMB_ERR) {

		for (asd = ao_smi_disable; asd->asd_sys_vendor != NULL; asd++) {
			if (strncmp(asd->asd_sys_vendor, si.smbi_manufacturer,
			    strlen(asd->asd_sys_vendor)) != 0 ||
			    strncmp(asd->asd_sys_product, si.smbi_product,
			    strlen(asd->asd_sys_product)) != 0 ||
			    strncmp(asd->asd_bios_vendor, sb.smbb_vendor,
			    strlen(asd->asd_bios_vendor)) != 0)
				continue;

			/*
			 * Look for the SMI_CMD port in the ACPI FADT,
			 * if the port is 0, this platform doesn't support
			 * SMM, so there is no SMI error polling to disable.
			 */
			if ((rv = ao_acpi_find_smicmd(&asd_port)) == 0 &&
			    asd_port != 0) {
				cmn_err(CE_CONT, "?SMI polling disabled in "
				    "favor of Solaris Fault Management for "
				    "AMD Processors\n");

				outb(asd_port, asd->asd_code);

			} else if (rv < 0) {
				cmn_err(CE_CONT, "?Solaris Fault Management "
				    "for AMD Processors could not disable SMI "
				    "polling because an error occurred while "
				    "trying to determine the SMI command port "
				    "from the ACPI FADT table\n");
			}
			break;
		}
	}

	ao_mca_poll_start();
}

/*
 * Called after a CPU has been marked with CPU_FAULTED.  Not called on the
 * faulted CPU.  cpu_lock is held.
 */
/*ARGSUSED*/
void
ao_faulted_enter(void *data)
{
	/*
	 * Nothing to do here.  We'd like to turn off the faulted CPU's
	 * correctable error detectors, but that can only be done by the
	 * faulted CPU itself.  cpu_get_state() will now return P_FAULTED,
	 * allowing the poller to skip this CPU until it is re-enabled.
	 */
}

/*
 * Called after the CPU_FAULTED bit has been cleared from a previously-faulted
 * CPU.  Not called on the faulted CPU.  cpu_lock is held.
 */
void
ao_faulted_exit(void *data)
{
	ao_data_t *ao = data;

	/*
	 * We'd like to clear the faulted CPU's MCi_STATUS registers so as to
	 * avoid generating ereports for errors which occurred while the CPU was
	 * officially faulted.  Unfortunately, those registers can only be
	 * cleared by the CPU itself, so we can't do it here.
	 *
	 * We're going to set the UNFAULTING bit on the formerly-faulted CPU's
	 * MCA state.  This will tell the poller that the MCi_STATUS registers
	 * can't yet be trusted.  The poller, which is the first thing we
	 * control that'll execute on that CPU, will clear the registers, and
	 * will then clear the bit.
	 */

	ao->ao_mca.ao_mca_flags |= AO_MCA_F_UNFAULTING;
}
