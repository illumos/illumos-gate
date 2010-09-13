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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/pci_impl.h>
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/pghw.h>
#include <sys/cyclic.h>
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
#include <sys/fm/smb/fmsmb.h>
#include <sys/acpi/acpi.h>
#include <sys/acpi/acpi_pci.h>
#include <sys/acpica.h>
#include <sys/cpu_module.h>

#include "ao.h"
#include "ao_mca_disp.h"

#define	AO_F_REVS_FG (X86_CHIPREV_AMD_F_REV_F | X86_CHIPREV_AMD_F_REV_G)

int ao_mca_smi_disable = 1;		/* attempt to disable SMI polling */

extern int x86gentopo_legacy;	/* x86 generic topology support */

struct ao_ctl_init {
	uint32_t ctl_revmask;	/* rev(s) to which this applies */
	uint64_t ctl_bits;	/* mca ctl reg bitmask to set */
};

/*
 * Additional NB MCA ctl initialization for revs F and G
 */
static const struct ao_ctl_init ao_nb_ctl_init[] = {
	{ AO_F_REVS_FG, AMD_NB_CTL_INIT_REV_FG },
	{ X86_CHIPREV_UNKNOWN, 0 }
};

typedef struct ao_bank_cfg {
	uint64_t bank_ctl_init_cmn;			/* Common init value */
	const struct ao_ctl_init *bank_ctl_init_extra;	/* Extra for each rev */
	void (*bank_misc_initfunc)(cmi_hdl_t, ao_ms_data_t *, uint32_t);
	uint_t bank_ctl_mask;
} ao_bank_cfg_t;

static void nb_mcamisc_init(cmi_hdl_t, ao_ms_data_t *, uint32_t);

static const ao_bank_cfg_t ao_bank_cfgs[] = {
	{ AMD_DC_CTL_INIT_CMN, NULL, NULL, AMD_MSR_DC_MASK },
	{ AMD_IC_CTL_INIT_CMN, NULL, NULL, AMD_MSR_IC_MASK },
	{ AMD_BU_CTL_INIT_CMN, NULL, NULL, AMD_MSR_BU_MASK },
	{ AMD_LS_CTL_INIT_CMN, NULL, NULL, AMD_MSR_LS_MASK },
	{ AMD_NB_CTL_INIT_CMN, &ao_nb_ctl_init[0], nb_mcamisc_init,
		AMD_MSR_NB_MASK },
};

static int ao_nbanks = sizeof (ao_bank_cfgs) / sizeof (ao_bank_cfgs[0]);

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
		AO_MCA_R4_BIT_ERR,	/* MCAX86_ERRCODE_RRRR_ERR */
		AO_MCA_R4_BIT_RD,	/* MCAX86_ERRCODE_RRRR_RD */
		AO_MCA_R4_BIT_WR,	/* MCAX86_ERRCODE_RRRR_WR */
		AO_MCA_R4_BIT_DRD,	/* MCAX86_ERRCODE_RRRR_DRD */
		AO_MCA_R4_BIT_DWR,	/* MCAX86_ERRCODE_RRRR_DWR */
		AO_MCA_R4_BIT_IRD,	/* MCAX86_ERRCODE_RRRR_IRD */
		AO_MCA_R4_BIT_PREFETCH,	/* MCAX86_ERRCODE_RRRR_PREFETCH */
		AO_MCA_R4_BIT_EVICT,	/* MCAX86_ERRCODE_RRRR_EVICT */
		AO_MCA_R4_BIT_SNOOP	/* MCAX86_ERRCODE_RRRR_SNOOP */
	};

	ASSERT(r4 < sizeof (ao_r4_map) / sizeof (uint16_t));

	return ((ref & ao_r4_map[r4]) != 0);
}

static int
ao_disp_match_pp(uint8_t ref, uint8_t pp)
{
	static const uint8_t ao_pp_map[] = {
		AO_MCA_PP_BIT_SRC,	/* MCAX86_ERRCODE_PP_SRC */
		AO_MCA_PP_BIT_RES,	/* MCAX86_ERRCODE_PP_RES */
		AO_MCA_PP_BIT_OBS,	/* MCAX86_ERRCODE_PP_OBS */
		AO_MCA_PP_BIT_GEN	/* MCAX86_ERRCODE_PP_GEN */
	};

	ASSERT(pp < sizeof (ao_pp_map) / sizeof (uint8_t));

	return ((ref & ao_pp_map[pp]) != 0);
}

static int
ao_disp_match_ii(uint8_t ref, uint8_t ii)
{
	static const uint8_t ao_ii_map[] = {
		AO_MCA_II_BIT_MEM,	/* MCAX86_ERRCODE_II_MEM */
		0,
		AO_MCA_II_BIT_IO,	/* MCAX86_ERRCODE_II_IO */
		AO_MCA_II_BIT_GEN	/* MCAX86_ERRCODE_II_GEN */
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
	bit_strip(codep, MCAX86_ERRCODE_##name##_MASK, \
	MCAX86_ERRCODE_##name##_SHIFT)

/*ARGSUSED*/
static int
ao_disp_match_one(const ao_error_disp_t *aed, uint64_t status, uint32_t rev,
    int bankno)
{
	uint16_t code = MCAX86_ERRCODE(status);
	uint8_t extcode = AMD_EXT_ERRCODE(status);
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
	    status & MSR_MC_STATUS_OVER) {
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
		uint8_t r4 = BIT_STRIP(&code, RRRR);

		if (!ao_disp_match_r4(aed->aed_stat_r4_bits, r4))
			return (0);

	} else if (AMD_ERRCODE_ISBUS(code)) {
		uint8_t r4 = BIT_STRIP(&code, RRRR);
		uint8_t pp = BIT_STRIP(&code, PP);
		uint8_t ii = BIT_STRIP(&code, II);

		if (!ao_disp_match_r4(aed->aed_stat_r4_bits, r4) ||
		    !ao_disp_match_pp(aed->aed_stat_pp_bits, pp) ||
		    !ao_disp_match_ii(aed->aed_stat_ii_bits, ii))
			return (0);
	}

	return (code == aed->aed_stat_code && extcode == aed->aed_stat_extcode);
}

/*ARGSUSED*/
cms_cookie_t
ao_ms_disp_match(cmi_hdl_t hdl, int ismc, int banknum, uint64_t status,
    uint64_t addr, uint64_t misc, void *mslogout)
{
	ao_ms_data_t *ao = cms_hdl_getcmsdata(hdl);
	uint32_t rev = ao->ao_ms_shared->aos_chiprev;
	const ao_error_disp_t *aed;

	for (aed = ao_error_disp[banknum]; aed->aed_stat_mask != 0; aed++) {
		if (ao_disp_match_one(aed, status, rev, banknum))
			return ((cms_cookie_t)aed);
	}

	return (NULL);
}

/*ARGSUSED*/
void
ao_ms_ereport_class(cmi_hdl_t hdl, cms_cookie_t mscookie,
    const char **cpuclsp, const char **leafclsp)
{
	const ao_error_disp_t *aed = mscookie;

	if (aed != NULL) {
		*cpuclsp = FM_EREPORT_CPU_AMD;
		*leafclsp = aed->aed_class;
	}
}

static int
ao_chip_once(ao_ms_data_t *ao, enum ao_cfgonce_bitnum what)
{
	return (atomic_set_long_excl(&ao->ao_ms_shared->aos_cfgonce,
	    what) == 0 ?  B_TRUE : B_FALSE);
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
nb_mcamisc_init(cmi_hdl_t hdl, ao_ms_data_t *ao, uint32_t rev)
{
	uint64_t val, nval;

	if (!X86_CHIPREV_MATCH(rev, AO_F_REVS_FG))
		return;

	if (cmi_hdl_rdmsr(hdl, AMD_MSR_NB_MISC, &val) != CMI_SUCCESS)
		return;

	ao->ao_ms_shared->aos_bcfg_nb_misc = val;

	if (ao_nb_cfg_mc4misc_noseize)
		return;		/* stash BIOS value, but no changes */


	/*
	 * The Valid bit tells us whether the CtrP bit is defined; if it
	 * is the CtrP bit tells us whether an ErrCount field is present.
	 * If not then there is nothing for us to do.
	 */
	if (!(val & AMD_NB_MISC_VALID) || !(val & AMD_NB_MISC_CTRP))
		return;


	nval = val;
	nval |= AMD_NB_MISC_CNTEN;		/* enable ECC error counting */
	nval &= ~AMD_NB_MISC_ERRCOUNT_MASK;	/* clear ErrCount */
	nval &= ~AMD_NB_MISC_OVRFLW;		/* clear Ovrflw */
	nval &= ~AMD_NB_MISC_INTTYPE_MASK;	/* no interrupt on overflow */
	nval |= AMD_NB_MISC_LOCKED;

	if (nval != val) {
		uint64_t locked = val & AMD_NB_MISC_LOCKED;

		if (locked)
			ao_bankstatus_prewrite(hdl, ao);

		(void) cmi_hdl_wrmsr(hdl, AMD_MSR_NB_MISC, nval);

		if (locked)
			ao_bankstatus_postwrite(hdl, ao);
	}
}

/*
 * NorthBridge (NB) MCA Configuration.
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
	{ AO_F_REVS_FG, &ao_nb_cfg_add_revFG, &ao_nb_cfg_remove_revFG },
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
ao_nb_cfg(ao_ms_data_t *ao, uint32_t rev)
{
	const struct ao_nb_cfg *nbcp = &ao_cfg_extra[0];
	uint_t procnodeid = pg_plat_hw_instance_id(CPU, PGHW_PROCNODE);
	uint32_t val;

	/*
	 * Read the NorthBridge (NB) configuration register in PCI space,
	 * modify the settings accordingly, and store the new value back.
	 * Note that the stashed BIOS config value aos_bcfg_nb_cfg is used
	 * in ereport payload population to determine ECC syndrome type for
	 * memory errors.
	 */
	ao->ao_ms_shared->aos_bcfg_nb_cfg = val =
	    ao_pcicfg_read(procnodeid, MC_FUNC_MISCCTL, MC_CTL_REG_NBCFG);

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
		if (!(val & AMD_NB_CFG_WDOGTMRDIS))
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

	ao_pcicfg_write(procnodeid, MC_FUNC_MISCCTL, MC_CTL_REG_NBCFG, val);
}

static void
ao_dram_cfg(ao_ms_data_t *ao, uint32_t rev)
{
	uint_t procnodeid = pg_plat_hw_instance_id(CPU, PGHW_PROCNODE);
	union mcreg_dramcfg_lo dcfglo;

	ao->ao_ms_shared->aos_bcfg_dcfg_lo = MCREG_VAL32(&dcfglo) =
	    ao_pcicfg_read(procnodeid, MC_FUNC_DRAMCTL, MC_DC_REG_DRAMCFGLO);
	ao->ao_ms_shared->aos_bcfg_dcfg_hi =
	    ao_pcicfg_read(procnodeid, MC_FUNC_DRAMCTL, MC_DC_REG_DRAMCFGHI);
#ifdef OPTERON_ERRATUM_172
	if (X86_CHIPREV_MATCH(rev, AO_F_REVS_FG) &&
	    MCREG_FIELD_F_revFG(&dcfglo, ParEn)) {
		MCREG_FIELD_F_revFG(&dcfglo, ParEn) = 0;
		ao_pcicfg_write(procnodeid, MC_FUNC_DRAMCTL,
		    MC_DC_REG_DRAMCFGLO, MCREG_VAL32(&dcfglo));
	}
#endif
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
ao_sparectl_cfg(ao_ms_data_t *ao)
{
	uint_t procnodeid = pg_plat_hw_instance_id(CPU, PGHW_PROCNODE);
	union mcreg_sparectl sparectl;
	int chan, cs;

	ao->ao_ms_shared->aos_bcfg_nb_sparectl = MCREG_VAL32(&sparectl) =
	    ao_pcicfg_read(procnodeid, MC_FUNC_MISCCTL, MC_CTL_REG_SPARECTL);

	if (ao_nb_cfg_sparectl_noseize)
		return;	/* stash BIOS value, but no changes */

	/*
	 * If the BIOS has requested SMI interrupt type for ECC count
	 * overflow for a chip-select or channel force those off.
	 */
	MCREG_FIELD_F_revFG(&sparectl, EccErrInt) = 0;
	MCREG_FIELD_F_revFG(&sparectl, SwapDoneInt) = 0;

	/*
	 * Zero EccErrCnt and write this back to all chan/cs combinations.
	 */
	MCREG_FIELD_F_revFG(&sparectl, EccErrCntWrEn) = 1;
	MCREG_FIELD_F_revFG(&sparectl, EccErrCnt) = 0;
	for (chan = 0; chan < MC_CHIP_NDRAMCHAN; chan++) {
		MCREG_FIELD_F_revFG(&sparectl, EccErrCntDramChan) = chan;

		for (cs = 0; cs < MC_CHIP_NCS; cs++) {
			MCREG_FIELD_F_revFG(&sparectl, EccErrCntDramCs) = cs;
			ao_pcicfg_write(procnodeid, MC_FUNC_MISCCTL,
			    MC_CTL_REG_SPARECTL, MCREG_VAL32(&sparectl));
		}
	}
}

int ao_forgive_uc = 0;		/* For test/debug only */
int ao_forgive_pcc = 0;		/* For test/debug only */
int ao_fake_poison = 0;		/* For test/debug only */

uint32_t
ao_ms_error_action(cmi_hdl_t hdl, int ismc, int banknum,
    uint64_t status, uint64_t addr, uint64_t misc, void *mslogout)
{
	const ao_error_disp_t *aed;
	uint32_t retval = 0;
	uint8_t when;
	int en;

	if (ao_forgive_uc)
		retval |= CMS_ERRSCOPE_CLEARED_UC;

	if (ao_forgive_pcc)
		retval |= CMS_ERRSCOPE_CURCONTEXT_OK;

	if (ao_fake_poison && status & MSR_MC_STATUS_UC)
		retval |= CMS_ERRSCOPE_POISONED;

	if (retval)
		return (retval);

	aed = ao_ms_disp_match(hdl, ismc, banknum, status, addr, misc,
	    mslogout);

	/*
	 * If we do not recognise the error let the cpu module apply
	 * the generic criteria to decide how to react.
	 */
	if (aed == NULL)
		return (0);

	en = (status & MSR_MC_STATUS_EN) != 0;

	if ((when = aed->aed_panic_when) == AO_AED_PANIC_NEVER)
		retval |= CMS_ERRSCOPE_IGNORE_ERR;

	if ((when & AO_AED_PANIC_ALWAYS) ||
	    ((when & AO_AED_PANIC_IFMCE) && (en || ismc)))
		retval |= CMS_ERRSCOPE_FORCE_FATAL;

	/*
	 * The original AMD implementation would panic on a machine check
	 * (not a poll) if the status overflow bit was set, with an
	 * exception for the case of rev F or later with an NB error
	 * indicating CECC.  This came from the perception that the
	 * overflow bit was not correctly managed on rev E and earlier, for
	 * example that repeated correctable memeory errors did not set
	 * OVER but somehow clear CECC.
	 *
	 * We will leave the generic support to evaluate overflow errors
	 * and decide to panic on their individual merits, e.g., if PCC
	 * is set and so on.  The AMD docs do say (as Intel does) that
	 * the status information is *all* from the higher-priority
	 * error in the case of an overflow, so it is at least as serious
	 * as the original and we can decide panic etc based on it.
	 */

	return (retval);
}

/*
 * Will need to change for family 0x10
 */
static uint_t
ao_ereport_synd(ao_ms_data_t *ao, uint64_t status, uint_t *typep,
    int is_nb)
{
	if (is_nb) {
		if (ao->ao_ms_shared->aos_bcfg_nb_cfg &
		    AMD_NB_CFG_CHIPKILLECCEN) {
			*typep = AMD_SYNDTYPE_CHIPKILL;
			return (AMD_NB_STAT_CKSYND(status));
		} else {
			*typep = AMD_SYNDTYPE_ECC;
			return (AMD_BANK_SYND(status));
		}
	} else {
		*typep = AMD_SYNDTYPE_ECC;
		return (AMD_BANK_SYND(status));
	}
}

static nvlist_t *
ao_ereport_create_resource_elem(cmi_hdl_t hdl, nv_alloc_t *nva,
    mc_unum_t *unump, int dimmnum)
{
	nvlist_t *nvl, *snvl;
	nvlist_t *board_list = NULL;

	if ((nvl = fm_nvlist_create(nva)) == NULL)	/* freed by caller */
		return (NULL);

	if ((snvl = fm_nvlist_create(nva)) == NULL) {
		fm_nvlist_destroy(nvl, nva ? FM_NVA_RETAIN : FM_NVA_FREE);
		return (NULL);
	}

	(void) nvlist_add_uint64(snvl, FM_FMRI_HC_SPECIFIC_OFFSET,
	    unump->unum_offset);

	if (!x86gentopo_legacy) {
		board_list = cmi_hdl_smb_bboard(hdl);

		if (board_list == NULL) {
			fm_nvlist_destroy(nvl,
			    nva ? FM_NVA_RETAIN : FM_NVA_FREE);
			fm_nvlist_destroy(snvl,
			    nva ? FM_NVA_RETAIN : FM_NVA_FREE);
			return (NULL);
		}

		fm_fmri_hc_create(nvl, FM_HC_SCHEME_VERSION, NULL, snvl,
		    board_list, 4,
		    "chip", cmi_hdl_smb_chipid(hdl),
		    "memory-controller", unump->unum_mc,
		    "dimm", unump->unum_dimms[dimmnum],
		    "rank", unump->unum_rank);
	} else {
		fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, snvl, 5,
		    "motherboard", unump->unum_board,
		    "chip", unump->unum_chip,
		    "memory-controller", unump->unum_mc,
		    "dimm", unump->unum_dimms[dimmnum],
		    "rank", unump->unum_rank);
	}

	fm_nvlist_destroy(snvl, nva ? FM_NVA_RETAIN : FM_NVA_FREE);

	return (nvl);
}

static void
ao_ereport_add_resource(cmi_hdl_t hdl, nvlist_t *payload, nv_alloc_t *nva,
    mc_unum_t *unump)
{

	nvlist_t *elems[MC_UNUM_NDIMM];
	int nelems = 0;
	int i;

	for (i = 0; i < MC_UNUM_NDIMM; i++) {
		if (unump->unum_dimms[i] == MC_INVALNUM)
			break;

		if ((elems[nelems] = ao_ereport_create_resource_elem(hdl, nva,
		    unump, i)) == NULL)
			break;

		nelems++;
	}

	if (nelems == 0)
		return;

	fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RESOURCE,
	    DATA_TYPE_NVLIST_ARRAY, nelems, elems, NULL);

	for (i = 0; i < nelems; i++)
		fm_nvlist_destroy(elems[i], nva ? FM_NVA_RETAIN : FM_NVA_FREE);
}

/*ARGSUSED*/
void
ao_ms_ereport_add_logout(cmi_hdl_t hdl, nvlist_t *ereport,
    nv_alloc_t *nva, int banknum, uint64_t status, uint64_t addr,
    uint64_t misc, void *mslogout, cms_cookie_t mscookie)
{
	ao_ms_data_t *ao = cms_hdl_getcmsdata(hdl);
	const ao_error_disp_t *aed = mscookie;
	uint_t synd, syndtype;
	uint64_t members;

	if (aed == NULL)
		return;

	members = aed->aed_ereport_members;

	synd = ao_ereport_synd(ao, status, &syndtype,
	    banknum == AMD_MCA_BANK_NB);

	if (members & FM_EREPORT_PAYLOAD_FLAG_SYND) {
		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_SYND,
		    DATA_TYPE_UINT16, synd, NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_SYND_TYPE) {
		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_SYND_TYPE,
		    DATA_TYPE_STRING, (syndtype == AMD_SYNDTYPE_CHIPKILL ?
		    "C4" : "E"), NULL);
	}

	if (members & FM_EREPORT_PAYLOAD_FLAG_RESOURCE) {
		mc_unum_t unum;

		if (((aed->aed_flags & AO_AED_FLAGS_ADDRTYPE) ==
		    AO_AED_F_PHYSICAL) && (status & MSR_MC_STATUS_ADDRV) &&
		    cmi_mc_patounum(addr, aed->aed_addrvalid_hi,
		    aed->aed_addrvalid_lo, synd, syndtype, &unum) ==
		    CMI_SUCCESS)
			ao_ereport_add_resource(hdl, ereport, nva, &unum);
	}
}

/*ARGSUSED*/
boolean_t
ao_ms_ereport_includestack(cmi_hdl_t hdl, cms_cookie_t mscookie)
{
	const ao_error_disp_t *aed = mscookie;

	if (aed == NULL)
		return (0);

	return ((aed->aed_ereport_members &
	    FM_EREPORT_PAYLOAD_FLAG_STACK) != 0);
}

cms_errno_t
ao_ms_msrinject(cmi_hdl_t hdl, uint_t msr, uint64_t val)
{
	ao_ms_data_t *ao = cms_hdl_getcmsdata(hdl);
	cms_errno_t rv = CMSERR_BADMSRWRITE;

	ao_bankstatus_prewrite(hdl, ao);
	if (cmi_hdl_wrmsr(hdl, msr, val) == CMI_SUCCESS)
		rv = CMS_SUCCESS;
	ao_bankstatus_postwrite(hdl, ao);

	return (rv);
}

/*ARGSUSED*/
uint64_t
ao_ms_mcgctl_val(cmi_hdl_t hdl, int nbanks, uint64_t def)
{
	return ((1ULL << nbanks) - 1);
}

boolean_t
ao_ms_bankctl_skipinit(cmi_hdl_t hdl, int banknum)
{
	ao_ms_data_t *ao = cms_hdl_getcmsdata(hdl);

	if (banknum != AMD_MCA_BANK_NB)
		return (B_FALSE);

	/*
	 * If we are the first to atomically set the "I'll do it" bit
	 * then return B_FALSE (do not skip), otherwise skip with B_TRUE.
	 */
	return (ao_chip_once(ao, AO_CFGONCE_NBMCA) == B_TRUE ?
	    B_FALSE : B_TRUE);
}

uint64_t
ao_ms_bankctl_val(cmi_hdl_t hdl, int banknum, uint64_t def)
{
	ao_ms_data_t *ao = cms_hdl_getcmsdata(hdl);
	const struct ao_ctl_init *extrap;
	const ao_bank_cfg_t *bankcfg;
	uint64_t mcictl;
	uint32_t rev = ao->ao_ms_shared->aos_chiprev;

	if (banknum >= sizeof (ao_bank_cfgs) / sizeof (ao_bank_cfgs[0]))
		return (def);

	bankcfg = &ao_bank_cfgs[banknum];
	extrap = bankcfg->bank_ctl_init_extra;

	mcictl = bankcfg->bank_ctl_init_cmn;

	while (extrap != NULL && extrap->ctl_revmask != X86_CHIPREV_UNKNOWN) {
		if (X86_CHIPREV_MATCH(rev, extrap->ctl_revmask))
			mcictl |= extrap->ctl_bits;
		extrap++;
	}

	return (mcictl);
}

/*ARGSUSED*/
void
ao_bankstatus_prewrite(cmi_hdl_t hdl, ao_ms_data_t *ao)
{
#ifndef __xpv
	uint64_t hwcr;

	if (cmi_hdl_rdmsr(hdl, MSR_AMD_HWCR, &hwcr) != CMI_SUCCESS)
		return;

	ao->ao_ms_hwcr_val = hwcr;

	if (!(hwcr & AMD_HWCR_MCI_STATUS_WREN)) {
		hwcr |= AMD_HWCR_MCI_STATUS_WREN;
		(void) cmi_hdl_wrmsr(hdl, MSR_AMD_HWCR, hwcr);
	}
#endif
}

/*ARGSUSED*/
void
ao_bankstatus_postwrite(cmi_hdl_t hdl, ao_ms_data_t *ao)
{
#ifndef __xpv
	uint64_t hwcr = ao->ao_ms_hwcr_val;

	if (!(hwcr & AMD_HWCR_MCI_STATUS_WREN)) {
		hwcr &= ~AMD_HWCR_MCI_STATUS_WREN;
		(void) cmi_hdl_wrmsr(hdl, MSR_AMD_HWCR, hwcr);
	}
#endif
}

void
ao_ms_mca_init(cmi_hdl_t hdl, int nbanks)
{
	ao_ms_data_t *ao = cms_hdl_getcmsdata(hdl);
	uint32_t rev = ao->ao_ms_shared->aos_chiprev;
	ao_ms_mca_t *mca = &ao->ao_ms_mca;
	uint64_t *maskp;
	int i;

	maskp = mca->ao_mca_bios_cfg.bcfg_bank_mask = kmem_zalloc(nbanks *
	    sizeof (uint64_t), KM_SLEEP);

	/*
	 * Read the bank ctl mask MSRs, but only as many as we know
	 * certainly exist - don't calculate the register address.
	 * Also initialize the MCi_MISC register where required.
	 */
	for (i = 0; i < MIN(nbanks, ao_nbanks); i++) {
		(void) cmi_hdl_rdmsr(hdl, ao_bank_cfgs[i].bank_ctl_mask,
		    maskp++);
		if (ao_bank_cfgs[i].bank_misc_initfunc != NULL)
			ao_bank_cfgs[i].bank_misc_initfunc(hdl, ao, rev);

	}

	if (ao_chip_once(ao, AO_CFGONCE_NBCFG) == B_TRUE) {
		ao_nb_cfg(ao, rev);

		if (X86_CHIPREV_MATCH(rev, AO_F_REVS_FG))
			ao_sparectl_cfg(ao);
	}

	if (ao_chip_once(ao, AO_CFGONCE_DRAMCFG) == B_TRUE)
		ao_dram_cfg(ao, rev);

	ao_procnode_scrubber_enable(hdl, ao);
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
	ACPI_TABLE_FADT *fadt = NULL;

	/*
	 * AcpiGetTable works even if ACPI is disabled, so a failure
	 * here means we weren't able to retreive a pointer to the FADT.
	 */
	if (AcpiGetTable(ACPI_SIG_FADT, 1, (ACPI_TABLE_HEADER **)&fadt) !=
	    AE_OK)
		return (-1);

	ASSERT(fadt != NULL);

	*asd_port = fadt->SmiCommand;
	return (0);
}

/*ARGSUSED*/
void
ao_ms_post_startup(cmi_hdl_t hdl)
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
}
