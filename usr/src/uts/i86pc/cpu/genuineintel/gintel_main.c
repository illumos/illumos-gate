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

/*
 * Intel model-specific support.  Right now all this conists of is
 * to modify the ereport subclass to produce different ereport classes
 * so that we can have different diagnosis rules and corresponding faults.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/mca_x86.h>
#include <sys/cpu_module_ms_impl.h>
#include <sys/mc_intel.h>
#include <sys/pci_cfgspace.h>
#include <sys/fm/protocol.h>

int gintel_ms_support_disable = 0;
int gintel_error_action_return = 0;
int gintel_ms_unconstrained = 0;

int quickpath;
int max_bus_number = 0xff;

#define	ERR_COUNTER_INDEX	2
#define	MAX_CPU_NODES		2
#define	N_MC_COR_ECC_CNT	6
uint32_t err_counter_array[MAX_CPU_NODES][ERR_COUNTER_INDEX][N_MC_COR_ECC_CNT];
uint8_t	err_counter_index[MAX_CPU_NODES];

#define	MAX_BUS_NUMBER  max_bus_number
#define	SOCKET_BUS(cpu) (MAX_BUS_NUMBER - (cpu))

#define	MC_COR_ECC_CNT(chipid, reg)	(*pci_getl_func)(SOCKET_BUS(chipid), \
    NEHALEM_EP_MEMORY_CONTROLLER_DEV, NEHALEM_EP_MEMORY_CONTROLLER_FUNC, \
    0x80 + (reg) * 4)

#define	MSCOD_MEM_ECC_READ	0x1
#define	MSCOD_MEM_ECC_SCRUB	0x2
#define	MSCOD_MEM_WR_PARITY	0x4
#define	MSCOD_MEM_REDUNDANT_MEM	0x8
#define	MSCOD_MEM_SPARE_MEM	0x10
#define	MSCOD_MEM_ILLEGAL_ADDR	0x20
#define	MSCOD_MEM_BAD_ID	0x40
#define	MSCOD_MEM_ADDR_PARITY	0x80
#define	MSCOD_MEM_BYTE_PARITY	0x100

#define	GINTEL_ERROR_MEM	0x1000
#define	GINTEL_ERROR_QUICKPATH	0x2000

#define	GINTEL_ERR_SPARE_MEM	(GINTEL_ERROR_MEM | 1)
#define	GINTEL_ERR_MEM_UE	(GINTEL_ERROR_MEM | 2)
#define	GINTEL_ERR_MEM_CE	(GINTEL_ERROR_MEM | 3)
#define	GINTEL_ERR_MEM_PARITY	(GINTEL_ERROR_MEM | 4)
#define	GINTEL_ERR_MEM_ADDR_PARITY	(GINTEL_ERROR_MEM | 5)
#define	GINTEL_ERR_MEM_REDUNDANT (GINTEL_ERROR_MEM | 6)
#define	GINTEL_ERR_MEM_BAD_ADDR	(GINTEL_ERROR_MEM | 7)
#define	GINTEL_ERR_MEM_BAD_ID	(GINTEL_ERROR_MEM | 8)
#define	GINTEL_ERR_MEM_UNKNOWN	(GINTEL_ERROR_MEM | 0xfff)

#define	MSR_MC_MISC_MEM_CHANNEL_MASK	0x00000000000c0000ULL
#define	MSR_MC_MISC_MEM_CHANNEL_SHIFT	18
#define	MSR_MC_MISC_MEM_DIMM_MASK	0x0000000000030000ULL
#define	MSR_MC_MISC_MEM_DIMM_SHIFT	16
#define	MSR_MC_MISC_MEM_SYNDROME_MASK	0xffffffff00000000ULL
#define	MSR_MC_MISC_MEM_SYNDROME_SHIFT	32

#define	CPU_GENERATION_DONT_CARE	0
#define	CPU_GENERATION_NEHALEM_EP	1

#define	INTEL_NEHALEM_CPU_FAMILY_ID	0x6
#define	INTEL_NEHALEM_CPU_MODEL_ID	0x1A

#define	NEHALEM_EP_MEMORY_CONTROLLER_DEV	0x3
#define	NEHALEM_EP_MEMORY_CONTROLLER_FUNC	0x2

/*ARGSUSED*/
int
gintel_init(cmi_hdl_t hdl, void **datap)
{
	uint32_t nb_chipset;

	if (gintel_ms_support_disable)
		return (ENOTSUP);

	if (!(x86_feature & X86_MCA))
		return (ENOTSUP);

	nb_chipset = (*pci_getl_func)(0, 0, 0, 0x0);
	switch (nb_chipset) {
	case INTEL_NB_7300:
	case INTEL_NB_5000P:
	case INTEL_NB_5000X:
	case INTEL_NB_5000V:
	case INTEL_NB_5000Z:
	case INTEL_NB_5400:
	case INTEL_NB_5400A:
	case INTEL_NB_5400B:
		if (!gintel_ms_unconstrained)
			gintel_error_action_return |= CMS_ERRSCOPE_POISONED;
		break;
	case INTEL_QP_IO:
	case INTEL_QP_36D:
	case INTEL_QP_24D:
		quickpath = 1;
		break;
	default:
		break;
	}
	return (0);
}

/*ARGSUSED*/
uint32_t
gintel_error_action(cmi_hdl_t hdl, int ismc, int bank,
    uint64_t status, uint64_t addr, uint64_t misc, void *mslogout)
{
	if ((status & MSR_MC_STATUS_PCC) == 0)
		return (gintel_error_action_return);
	else
		return (gintel_error_action_return & ~CMS_ERRSCOPE_POISONED);
}

/*ARGSUSED*/
cms_cookie_t
gintel_disp_match(cmi_hdl_t hdl, int bank, uint64_t status,
    uint64_t addr, uint64_t misc, void *mslogout)
{
	cms_cookie_t rt = (cms_cookie_t)NULL;
	uint16_t mcacode = MCAX86_ERRCODE(status);
	uint16_t mscode = MCAX86_MSERRCODE(status);

	if (MCAX86_ERRCODE_ISMEMORY_CONTROLLER(mcacode)) {
		/*
		 * memory controller errors
		 */
		if (mscode & MSCOD_MEM_SPARE_MEM) {
			rt = (cms_cookie_t)GINTEL_ERR_SPARE_MEM;
		} else if (mscode & (MSCOD_MEM_ECC_READ |
		    MSCOD_MEM_ECC_SCRUB)) {
			if (status & MSR_MC_STATUS_UC)
				rt = (cms_cookie_t)GINTEL_ERR_MEM_UE;
			else
				rt = (cms_cookie_t)GINTEL_ERR_MEM_CE;
		} else if (mscode & (MSCOD_MEM_WR_PARITY |
		    MSCOD_MEM_BYTE_PARITY)) {
			rt = (cms_cookie_t)GINTEL_ERR_MEM_PARITY;
		} else if (mscode & MSCOD_MEM_ADDR_PARITY) {
			rt = (cms_cookie_t)GINTEL_ERR_MEM_ADDR_PARITY;
		} else if (mscode & MSCOD_MEM_REDUNDANT_MEM) {
			rt = (cms_cookie_t)GINTEL_ERR_MEM_REDUNDANT;
		} else if (mscode & MSCOD_MEM_ILLEGAL_ADDR) {
			rt = (cms_cookie_t)GINTEL_ERR_MEM_BAD_ADDR;
		} else if (mscode & MSCOD_MEM_BAD_ID) {
			rt = (cms_cookie_t)GINTEL_ERR_MEM_BAD_ID;
		} else {
			rt = (cms_cookie_t)GINTEL_ERR_MEM_UNKNOWN;
		}
	} else if (quickpath &&
	    MCAX86_ERRCODE_ISBUS_INTERCONNECT(MCAX86_ERRCODE(status))) {
		rt = (cms_cookie_t)GINTEL_ERROR_QUICKPATH;
	}
	return (rt);
}

/*ARGSUSED*/
void
gintel_ereport_class(cmi_hdl_t hdl, cms_cookie_t mscookie,
    const char **cpuclsp, const char **leafclsp)
{
	*cpuclsp = FM_EREPORT_CPU_INTEL;
	switch ((uintptr_t)mscookie) {
	case GINTEL_ERROR_QUICKPATH:
		*leafclsp = "quickpath.interconnect";
		break;
	case GINTEL_ERR_SPARE_MEM:
		*leafclsp = "quickpath.mem_spare";
		break;
	case GINTEL_ERR_MEM_UE:
		*leafclsp = "quickpath.mem_ue";
		break;
	case GINTEL_ERR_MEM_CE:
		*leafclsp = "quickpath.mem_ce";
		break;
	case GINTEL_ERR_MEM_PARITY:
		*leafclsp = "quickpath.mem_parity";
		break;
	case GINTEL_ERR_MEM_ADDR_PARITY:
		*leafclsp = "quickpath.mem_addr_parity";
		break;
	case GINTEL_ERR_MEM_REDUNDANT:
		*leafclsp = "quickpath.mem_redundant";
		break;
	case GINTEL_ERR_MEM_BAD_ADDR:
		*leafclsp = "quickpath.mem_bad_addr";
		break;
	case GINTEL_ERR_MEM_BAD_ID:
		*leafclsp = "quickpath.mem_bad_id";
		break;
	case GINTEL_ERR_MEM_UNKNOWN:
		*leafclsp = "quickpath.mem_unknown";
		break;
	}
}

nvlist_t *
gintel_ereport_detector(cmi_hdl_t hdl, cms_cookie_t mscookie, nv_alloc_t *nva)
{
	nvlist_t *nvl = (nvlist_t *)NULL;

	if (mscookie) {
		if ((nvl = fm_nvlist_create(nva)) == NULL)
			return (NULL);
		if ((uintptr_t)mscookie & GINTEL_ERROR_QUICKPATH) {
			fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, NULL, 2,
			    "motherboard", 0,
			    "chip", cmi_hdl_chipid(hdl));
		} else {
			fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, NULL, 3,
			    "motherboard", 0,
			    "chip", cmi_hdl_chipid(hdl),
			    "memory-controller", 0);
		}
	}
	return (nvl);
}

static nvlist_t *
gintel_ereport_create_resource_elem(nv_alloc_t *nva, mc_unum_t *unump)
{
	nvlist_t *nvl, *snvl;

	if ((nvl = fm_nvlist_create(nva)) == NULL)	/* freed by caller */
		return (NULL);

	if ((snvl = fm_nvlist_create(nva)) == NULL) {
		fm_nvlist_destroy(nvl, nva ? FM_NVA_RETAIN : FM_NVA_FREE);
		return (NULL);
	}

	(void) nvlist_add_uint64(snvl, FM_FMRI_HC_SPECIFIC_OFFSET,
	    unump->unum_offset);

	if (unump->unum_chan == -1) {
		fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, snvl, 3,
		    "motherboard", unump->unum_board,
		    "chip", unump->unum_chip,
		    "memory-controller", unump->unum_mc);
	} else if (unump->unum_cs == -1) {
		fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, snvl, 4,
		    "motherboard", unump->unum_board,
		    "chip", unump->unum_chip,
		    "memory-controller", unump->unum_mc,
		    "dram-channel", unump->unum_chan);
	} else if (unump->unum_rank == -1) {
		fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, snvl, 5,
		    "motherboard", unump->unum_board,
		    "chip", unump->unum_chip,
		    "memory-controller", unump->unum_mc,
		    "dram-channel", unump->unum_chan,
		    "dimm", unump->unum_cs);
	} else {
		fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, snvl, 6,
		    "motherboard", unump->unum_board,
		    "chip", unump->unum_chip,
		    "memory-controller", unump->unum_mc,
		    "dram-channel", unump->unum_chan,
		    "dimm", unump->unum_cs,
		    "rank", unump->unum_rank);
	}

	fm_nvlist_destroy(snvl, nva ? FM_NVA_RETAIN : FM_NVA_FREE);

	return (nvl);
}

static void
nehalem_ep_ereport_add_memory_error_counter(uint_t  chipid,
    uint32_t *this_err_counter_array)
{
	int	index;

	for (index = 0; index < N_MC_COR_ECC_CNT; index ++)
		this_err_counter_array[index] = MC_COR_ECC_CNT(chipid, index);
}

static int
gintel_cpu_generation()
{
	int	cpu_generation = CPU_GENERATION_DONT_CARE;

	if ((cpuid_getfamily(CPU) == INTEL_NEHALEM_CPU_FAMILY_ID) &&
	    (cpuid_getmodel(CPU) == INTEL_NEHALEM_CPU_MODEL_ID))
		cpu_generation = CPU_GENERATION_NEHALEM_EP;

	return (cpu_generation);
}

/*ARGSUSED*/
void
gintel_ereport_add_logout(cmi_hdl_t hdl, nvlist_t *ereport,
    nv_alloc_t *nva, int banknum, uint64_t status, uint64_t addr,
    uint64_t misc, void *mslogout, cms_cookie_t mscookie)
{
	mc_unum_t unum;
	nvlist_t *resource;
	uint32_t synd = 0;
	int  chan = MCAX86_ERRCODE_CCCC(status);
	uint8_t last_index, this_index;
	int chipid;

	if (chan == 0xf)
		chan = -1;

	if ((uintptr_t)mscookie & GINTEL_ERROR_MEM) {
		unum.unum_board = 0;
		unum.unum_chip = cmi_hdl_chipid(hdl);
		unum.unum_mc = 0;
		unum.unum_chan = chan;
		unum.unum_cs = -1;
		unum.unum_rank = -1;
		unum.unum_offset = -1ULL;
		if (status & MSR_MC_STATUS_MISCV) {
			unum.unum_chan =
			    (misc & MSR_MC_MISC_MEM_CHANNEL_MASK) >>
			    MSR_MC_MISC_MEM_CHANNEL_SHIFT;
			unum.unum_cs =
			    (misc & MSR_MC_MISC_MEM_DIMM_MASK) >>
			    MSR_MC_MISC_MEM_DIMM_SHIFT;
			synd = (misc & MSR_MC_MISC_MEM_SYNDROME_MASK) >>
			    MSR_MC_MISC_MEM_SYNDROME_SHIFT;
			fm_payload_set(ereport, FM_EREPORT_PAYLOAD_ECC_SYND,
			    DATA_TYPE_UINT32, synd, 0);
		}
		if (status & MSR_MC_STATUS_ADDRV) {
			fm_payload_set(ereport, FM_FMRI_MEM_PHYSADDR,
			    DATA_TYPE_UINT64, addr, NULL);
			(void) cmi_mc_patounum(addr, 0, 0, synd, 0, &unum);
		}
		resource = gintel_ereport_create_resource_elem(nva, &unum);
		fm_payload_set(ereport, FM_EREPORT_PAYLOAD_NAME_RESOURCE,
		    DATA_TYPE_NVLIST_ARRAY, 1, &resource, NULL);
		fm_nvlist_destroy(resource, nva ? FM_NVA_RETAIN:FM_NVA_FREE);

		if (gintel_cpu_generation() == CPU_GENERATION_NEHALEM_EP) {

			chipid = cmi_ntv_hwchipid(CPU);
			if (chipid < MAX_CPU_NODES) {
				last_index = err_counter_index[chipid];
				this_index =
				    (last_index + 1) % ERR_COUNTER_INDEX;
				err_counter_index[chipid] = this_index;
				nehalem_ep_ereport_add_memory_error_counter(
				    chipid,
				    err_counter_array[chipid][this_index]);
				fm_payload_set(ereport,
				    FM_EREPORT_PAYLOAD_MEM_ECC_COUNTER_THIS,
				    DATA_TYPE_UINT32_ARRAY, N_MC_COR_ECC_CNT,
				    err_counter_array[chipid][this_index],
				    NULL);
				fm_payload_set(ereport,
				    FM_EREPORT_PAYLOAD_MEM_ECC_COUNTER_LAST,
				    DATA_TYPE_UINT32_ARRAY, N_MC_COR_ECC_CNT,
				    err_counter_array[chipid][last_index],
				    NULL);
			}
		}
	}
}

boolean_t
gintel_bankctl_skipinit(cmi_hdl_t hdl, int banknum)
{
	/*
	 * On Intel family 6 before QuickPath we must not enable machine check
	 * from bank 0 detectors. bank 0 is reserved for the platform
	 */

	if (banknum == 0 &&
	    cmi_hdl_family(hdl) == INTEL_NEHALEM_CPU_FAMILY_ID &&
	    cmi_hdl_model(hdl) < INTEL_NEHALEM_CPU_MODEL_ID)
		return (1);
	else
		return (0);
}

cms_api_ver_t _cms_api_version = CMS_API_VERSION_0;

const cms_ops_t _cms_ops = {
	gintel_init,		/* cms_init */
	NULL,			/* cms_post_startup */
	NULL,			/* cms_post_mpstartup */
	NULL,			/* cms_logout_size */
	NULL,			/* cms_mcgctl_val */
	gintel_bankctl_skipinit, /* cms_bankctl_skipinit */
	NULL,			/* cms_bankctl_val */
	NULL,			/* cms_bankstatus_skipinit */
	NULL,			/* cms_bankstatus_val */
	NULL,			/* cms_mca_init */
	NULL,			/* cms_poll_ownermask */
	NULL,			/* cms_bank_logout */
	gintel_error_action,	/* cms_error_action */
	gintel_disp_match,	/* cms_disp_match */
	gintel_ereport_class,	/* cms_ereport_class */
	gintel_ereport_detector,	/* cms_ereport_detector */
	NULL,			/* cms_ereport_includestack */
	gintel_ereport_add_logout,	/* cms_ereport_add_logout */
	NULL,			/* cms_msrinject */
	NULL,			/* cms_fini */
};

static struct modlcpu modlcpu = {
	&mod_cpuops,
	"Generic Intel model-specific MCA"
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
