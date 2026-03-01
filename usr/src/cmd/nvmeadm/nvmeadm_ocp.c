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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Field information for OCP logs.
 */

#include <err.h>
#include <string.h>
#include <sys/stddef.h>
#include <sys/sysmacros.h>
#include <sys/nvme/ocp.h>

#include "nvmeadm.h"

#define	OCP_F_SMART(f)	.nf_off = offsetof(ocp_vul_smart_t, osh_##f), \
	.nf_len = sizeof (((ocp_vul_smart_t *)NULL)->osh_##f)

static const nvmeadm_field_bit_t ocp_vul_smart_block_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 47,
	.nfb_short = "raw",
	.nfb_desc = "Raw Count",
	.nfb_type = NVMEADM_FT_HEX,
}, {
	.nfb_lowbit = 48, .nfb_hibit = 63,
	.nfb_short = "norm",
	.nfb_desc = "Normalized Value",
	.nfb_type = NVMEADM_FT_PERCENT,
} };

static const nvmeadm_field_bit_t ocp_vul_smart_e2e_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 31,
	.nfb_short = "det",
	.nfb_desc = "Detected Errors",
	.nfb_type = NVMEADM_FT_HEX,
}, {
	.nfb_lowbit = 32, .nfb_hibit = 63,
	.nfb_short = "cor",
	.nfb_desc = "Corrected Errors",
	.nfb_type = NVMEADM_FT_HEX
} };

static const nvmeadm_field_bit_t ocp_vul_smart_udec_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 31,
	.nfb_short = "max",
	.nfb_desc = "Maximum Count",
	.nfb_type = NVMEADM_FT_HEX,
}, {
	.nfb_lowbit = 32, .nfb_hibit = 63,
	.nfb_short = "min",
	.nfb_desc = "Minimum Count",
	.nfb_type = NVMEADM_FT_HEX
} };

static const nvmeadm_field_bit_t ocp_vul_smart_therm_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 7,
	.nfb_short = "events",
	.nfb_desc = "Throttling Events",
	.nfb_type = NVMEADM_FT_HEX,
}, {
	.nfb_lowbit = 8, .nfb_hibit = 15,
	.nfb_short = "status",
	.nfb_desc = "Current Throttling Status",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unthrottled", "first level", "second level",
	    "third level" }
} };

static const nvmeadm_field_bit_t ocp_vul_smart_dssd_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 7,
	.nfb_short = "errata",
	.nfb_desc = "Errata Version",
	.nfb_type = NVMEADM_FT_HEX,
}, {
	.nfb_lowbit = 8, .nfb_hibit = 23,
	.nfb_short = "point",
	.nfb_desc = "Point Version",
	.nfb_type = NVMEADM_FT_HEX,
}, {
	.nfb_lowbit = 24, .nfb_hibit = 39,
	.nfb_short = "minor",
	.nfb_desc = "Minor Version",
	.nfb_type = NVMEADM_FT_HEX,
}, {
	.nfb_lowbit = 40, .nfb_hibit = 47,
	.nfb_short = "major",
	.nfb_desc = "Major Version",
	.nfb_type = NVMEADM_FT_HEX,
} };

static const nvmeadm_field_t ocp_vul_smart_fields[] = { {
	OCP_F_SMART(pmed_write),
	.nf_short = "pmuw",
	.nf_desc = "Physical Media Units Written",
	.nf_type = NVMEADM_FT_BYTES
}, {
	OCP_F_SMART(pmed_read),
	.nf_short = "pmur",
	.nf_desc = "Physical Media Units Read",
	.nf_type = NVMEADM_FT_BYTES
}, {
	OCP_F_SMART(bunb),
	.nf_short = "bunb",
	.nf_desc = "Bad User NAND Blocks",
	NVMEADM_F_BITS(ocp_vul_smart_block_bits)
}, {
	OCP_F_SMART(bsnb),
	.nf_short = "bsnb",
	.nf_desc = "Bad System NAND Blocks",
	NVMEADM_F_BITS(ocp_vul_smart_block_bits)
}, {
	OCP_F_SMART(xor_rec),
	.nf_short = "xrc",
	.nf_desc = "XOR Recovery Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(read_unrec),
	.nf_short = "urec",
	.nf_desc = "Uncorrectable Read Error Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(soft_ecc_err),
	.nf_short = "seec",
	.nf_desc = "Soft ECC Error Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(e2e),
	.nf_short = "e2e",
	.nf_desc = "End to End Correction Counts",
	NVMEADM_F_BITS(ocp_vul_smart_e2e_bits)
}, {
	OCP_F_SMART(sys_used),
	.nf_short = "sdu",
	.nf_desc = "System Data Percent Used",
	.nf_type = NVMEADM_FT_PERCENT
}, {
	OCP_F_SMART(refresh),
	.nf_short = "refresh",
	.nf_desc = "Refresh Counts",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(udec),
	.nf_short = "udec",
	.nf_desc = "User Data Erase Counts",
	NVMEADM_F_BITS(ocp_vul_smart_udec_bits)
}, {
	OCP_F_SMART(therm),
	.nf_short = "therm",
	.nf_desc = "Thermal Throttling Status and Count",
	NVMEADM_F_BITS(ocp_vul_smart_therm_bits)
}, {
	OCP_F_SMART(dssd),
	.nf_short = "dssd",
	.nf_desc = "DSSD Specification Version",
	.nf_rev = 3,
	NVMEADM_F_BITS(ocp_vul_smart_dssd_bits)
}, {
	OCP_F_SMART(pcie_errcor),
	.nf_short = "pcicor",
	.nf_desc = "PCIe Correctable Error Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(inc_shut),
	.nf_short = "incshut",
	.nf_desc = "Incomplete Shutdowns",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(free),
	.nf_short = "freeblk",
	.nf_desc = "Percent Free Blocks",
	.nf_type = NVMEADM_FT_PERCENT
}, {
	OCP_F_SMART(cap_health),
	.nf_short = "cap",
	.nf_desc = "Capacitor Health",
	.nf_type = NVMEADM_FT_PERCENT
}, {
	OCP_F_SMART(nvme_base_errata),
	.nf_short = "baseev",
	.nf_desc = "NVMe Base Errata Version",
	.nf_rev = 3,
	.nf_type = NVMEADM_FT_ASCII
}, {
	OCP_F_SMART(nvme_cmd_errata),
	.nf_short = "cmdev",
	.nf_desc = "NVMe Command Set Errata Version",
	.nf_rev = 4,
	.nf_type = NVMEADM_FT_ASCII
}, {
	OCP_F_SMART(unaligned),
	.nf_short = "unalign",
	.nf_desc = "Unaligned I/O",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(sec_vers),
	.nf_short = "secvers",
	.nf_desc = "Security Version Number",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(nuse),
	.nf_short = "nuse",
	.nf_desc = "Total NUSE",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(plp_start),
	.nf_short = "plp",
	.nf_desc = "PLP Start Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(endurance),
	.nf_short = "endest",
	.nf_desc = "Endurance Estimate",
	.nf_type = NVMEADM_FT_BYTES
}, {
	OCP_F_SMART(pcie_retrain),
	.nf_short = "retrain",
	.nf_desc = "PCIe Link Retraining Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(ps_change),
	.nf_short = "pstate",
	.nf_desc = "Power State Change Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(min_fwrev),
	.nf_short = "minfw",
	.nf_desc = "Lowest Permitted Firmware Revision",
	.nf_type = NVMEADM_FT_ASCII
}, {
	OCP_F_SMART(vers),
	.nf_short = "lpv",
	.nf_desc = "Log Page Version",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_SMART(guid),
	.nf_short = "lpg",
	.nf_desc = "Log Page GUID",
	.nf_type = NVMEADM_FT_GUID
} };

static uint32_t
ocp_vul_smart_getvers(const void *data, size_t len)
{
	if (len < sizeof (ocp_vul_smart_t)) {
		errx(-1, "cannot parse revision information, found 0x%zx "
		    "bytes, need at least 0x%zx", len,
		    sizeof (ocp_vul_smart_t));
	}

	const ocp_vul_smart_t *log = data;
	return (log->osh_vers);
}

const nvmeadm_log_field_info_t ocp_vul_smart_field_info = {
	.nlfi_log = "ocp/smart",
	.nlfi_fields = ocp_vul_smart_fields,
	.nlfi_nfields = ARRAY_SIZE(ocp_vul_smart_fields),
	.nlfi_min = sizeof (ocp_vul_smart_t),
	.nlfi_getrev = ocp_vul_smart_getvers
};

#define	OCP_F_ERRREC(f)	.nf_off = offsetof(ocp_vul_errrec_t, oer_##f), \
	.nf_len = sizeof (((ocp_vul_errrec_t *)NULL)->oer_##f)

static const nvmeadm_field_bit_t ocp_vul_errrec_pra_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "ctrl",
	.nfb_desc = "NVMe Controller Reset",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "subsys",
	.nfb_desc = "NVMe Subsystem Reset",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "flr",
	.nfb_desc = "PCIe Function Level Reset",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "perst",
	.nfb_desc = "PERST#",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "power",
	.nfb_desc = "Main Power Cycle",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 5, .nfb_hibit = 5,
	.nfb_short = "hotrst",
	.nfb_desc = "PCIe Conventional Hot Reset",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
} };

static const nvmeadm_field_bit_t ocp_vul_errrec_dra_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "none",
	.nfb_desc = "No Action",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "fmt",
	.nfb_desc = "Format NVM",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "vsc",
	.nfb_desc = "Vendor Specific Command",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "valys",
	.nfb_desc = "Vendor Analysis",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "rep",
	.nfb_desc = "Device Replacement",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 5, .nfb_hibit = 5,
	.nfb_short = "san",
	.nfb_desc = "Sanitize",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
}, {
	.nfb_lowbit = 6, .nfb_hibit = 6,
	.nfb_short = "udl",
	.nfb_desc = "User Data Loss",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "not required", "required" }
} };

static const nvmeadm_field_bit_t ocp_vul_errrec_devcap_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "aen",
	.nfb_desc = "Panic AEN",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "cfs",
	.nfb_desc = "Panic CFS",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
} };

static const nvmeadm_field_t ocp_vul_errrec_fields[] = { {
	OCP_F_ERRREC(prwt),
	.nf_short = "prwt",
	.nf_desc = "Panic Reset Wait Time",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(pra),
	.nf_short = "pra",
	.nf_desc = "Panic Reset Action",
	NVMEADM_F_BITS(ocp_vul_errrec_pra_bits)
}, {
	OCP_F_ERRREC(dra),
	.nf_short = "dra",
	.nf_desc = "Device Recovery Action 1",
	NVMEADM_F_BITS(ocp_vul_errrec_dra_bits)
}, {
	OCP_F_ERRREC(panic_id),
	.nf_short = "id",
	.nf_desc = "Panic ID",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(devcap),
	.nf_short = "devcap",
	.nf_desc = "Device Capabilities",
	NVMEADM_F_BITS(ocp_vul_errrec_devcap_bits)
}, {
	OCP_F_ERRREC(vsr_opcode),
	.nf_short = "vsro",
	.nf_desc = "Vendor Specific Recovery Opcode",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(vsr_cdw12),
	.nf_short = "vcdw12",
	.nf_desc = "Vendor Specific Command CDW12",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(vsr_cdw13),
	.nf_short = "vcdw13",
	.nf_desc = "Vendor Specific Command CDW13",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(vsr_to),
	.nf_short = "vsct",
	.nf_desc = "Vendor Specific Command Timeout",
	.nf_rev = 2,
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(dra2),
	.nf_short = "dra2",
	.nf_desc = "Device Recovery Action 2",
	.nf_rev = 3,
	NVMEADM_F_BITS(ocp_vul_errrec_dra_bits)
}, {
	OCP_F_ERRREC(dra2_to),
	.nf_short = "dra2to",
	.nf_desc = "Device Recovery Action 2 Timeout",
	.nf_rev = 3,
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(npanic),
	.nf_short = "npanic",
	.nf_desc = "Panic Count",
	.nf_rev = 3,
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(old_panics[0]),
	.nf_short = "ppanic1",
	.nf_desc = "Previous Panic N-1",
	.nf_rev = 3,
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(old_panics[1]),
	.nf_short = "ppanic2",
	.nf_desc = "Previous Panic N-2",
	.nf_rev = 3,
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(old_panics[2]),
	.nf_short = "ppanic3",
	.nf_desc = "Previous Panic N-3",
	.nf_rev = 3,
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(old_panics[3]),
	.nf_short = "ppanic4",
	.nf_desc = "Previous Panic N-4",
	.nf_rev = 3,
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(vers),
	.nf_short = "lpv",
	.nf_desc = "Log Page Version",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_ERRREC(guid),
	.nf_short = "lpg",
	.nf_desc = "Log Page GUID",
	.nf_type = NVMEADM_FT_GUID
} };

static uint32_t
ocp_vul_errrec_getvers(const void *data, size_t len)
{
	if (len < sizeof (ocp_vul_errrec_t)) {
		errx(-1, "cannot parse revision information, found 0x%zx "
		    "bytes, need at least 0x%zx", len,
		    sizeof (ocp_vul_errrec_t));
	}

	const ocp_vul_errrec_t *log = data;
	return (log->oer_vers);
}

const nvmeadm_log_field_info_t ocp_vul_errrec_field_info = {
	.nlfi_log = "ocp/errrec",
	.nlfi_fields = ocp_vul_errrec_fields,
	.nlfi_nfields = ARRAY_SIZE(ocp_vul_errrec_fields),
	.nlfi_min = sizeof (ocp_vul_errrec_t),
	.nlfi_getrev = ocp_vul_errrec_getvers
};

#define	OCP_F_DEVCAP(f)	.nf_off = offsetof(ocp_vul_devcap_t, odc_##f), \
	.nf_len = sizeof (((ocp_vul_devcap_t *)NULL)->odc_##f)

#define	OCP_F_DEVCAP_PSD(f)	{ .nf_off = offsetof(ocp_vul_devcap_t, \
	odc_dssd[f]), \
	.nf_len = sizeof (((ocp_vul_devcap_t *)NULL)->odc_dssd[f]), \
	.nf_short = "psd" #f, .nf_desc = "DSSD Power State Descriptor " #f, \
	NVMEADM_F_BITS(ocp_vul_devcap_psd_bits) }

static const nvmeadm_field_bit_t ocp_vul_devcap_oob_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "smbus",
	.nfb_desc = "MCTP over SMBus",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "vdm",
	.nfb_desc = "MCTP over PCIe VDM",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "bmc",
	.nfb_desc = "NVMe Basic Management Command",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 15, .nfb_hibit = 15,
	.nfb_short = "pass",
	.nfb_desc = "Meets OOB Management Requirements",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

static const nvmeadm_field_bit_t ocp_vul_devcap_wz_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "wz",
	.nfb_desc = "Write Zeros Command",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "deac",
	.nfb_desc = "Setting DEAC Bit",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "fua",
	.nfb_desc = "Setting FUA Bit",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "io5",
	.nfb_desc = "NVMe-IO-5 Requirements",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "io6",
	.nfb_desc = "NVMe-IO-6 Requirements",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 15, .nfb_hibit = 15,
	.nfb_short = "pass",
	.nfb_desc = "Meets Write Zeros Requirements",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

static const nvmeadm_field_bit_t ocp_vul_devcap_san_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "san",
	.nfb_desc = "Sanitize Command",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "crypto",
	.nfb_desc = "Crypto-Erase",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "block",
	.nfb_desc = "Block Erase",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "ovr",
	.nfb_desc = "Overwrite",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "dea",
	.nfb_desc = "Deallocate LBAs",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 15, .nfb_hibit = 15,
	.nfb_short = "pass",
	.nfb_desc = "Meets Sanitize Requirements",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

static const nvmeadm_field_bit_t ocp_vul_devcap_ds_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "dsmgmt",
	.nfb_desc = "Dataset Management Command",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "ad",
	.nfb_desc = "Attribute Deallocate",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 15, .nfb_hibit = 15,
	.nfb_short = "pass",
	.nfb_desc = "Meets Dataset Management Requirements",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

static const nvmeadm_field_bit_t ocp_vul_devcap_wu_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "wu",
	.nfb_desc = "Write Uncorrectable Command",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "slba",
	.nfb_desc = "Single LBA",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "maxlba",
	.nfb_desc = "Maximum Number of LBAs",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "io14",
	.nfb_desc = "NVMe-IO-14",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 15, .nfb_hibit = 15,
	.nfb_short = "pass",
	.nfb_desc = "Meets Write Uncorrectable Requirements",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

static const nvmeadm_field_bit_t ocp_vul_devcap_fuse_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "cmpwr",
	.nfb_desc = "Compare and Write Fused Command",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 15, .nfb_hibit = 15,
	.nfb_short = "pass",
	.nfb_desc = "Meets Fused Command Requirements",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

static const nvmeadm_field_bit_t ocp_vul_devcap_psd_bits[] = {  {
	.nfb_lowbit = 0, .nfb_hibit = 4,
	.nfb_short = "ps",
	.nfb_desc = "NVMe Power State",
	.nfb_type = NVMEADM_FT_HEX
}, {
	.nfb_lowbit = 7, .nfb_hibit = 7,
	.nfb_short = "valid",
	.nfb_desc = "Valid DSSD Power State",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

static const nvmeadm_field_t ocp_vul_devcap_fields[] = { {
	OCP_F_DEVCAP(nports),
	.nf_short = "nports",
	.nf_desc = "PCI Express Ports",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_DEVCAP(oob_sup),
	.nf_short = "oob",
	.nf_desc = "OOB Management Support",
	NVMEADM_F_BITS(ocp_vul_devcap_oob_bits)
}, {
	OCP_F_DEVCAP(wz_sup),
	.nf_short = "wz",
	.nf_desc = "Write Zeroes Command Support",
	NVMEADM_F_BITS(ocp_vul_devcap_wz_bits)
}, {
	OCP_F_DEVCAP(san_sup),
	.nf_short = "san",
	.nf_desc = "Sanitize Command Support",
	NVMEADM_F_BITS(ocp_vul_devcap_san_bits)
}, {
	OCP_F_DEVCAP(dsmgmt_sup),
	.nf_short = "ds",
	.nf_desc = "Dataset Management Support",
	NVMEADM_F_BITS(ocp_vul_devcap_ds_bits)
}, {
	OCP_F_DEVCAP(wunc_sup),
	.nf_short = "wu",
	.nf_desc = "Write Uncorrectable Command Support",
	NVMEADM_F_BITS(ocp_vul_devcap_wu_bits)
}, {
	OCP_F_DEVCAP(fuse_sup),
	.nf_short = "fuse",
	.nf_desc = "Fused Operations Support",
	NVMEADM_F_BITS(ocp_vul_devcap_fuse_bits)
}, {
	OCP_F_DEVCAP(dssd_min_valid),
	.nf_short = "minps",
	.nf_desc = "Minimum Valid DSSD Power State",
	.nf_type = NVMEADM_FT_HEX
},
	OCP_F_DEVCAP_PSD(1), OCP_F_DEVCAP_PSD(2), OCP_F_DEVCAP_PSD(3),
	OCP_F_DEVCAP_PSD(4), OCP_F_DEVCAP_PSD(5), OCP_F_DEVCAP_PSD(6),
	OCP_F_DEVCAP_PSD(7), OCP_F_DEVCAP_PSD(8), OCP_F_DEVCAP_PSD(9),
	OCP_F_DEVCAP_PSD(10), OCP_F_DEVCAP_PSD(11), OCP_F_DEVCAP_PSD(12),
	OCP_F_DEVCAP_PSD(13), OCP_F_DEVCAP_PSD(14), OCP_F_DEVCAP_PSD(15),
	OCP_F_DEVCAP_PSD(16), OCP_F_DEVCAP_PSD(17), OCP_F_DEVCAP_PSD(18),
	OCP_F_DEVCAP_PSD(19), OCP_F_DEVCAP_PSD(20), OCP_F_DEVCAP_PSD(21),
	OCP_F_DEVCAP_PSD(22), OCP_F_DEVCAP_PSD(23), OCP_F_DEVCAP_PSD(24),
	OCP_F_DEVCAP_PSD(25), OCP_F_DEVCAP_PSD(26), OCP_F_DEVCAP_PSD(27),
	OCP_F_DEVCAP_PSD(28), OCP_F_DEVCAP_PSD(29), OCP_F_DEVCAP_PSD(30),
	OCP_F_DEVCAP_PSD(31), OCP_F_DEVCAP_PSD(32), OCP_F_DEVCAP_PSD(33),
	OCP_F_DEVCAP_PSD(34), OCP_F_DEVCAP_PSD(35), OCP_F_DEVCAP_PSD(36),
	OCP_F_DEVCAP_PSD(37), OCP_F_DEVCAP_PSD(38), OCP_F_DEVCAP_PSD(39),
	OCP_F_DEVCAP_PSD(40), OCP_F_DEVCAP_PSD(41), OCP_F_DEVCAP_PSD(42),
	OCP_F_DEVCAP_PSD(43), OCP_F_DEVCAP_PSD(44), OCP_F_DEVCAP_PSD(45),
	OCP_F_DEVCAP_PSD(46), OCP_F_DEVCAP_PSD(47), OCP_F_DEVCAP_PSD(48),
	OCP_F_DEVCAP_PSD(49), OCP_F_DEVCAP_PSD(50), OCP_F_DEVCAP_PSD(51),
	OCP_F_DEVCAP_PSD(52), OCP_F_DEVCAP_PSD(53), OCP_F_DEVCAP_PSD(54),
	OCP_F_DEVCAP_PSD(55), OCP_F_DEVCAP_PSD(56), OCP_F_DEVCAP_PSD(57),
	OCP_F_DEVCAP_PSD(58), OCP_F_DEVCAP_PSD(59), OCP_F_DEVCAP_PSD(60),
	OCP_F_DEVCAP_PSD(61), OCP_F_DEVCAP_PSD(62), OCP_F_DEVCAP_PSD(63),
	OCP_F_DEVCAP_PSD(64), OCP_F_DEVCAP_PSD(65), OCP_F_DEVCAP_PSD(66),
	OCP_F_DEVCAP_PSD(67), OCP_F_DEVCAP_PSD(68), OCP_F_DEVCAP_PSD(69),
	OCP_F_DEVCAP_PSD(70), OCP_F_DEVCAP_PSD(71), OCP_F_DEVCAP_PSD(72),
	OCP_F_DEVCAP_PSD(73), OCP_F_DEVCAP_PSD(74), OCP_F_DEVCAP_PSD(75),
	OCP_F_DEVCAP_PSD(76), OCP_F_DEVCAP_PSD(77), OCP_F_DEVCAP_PSD(78),
	OCP_F_DEVCAP_PSD(79), OCP_F_DEVCAP_PSD(80), OCP_F_DEVCAP_PSD(81),
	OCP_F_DEVCAP_PSD(82), OCP_F_DEVCAP_PSD(83), OCP_F_DEVCAP_PSD(84),
	OCP_F_DEVCAP_PSD(85), OCP_F_DEVCAP_PSD(86), OCP_F_DEVCAP_PSD(87),
	OCP_F_DEVCAP_PSD(88), OCP_F_DEVCAP_PSD(89), OCP_F_DEVCAP_PSD(90),
	OCP_F_DEVCAP_PSD(91), OCP_F_DEVCAP_PSD(92), OCP_F_DEVCAP_PSD(93),
	OCP_F_DEVCAP_PSD(94), OCP_F_DEVCAP_PSD(95), OCP_F_DEVCAP_PSD(96),
	OCP_F_DEVCAP_PSD(97), OCP_F_DEVCAP_PSD(98), OCP_F_DEVCAP_PSD(99),
	OCP_F_DEVCAP_PSD(100), OCP_F_DEVCAP_PSD(101), OCP_F_DEVCAP_PSD(102),
	OCP_F_DEVCAP_PSD(103), OCP_F_DEVCAP_PSD(104), OCP_F_DEVCAP_PSD(105),
	OCP_F_DEVCAP_PSD(106), OCP_F_DEVCAP_PSD(107), OCP_F_DEVCAP_PSD(108),
	OCP_F_DEVCAP_PSD(109), OCP_F_DEVCAP_PSD(110), OCP_F_DEVCAP_PSD(111),
	OCP_F_DEVCAP_PSD(112), OCP_F_DEVCAP_PSD(113), OCP_F_DEVCAP_PSD(114),
	OCP_F_DEVCAP_PSD(115), OCP_F_DEVCAP_PSD(116), OCP_F_DEVCAP_PSD(117),
	OCP_F_DEVCAP_PSD(118), OCP_F_DEVCAP_PSD(119), OCP_F_DEVCAP_PSD(120),
	OCP_F_DEVCAP_PSD(121), OCP_F_DEVCAP_PSD(122), OCP_F_DEVCAP_PSD(123),
	OCP_F_DEVCAP_PSD(124), OCP_F_DEVCAP_PSD(125), OCP_F_DEVCAP_PSD(126),
	OCP_F_DEVCAP_PSD(127),
{
	OCP_F_DEVCAP(vers),
	.nf_short = "lpv",
	.nf_desc = "Log Page Version",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_DEVCAP(guid),
	.nf_short = "lpg",
	.nf_desc = "Log Page GUID",
	.nf_type = NVMEADM_FT_GUID
} };

static uint32_t
ocp_vul_devcap_getvers(const void *data, size_t len)
{
	if (len < sizeof (ocp_vul_devcap_t)) {
		errx(-1, "cannot parse revision information, found 0x%zx "
		    "bytes, need at least 0x%zx", len,
		    sizeof (ocp_vul_devcap_t));
	}

	const ocp_vul_devcap_t *log = data;
	return (log->odc_vers);
}

const nvmeadm_log_field_info_t ocp_vul_devcap_field_info = {
	.nlfi_log = "ocp/devcap",
	.nlfi_fields = ocp_vul_devcap_fields,
	.nlfi_nfields = ARRAY_SIZE(ocp_vul_devcap_fields),
	.nlfi_min = sizeof (ocp_vul_devcap_t),
	.nlfi_getrev = ocp_vul_devcap_getvers
};

#define	OCP_F_UNSUP(f)	.nf_off = offsetof(ocp_vul_unsup_req_t, our_##f), \
	.nf_len = sizeof (((ocp_vul_unsup_req_t *)NULL)->our_##f)

static const nvmeadm_field_t ocp_vul_unsup_fields_head[] = { {
	OCP_F_UNSUP(nunsup),
	.nf_short = "count",
	.nf_desc = "Unsupported Count",
	.nf_type = NVMEADM_FT_HEX
} };

static const nvmeadm_field_t ocp_vul_unsup_fields_tail[] = { {
	OCP_F_UNSUP(vers),
	.nf_short = "lpv",
	.nf_desc = "Log Page Version",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_UNSUP(guid),
	.nf_short = "lpg",
	.nf_desc = "Log Page GUID",
	.nf_type = NVMEADM_FT_GUID
} };

static uint32_t
ocp_vul_unsup_getvers(const void *data, size_t len)
{
	if (len < sizeof (ocp_vul_unsup_req_t)) {
		errx(-1, "cannot parse revision information, found 0x%zx "
		    "bytes, need at least 0x%zx", len,
		    sizeof (ocp_vul_unsup_req_t));
	}

	const ocp_vul_unsup_req_t *log = data;
	return (log->our_vers);
}

/*
 * We manually drive this so we can create the appropriate number of entries for
 * the string table as there are a variable number of these.
 */
static bool
ocp_vul_unsup_drive(nvmeadm_field_print_t *print, const void *data, size_t len)
{
	print->fp_header = NULL;
	print->fp_fields = ocp_vul_unsup_fields_head;
	print->fp_nfields = ARRAY_SIZE(ocp_vul_unsup_fields_head);
	print->fp_base = NULL;
	print->fp_data = data;
	print->fp_dlen = len;
	print->fp_off = 0;
	nvmeadm_field_print(print);

	/*
	 * Look at the data and make sure we have an appropriate number of
	 * entries specified. While there is a uint16_t worth of entries the
	 * specification indicates there can be a maximum of 253.
	 */
	const ocp_vul_unsup_req_t *log = data;
	if (log->our_nunsup > 253) {
		warnx("log page has questionable data: log page count of "
		    "unsupported requirements %u exceeds spec max of 253",
		    log->our_nunsup);
	}
	size_t nlogs = MIN(log->our_nunsup, 253);
	for (size_t i = 0; i < nlogs; i++) {
		nvmeadm_field_t field;
		char shrt[32];
		char desc[128];

		(void) snprintf(shrt, sizeof (shrt), "ureq%zu", i);
		(void) snprintf(desc, sizeof (desc), "Unsupported Requirement "
		    "%zu", i);
		(void) memset(&field, 0, sizeof (nvmeadm_field_t));
		field.nf_off = offsetof(ocp_vul_unsup_req_t, our_reqs[i]);
		field.nf_len = sizeof (ocp_req_str_t);
		field.nf_short = shrt;
		field.nf_desc = desc;
		field.nf_type = NVMEADM_FT_ASCIIZ;

		print->fp_fields = &field;
		print->fp_nfields = 1;
		nvmeadm_field_print(print);
	}

	print->fp_fields = ocp_vul_unsup_fields_tail;
	print->fp_nfields = ARRAY_SIZE(ocp_vul_unsup_fields_tail);
	nvmeadm_field_print(print);
	return (true);
}

const nvmeadm_log_field_info_t ocp_vul_unsup_field_info = {
	.nlfi_log = "ocp/unsup",
	.nlfi_min = sizeof (ocp_vul_unsup_req_t),
	.nlfi_getrev = ocp_vul_unsup_getvers,
	.nlfi_drive = ocp_vul_unsup_drive
};

#define	OCP_F_TELSTR(f)	.nf_off = offsetof(ocp_vul_telstr_t, ots_##f), \
	.nf_len = sizeof (((ocp_vul_telstr_t *)NULL)->ots_##f)

static const nvmeadm_field_t ocp_vul_telstr_fields[] = { {
	OCP_F_TELSTR(vers),
	.nf_short = "lpv",
	.nf_desc = "Log Page Version",
	.nf_type = NVMEADM_FT_HEX
}, {
	OCP_F_TELSTR(guid),
	.nf_short = "lpg",
	.nf_desc = "Log Page GUID",
	.nf_type = NVMEADM_FT_GUID
}, {
	OCP_F_TELSTR(sls),
	.nf_short = "sls",
	.nf_desc = "Telemetry String Log Size",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
}, {
	OCP_F_TELSTR(sits),
	.nf_short = "sits",
	.nf_desc = "Statistics Identifier String Table Start",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
}, {
	OCP_F_TELSTR(sitz),
	.nf_short = "sitz",
	.nf_desc = "Statistics Identifier String Table Size",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
}, {
	OCP_F_TELSTR(ests),
	.nf_short = "ests",
	.nf_desc = "Event String Table Start",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
}, {
	OCP_F_TELSTR(estz),
	.nf_short = "estz",
	.nf_desc = "Event String Table Size",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
}, {
	OCP_F_TELSTR(vuests),
	.nf_short = "vuests",
	.nf_desc = "VU Event String Table Start",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
}, {
	OCP_F_TELSTR(vuestz),
	.nf_short = "vuestz",
	.nf_desc = "VU Event String Table Size",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
}, {
	OCP_F_TELSTR(ascts),
	.nf_short = "asctss",
	.nf_desc = "ASCII Table Start",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
}, {
	OCP_F_TELSTR(asctz),
	.nf_short = "asctsz",
	.nf_desc = "ASCII Table Size",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
} };

#define	OCP_F_TELSTR_SIT(f)	.nf_off = offsetof(ocp_vul_telstr_sit_t, \
	ocp_sit_##f), \
	.nf_len = sizeof (((ocp_vul_telstr_sit_t *)NULL)->ocp_sit_##f)

static const nvmeadm_field_t ocp_vul_telstr_sit_fields[] = { {
	OCP_F_TELSTR_SIT(id),
	.nf_short = "id",
	.nf_desc = "Vendor Unique Statistic Identifier",
	.nf_type = NVMEADM_FT_HEX,
}, {
	OCP_F_TELSTR_SIT(len),
	.nf_short = "len",
	.nf_desc = "ASCII ID Length",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_addend = 1 }
}, {
	OCP_F_TELSTR_SIT(off),
	.nf_short = "off",
	.nf_desc = "ASCII ID Offset",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
} };

#define	OCP_F_TELSTR_EST(f)	.nf_off = offsetof(ocp_vul_telstr_est_t, \
	ocp_est_##f), \
	.nf_len = sizeof (((ocp_vul_telstr_est_t *)NULL)->ocp_est_##f)

/*
 * This is the same currently for both the vendor unique and regular events so
 * we use the same structure for the time being.
 */
static const nvmeadm_field_t ocp_vul_telstr_est_fields[] = { {
	OCP_F_TELSTR_EST(class),
	.nf_short = "class",
	.nf_desc = "Debug Event Class",
	.nf_type = NVMEADM_FT_HEX,
}, {
	OCP_F_TELSTR_EST(eid),
	.nf_short = "id",
	.nf_desc = "Event Identifier",
	.nf_type = NVMEADM_FT_HEX,
}, {
	OCP_F_TELSTR_EST(len),
	.nf_short = "len",
	.nf_desc = "ASCII ID Length",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_addend = 1 }
}, {
	OCP_F_TELSTR_EST(off),
	.nf_short = "off",
	.nf_desc = "ASCII ID Offset",
	.nf_type = NVMEADM_FT_HEX,
	.nf_addend = { .nfa_shift = 2 }
} };

static uint32_t
ocp_vul_telstr_getvers(const void *data, size_t len)
{
	if (len < sizeof (ocp_vul_telstr_t)) {
		errx(-1, "cannot parse revision information, found 0x%zx "
		    "bytes, need at least 0x%zx", len,
		    sizeof (ocp_vul_telstr_t));
	}

	const ocp_vul_telstr_t *log = data;
	return (log->ots_vers);
}

static bool
ocp_vul_telstr_sanity(const char *name, uint64_t off_dw, uint64_t len_dw,
    size_t flen)
{
	const uint64_t max_dw = UINT64_MAX / sizeof (uint32_t);

	/*
	 * These values are in units of uint32_t's. Make sure we can represent
	 * them.
	 */
	if (off_dw > max_dw) {
		warnx("telemetry log %s offset does not fit in a 64-bit "
		    "quantity", name);
		return (false);
	}

	if (len_dw > max_dw) {
		warnx("telemetry log %s length does not fit in a 64-bit "
		    "quantity", name);
		return (false);
	}

	const uint64_t off_bytes = off_dw << 2;
	const uint64_t len_bytes = len_dw << 2;

	if (len_bytes > UINT64_MAX - off_bytes) {
		warnx("telemetry log %s final offset would overflow a 64-bit "
		    "quantity", name);
		return (false);
	}

	const uint64_t end = off_bytes + len_bytes;
	if (end > flen) {
		warnx("telemetry log %s exceeds beyond the end of the file",
		    name);
		return (false);
	}

	return (true);
}

/*
 * Set up a field to print an ASCII string and error if the embedded information
 * is not useful.
 */
static bool
ocp_vul_telstr_field_str(nvmeadm_field_t *field, uint16_t len0, uint64_t off_dw,
    uint64_t ascii_start, uint64_t ascii_len)
{
	const uint64_t max_dw = UINT64_MAX / sizeof (uint32_t);

	(void) memset(field, 0, sizeof (nvmeadm_field_t));

	if (off_dw > max_dw) {
		warnx("telemetry log ASCII string offset 0x%" PRIx64 " is "
		    "not representable in a 64-bit quantity", off_dw);
		return (false);
	}

	const uint64_t off = off_dw << 2;
	const uint64_t len = len0 + 1;
	if (len > UINT64_MAX - off) {
		warnx("telemetry log ASCII string would overflow a 64-bit "
		    "quantity: offset 0x%" PRIx64 ", length: %" PRIu64,
		    off, len);
		return (false);
	}

	if (off + len > ascii_start + ascii_len) {
		warnx("telemetry log ASCII string exceeds ASCII table");
		return (false);
	}

	field->nf_len = len;
	field->nf_off = off + ascii_start;
	field->nf_short = "str";
	field->nf_desc = "String";
	/*
	 * Vendors are inconsistent as to whether the string table is padded
	 * with zeros or spaces. Use ASCIIZ here to account for both.
	 */
	field->nf_type = NVMEADM_FT_ASCIIZ;

	return (true);
}

/*
 * The telemetry string table is comprised of a fixed section and then a number
 * of variable sections that point into the ASCII table, somewhat analogous to
 * an ELF string table. There is no good way to see where the various strings
 * begin and end in the ASCII table. There is no strict separator between
 * entries. Entries are space padded to the next u32 aligned point generally;
 * however, the presence or lack of spaces doesn't tell us where something
 * begins or ends.
 *
 * As such, we manually drive this and relate the ASCII strings to the
 * corresponding other tables that we encounter. This isn't the most eloquent;
 * however, there's no other good way to do display this programmatically.
 */
static bool
ocp_vul_telstr_drive(nvmeadm_field_print_t *print, const void *data, size_t len)
{
	const ocp_vul_telstr_t *telstr = data;
	bool ret = true;

	print->fp_header = "Telemetry String Header";
	print->fp_fields = ocp_vul_telstr_fields;
	print->fp_nfields = ARRAY_SIZE(ocp_vul_telstr_fields);
	print->fp_base = "tsh";
	print->fp_data = data;
	print->fp_dlen = len;
	print->fp_off = 0;
	nvmeadm_field_print(print);

	/*
	 * First take care of the 16 FIFOs. If a FIFO has a totally zero string,
	 * then we should ignore it. This is the last data entry that we're
	 * guaranteed we have space for. Everything else after this needs to be
	 * checked for paranoia and consistency.
	 */
	for (size_t i = 0; i < 16; i++) {
		char shrt[32], desc[128];
		nvmeadm_field_t field;
		const uint8_t empty[16] = { 0 };

		(void) snprintf(shrt, sizeof (shrt), "fifo%zu", i);
		(void) snprintf(desc, sizeof (desc), "FIFO %zu", i);
		(void) memset(&field, 0, sizeof (nvmeadm_field_t));
		field.nf_len = sizeof (((ocp_vul_telstr_t *)NULL)->ots_fifo0);
		field.nf_off = offsetof(ocp_vul_telstr_t, ots_fifo0) +
		    i * field.nf_len;
		field.nf_short = shrt;
		field.nf_desc = desc;
		field.nf_type = NVMEADM_FT_ASCIIZ;

		if (memcmp(data + field.nf_off, empty, sizeof (empty)) == 0) {
			continue;
		}

		print->fp_header = NULL;
		print->fp_fields = &field;
		print->fp_nfields = 1;
		nvmeadm_field_print(print);
	}

	/*
	 * Sanity check that the rest of this makes sense. In particular, this
	 * is supposed to be ordered SITS, ESTS, VUETS, ASCTS. Make sure these
	 * don't overlap, that the offsets don't cause an overflow when we
	 * expand them, etc.
	 */
	if (!ocp_vul_telstr_sanity("sit", telstr->ots_sits, telstr->ots_sitz,
	    len) ||
	    !ocp_vul_telstr_sanity("est", telstr->ots_ests, telstr->ots_estz,
	    len) ||
	    !ocp_vul_telstr_sanity("vuest", telstr->ots_vuests,
	    telstr->ots_vuestz, len) ||
	    !ocp_vul_telstr_sanity("asct", telstr->ots_ascts, telstr->ots_asctz,
	    len)) {
		return (false);
	}

	const uint64_t sit_start = telstr->ots_sits << 2;
	const uint64_t sit_len = telstr->ots_sitz << 2;
	const uint64_t est_start = telstr->ots_ests << 2;
	const uint64_t est_len = telstr->ots_estz << 2;
	const uint64_t vu_start = telstr->ots_vuests << 2;
	const uint64_t vu_len = telstr->ots_vuestz << 2;
	const uint64_t ascii_start = telstr->ots_ascts << 2;
	const uint64_t ascii_len = telstr->ots_asctz << 2;

	if (sit_start != offsetof(ocp_vul_telstr_t, ots_data)) {
		warnx("invalid telemetry string table: SIT table starts at "
		    "unexpected offset 0x%" PRIx64, sit_start);
		return (false);
	}

	if (est_start < sit_start + sit_len) {
		warnx("invalid telemetry string table: EST table starts before "
		    "SIT table ends");
		return (false);
	}

	if (vu_start < est_start + est_len) {
		warnx("invalid telemetry string table: VUEST table starts "
		    "before EST table ends");
		return (false);
	}

	if (ascii_start < vu_start + vu_len) {
		warnx("invalid telemetry string table: ASCT table starts "
		    "before VUEST table ends");
		return (false);
	}

	print->fp_header = "Statistic Identifier Table";
	print->fp_base = "sit";
	const uint64_t sit_nents = sit_len / sizeof (ocp_vul_telstr_sit_t);
	for (uint64_t i = 0; i < sit_nents; i++) {
		char shrt[32], desc[128];
		const size_t off = sit_start + i *
		    sizeof (ocp_vul_telstr_sit_t);
		const ocp_vul_telstr_sit_t *sit = data + off;
		nvmeadm_field_t cont;
		nvmeadm_field_t fields[ARRAY_SIZE(ocp_vul_telstr_sit_fields) +
		    1];

		(void) memcpy(fields, ocp_vul_telstr_sit_fields,
		    sizeof (ocp_vul_telstr_sit_fields));
		if (!ocp_vul_telstr_field_str(&fields[ARRAY_SIZE(fields) - 1],
		    sit->ocp_sit_len, sit->ocp_sit_off, ascii_start,
		    ascii_len)) {
			ret = false;
			continue;
		}

		for (size_t f = 0; f < ARRAY_SIZE(fields) - 1; f++) {
			fields[f].nf_off += off;
		}

		(void) snprintf(shrt, sizeof (shrt), "%" PRIu64, i);
		(void) snprintf(desc, sizeof (desc), "SIT Entry %" PRIu64, i);
		(void) memset(&cont, 0, sizeof (nvmeadm_field_t));
		cont.nf_off = 0;
		cont.nf_len = sizeof (ocp_vul_telstr_sit_t);
		cont.nf_short = shrt;
		cont.nf_desc = desc;
		cont.nf_type = NVMEADM_FT_CONTAINER;
		cont.nf_fields = fields;
		cont.nf_nfields = ARRAY_SIZE(fields);

		if (i > 0) {
			print->fp_header = NULL;
		}
		print->fp_fields = &cont;
		print->fp_nfields = 1;

		nvmeadm_field_print(print);

	}

	print->fp_header = "Event Identifier Table";
	print->fp_base = "est";
	const uint64_t est_nents = est_len / sizeof (ocp_vul_telstr_est_t);
	for (uint64_t i = 0; i < est_nents; i++) {
		char shrt[32], desc[128];
		const size_t off = est_start + i *
		    sizeof (ocp_vul_telstr_est_t);
		const ocp_vul_telstr_est_t *est = data + off;
		nvmeadm_field_t cont;
		nvmeadm_field_t fields[ARRAY_SIZE(ocp_vul_telstr_est_fields) +
		    1];

		(void) memcpy(fields, ocp_vul_telstr_est_fields,
		    sizeof (ocp_vul_telstr_est_fields));
		if (!ocp_vul_telstr_field_str(&fields[ARRAY_SIZE(fields) - 1],
		    est->ocp_est_len, est->ocp_est_off, ascii_start,
		    ascii_len)) {
			ret = false;
			continue;
		}

		for (size_t f = 0; f < ARRAY_SIZE(fields) - 1; f++) {
			fields[f].nf_off += off;
		}

		(void) snprintf(shrt, sizeof (shrt), "%" PRIu64, i);
		(void) snprintf(desc, sizeof (desc), "EST Entry %" PRIu64, i);
		(void) memset(&cont, 0, sizeof (nvmeadm_field_t));
		cont.nf_off = 0;
		cont.nf_len = sizeof (ocp_vul_telstr_est_t);
		cont.nf_short = shrt;
		cont.nf_desc = desc;
		cont.nf_type = NVMEADM_FT_CONTAINER;
		cont.nf_fields = fields;
		cont.nf_nfields = ARRAY_SIZE(fields);

		if (i > 0) {
			print->fp_header = NULL;
		}
		print->fp_fields = &cont;
		print->fp_nfields = 1;

		nvmeadm_field_print(print);
	}

	print->fp_header = "Vendor Unique Event Identifier Table";
	print->fp_base = "vuest";
	const uint64_t vuest_nents = vu_len / sizeof (ocp_vul_telstr_vuest_t);
	for (uint64_t i = 0; i < vuest_nents; i++) {
		char shrt[32], desc[128];
		const size_t off = vu_start + i *
		    sizeof (ocp_vul_telstr_vuest_t);
		const ocp_vul_telstr_vuest_t *vuest = data + off;
		nvmeadm_field_t cont;
		nvmeadm_field_t fields[ARRAY_SIZE(ocp_vul_telstr_est_fields) +
		    1];

		(void) memcpy(fields, ocp_vul_telstr_est_fields,
		    sizeof (ocp_vul_telstr_est_fields));
		if (!ocp_vul_telstr_field_str(&fields[ARRAY_SIZE(fields) - 1],
		    vuest->ocp_vuest_len, vuest->ocp_vuest_off, ascii_start,
		    ascii_len)) {
			ret = false;
			continue;
		}

		for (size_t f = 0; f < ARRAY_SIZE(fields) - 1; f++) {
			fields[f].nf_off += off;
		}

		(void) snprintf(shrt, sizeof (shrt), "%" PRIu64, i);
		(void) snprintf(desc, sizeof (desc), "VUEST Entry %" PRIu64, i);
		(void) memset(&cont, 0, sizeof (nvmeadm_field_t));
		cont.nf_off = 0;
		cont.nf_len = sizeof (ocp_vul_telstr_vuest_t);
		cont.nf_short = shrt;
		cont.nf_desc = desc;
		cont.nf_type = NVMEADM_FT_CONTAINER;
		cont.nf_fields = fields;
		cont.nf_nfields = ARRAY_SIZE(fields);

		if (i > 0) {
			print->fp_header = NULL;
		}
		print->fp_fields = &cont;
		print->fp_nfields = 1;

		nvmeadm_field_print(print);
	}

	return (ret);
}

const nvmeadm_log_field_info_t ocp_vul_telstr_field_info = {
	.nlfi_log = "ocp/telstr",
	.nlfi_min = sizeof (ocp_vul_telstr_t),
	.nlfi_getrev = ocp_vul_telstr_getvers,
	.nlfi_drive = ocp_vul_telstr_drive
};
