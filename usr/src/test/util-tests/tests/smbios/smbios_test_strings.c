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
 * Copyright 2021 Oxide Computer Company
 */

/*
 * This is a hodgepodge to validate that the string tables are directionally
 * correct.
 */

#include "smbios_test.h"

typedef const char *(*smbios_strfunc_f)(uint_t);

typedef struct smbios_strtest {
	smbios_strfunc_f	ss_func;
	uint_t			ss_num;
	const char		*ss_str;
} smbios_strtest_t;

static smbios_strtest_t smbios_strs[] = {
	{ smbios_battery_chem_desc, SMB_BDC_LEADACID, "Lead Acid" },
	{ smbios_bboard_flag_name, SMB_BBFL_NEEDAUX, "SMB_BBFL_NEEDAUX" },
	{ smbios_bboard_flag_name, SMB_BBFL_HOTSWAP, "SMB_BBFL_HOTSWAP" },
	{ smbios_bboard_flag_desc, SMB_BBFL_REMOVABLE, "board is removable" },
	{ smbios_bboard_flag_desc, SMB_BBFL_HOTSWAP, "board is hot-swappable" },
	{ smbios_bboard_type_desc, SMB_BBT_PROC, "processor module" },
	{ smbios_bboard_type_desc, SMB_BBT_MOTHER, "motherboard" },
	{ smbios_bios_xb1_desc, SMB_BIOSXB1_ACPI, "ACPI is supported" },
	{ smbios_bios_xb1_name, SMB_BIOSXB1_ACPI, "SMB_BIOSXB1_ACPI" },
	{ smbios_bios_xb2_desc,	SMB_BIOSXB2_VM, "SMBIOS table describes a VM" },
	{ smbios_bios_xb2_name, SMB_BIOSXB2_UEFI, "SMB_BIOSXB2_UEFI" },
	{ smbios_boot_desc, SMB_BOOT_NOMEDIA, "no bootable media" },
	{ smbios_cache_assoc_desc, SMB_CAA_4WAY, "4-way set associative" },
	{ smbios_cache_ctype_desc, SMB_CAT_BURST, "burst" },
	{ smbios_cache_ctype_desc, SMB_CAT_SYNC, "synchronous" },
	{ smbios_cache_ctype_name, SMB_CAT_ASYNC, "SMB_CAT_ASYNC" },
	{ smbios_cache_ecc_desc, SMB_CAE_PARITY, "parity" },
	{ smbios_cache_flag_desc, SMB_CAF_SOCKETED, "cache is socketed" },
	{ smbios_cache_flag_name, SMB_CAF_ENABLED, "SMB_CAF_ENABLED" },
	{ smbios_cache_logical_desc, SMB_CAG_INSTR, "instruction" },
	{ smbios_cache_mode_desc, SMB_CAM_WB, "write-back" },
	{ smbios_chassis_type_desc, SMB_CHT_PIZZA, "pizza box" },
	{ smbios_chassis_state_desc, SMB_CHST_SAFE, "safe" },
	{ smbios_evlog_flag_desc, SMB_EVFL_VALID, "log area valid" },
	{ smbios_evlog_flag_name, SMB_EVFL_FULL, "SMB_EVFL_FULL" },
	{ smbios_evlog_format_desc, SMB_EVHF_F1, "DMTF log header type 1" },
	{ smbios_evlog_method_desc, SMB_EVM_GPNV,
	    "GP Non-Volatile API Access" },
	{ smbios_fwinfo_ch_name, SMB_FWC_UPDATE, "SMB_FWC_UPDATE" },
	{ smbios_fwinfo_ch_desc, SMB_FWC_WP, "write-protect" },
	{ smbios_fwinfo_id_desc, SMB_FWI_UEFI, "UEFI GUID" },
	{ smbios_fwinfo_state_desc, SMB_FWS_DISABLED, "disabled" },
	{ smbios_fwinfo_state_desc, SMB_FWS_STB_SPARE, "standby spare" },
	{ smbios_fwinfo_vers_desc, SMB_FWV_HEX64, "64-bit hex" },
	{ smbios_vprobe_loc_desc, SMB_VPROBE_L_PROC, "processor" },
	{ smbios_vprobe_loc_desc, SMB_VPROBE_L_PROCMOD, "processor module" },
	{ smbios_vprobe_status_desc, SMB_VPROBE_S_CRIT, "critical" },
	{ smbios_cooldev_status_desc, SMB_COOLDEV_S_OK, "OK" },
	{ smbios_cooldev_type_desc, SMB_COOLDEV_T_FAN, "fan" },
	{ smbios_tprobe_loc_desc, SMB_TPROBE_L_DISK, "disk" },
	{ smbios_tprobe_status_desc, SMB_TPROBE_S_NONRECOV, "non-recoverable" },
	{ smbios_iprobe_loc_desc, SMB_IPROBE_L_AIC, "add-in card" },
	{ smbios_iprobe_status_desc, SMB_IPROBE_S_UNKNOWN, "unknown" },
	{ smbios_ipmi_flag_desc, SMB_IPMI_F_INTRHIGH,
	    "intr active high (else low)" },
	{ smbios_ipmi_flag_name, SMB_IPMI_F_IOADDR,
	    "SMB_IPMI_F_IOADDR" },
	{ smbios_ipmi_type_desc, SMB_IPMI_T_KCS,
	    "KCS: Keyboard Controller Style" },
	{ smbios_powersup_flag_name, SMB_POWERSUP_F_PRESENT,
	    "SMB_POWERSUP_F_PRESENT" },
	{ smbios_powersup_flag_desc, SMB_POWERSUP_F_HOT,
	    "PSU is hot-replaceable" },
	{ smbios_powersup_input_desc, SMB_POWERSUP_I_WIDE, "wide range" },
	{ smbios_powersup_status_desc, SMB_POWERSUP_S_OK, "OK" },
	{ smbios_powersup_type_desc, SMB_POWERSUP_T_UPS, "UPS" },
	{ smbios_hwsec_desc, SMB_HWSEC_PS_ENABLED, "password enabled" },
	{ smbios_memarray_loc_desc, SMB_MAL_NUBUS, "NuBus" },
	{ smbios_memarray_use_desc, SMB_MAU_CACHE, "cache memory" },
	{ smbios_memarray_ecc_desc, SMB_MAE_CRC, "CRC" },
	{ smbios_memdevice_form_desc, SMB_MDFF_ZIP, "ZIP" },
	{ smbios_memdevice_type_desc, SMB_MDT_LPDDR5, "LPDDR5" },
	{ smbios_memdevice_flag_name, SMB_MDF_EDO, "SMB_MDF_EDO" },
	{ smbios_memdevice_flag_desc, SMB_MDF_PSTATIC, "pseudo-static" },
	{ smbios_memdevice_rank_desc, SMB_MDR_OCTAL, "octal" },
	{ smbios_memdevice_memtech_desc, SMB_MTECH_DRAM, "DRAM" },
	{ smbios_memdevice_op_capab_name, SMB_MOMC_VOLATILE,
	    "SMB_MOMC_VOLATILE" },
	{ smbios_memdevice_op_capab_desc, SMB_MOMC_BLOCK_PM,
	    "Block-accessible persistent memory" },
	{ smbios_onboard_type_desc, SMB_OBT_SAS, "sas" },
	{ smbios_onboard_ext_type_desc, SMB_OBET_EMMC, "eMMC" },
	{ smbios_pointdev_iface_desc, SMB_PDI_PS2, "PS/2" },
	{ smbios_pointdev_type_desc, SMB_PDT_TOPAD, "Touch Pad" },
	{ smbios_port_conn_desc, SMB_POC_RJ45, "RJ-45" },
	{ smbios_port_type_desc, SMB_POT_NETWORK, "Network port" },
	{ smbios_processor_family_desc, SMB_PRF_HOBBIT, "Hobbit" },
	{ smbios_processor_status_desc, SMB_PRS_IDLE, "waiting to be enabled" },
	{ smbios_processor_type_desc, SMB_PRT_DSP, "DSP processor" },
	{ smbios_processor_upgrade_desc, SMB_PRU_SP3, "socket SP3" },
	{ smbios_processor_core_flag_name, SMB_PRC_PM, "SMB_PRC_PM" },
	{ smbios_processor_core_flag_desc, SMB_PRC_MC, "multi-core" },
	{ smbios_processor_info_type_desc, SMB_PROCINFO_T_AARCH64,
	    "64-bit ARM (aarch64)" },
	{ smbios_riscv_priv_desc, SMB_RV_PRIV_S, "Supervisor Mode" },
	{ smbios_riscv_priv_name, SMB_RV_PRIV_U, "SMB_RV_PRIV_U" },
	{ smbios_riscv_width_desc, SMB_RV_WIDTH_64B, "64-bit" },
	{ smbios_slot_type_desc, SMB_SLT_AGP, "AGP" },
	{ smbios_slot_width_desc, SMB_SLW_32X, "32x or x32" },
	{ smbios_slot_usage_desc, SMB_SLU_AVAIL, "available" },
	{ smbios_slot_length_desc, SMB_SLL_LONG, "long length" },
	{ smbios_slot_ch1_desc, SMB_SLCH1_33V, "provides 3.3V" },
	{ smbios_slot_ch1_name, SMB_SLCH1_PCMRR, "SMB_SLCH1_PCMRR" },
	{ smbios_slot_ch2_desc, SMB_SLCH2_HOTPLUG,
	    "slot supports hot-plug devices" },
	{ smbios_slot_ch2_name, SMB_SLCH2_CXL2, "SMB_SLCH2_CXL2" },
	{ smbios_slot_height_desc, SMB_SLHT_FULL, "full height" },
	{ smbios_strprop_id_desc, SMB_STRP_UEFI_DEVPATH, "UEFI device path" },
	{ smbios_type_desc, SMB_TYPE_COOLDEV, "cooling device" },
	{ smbios_type_name, SMB_TYPE_POWERSUP, "SMB_TYPE_POWERSUP" },
	{ smbios_system_wakeup_desc, SMB_WAKEUP_LAN, "LAN remote" },
};

boolean_t
smbios_test_verify_strings(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;

	for (uint_t i = 0; i < ARRAY_SIZE(smbios_strs); i++) {
		uint_t in = smbios_strs[i].ss_num;
		const char *exp = smbios_strs[i].ss_str;
		const char *out = smbios_strs[i].ss_func(in);

		if (out == NULL) {
			warnx("failed to look up string, expected %u->%s",
			    in, exp);
			ret = B_FALSE;
		} else if (strcmp(exp, out) != 0) {
			warnx("found wrong string for %u->%s: %s", in, exp,
			    out);
			ret = B_FALSE;
		}
	}

	return (ret);
}
