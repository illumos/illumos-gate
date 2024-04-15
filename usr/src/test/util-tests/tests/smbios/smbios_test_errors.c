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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Collection of functions to be used with tests that will cause a handle to
 * fail to open.
 */

#include "smbios_test.h"

boolean_t
smbios_test_badvers_mktable(smbios_test_table_t *table)
{
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

typedef int (*smbios_lookup_f)(smbios_hdl_t *, id_t, void *);
typedef struct {
	smbios_lookup_f sif_func;
	const char *sif_name;
} smbios_info_func_t;

static smbios_info_func_t smbios_lookup_funcs[] = {
	{ (smbios_lookup_f)smbios_info_bboard, "bboard" },
	{ (smbios_lookup_f)smbios_info_chassis, "chassis" },
	{ (smbios_lookup_f)smbios_info_processor, "processor" },
	{ (smbios_lookup_f)smbios_info_extprocessor, "extprocessor" },
	{ (smbios_lookup_f)smbios_info_cache, "cache" },
	{ (smbios_lookup_f)smbios_info_pointdev, "pointdev" },
	{ (smbios_lookup_f)smbios_info_battery, "battery" },
	{ (smbios_lookup_f)smbios_info_port, "port" },
	{ (smbios_lookup_f)smbios_info_extport, "extport" },
	{ (smbios_lookup_f)smbios_info_slot, "slot" },
	{ (smbios_lookup_f)smbios_info_obdevs_ext, "obdevs_ext" },
	{ (smbios_lookup_f)smbios_info_memarray, "memarray" },
	{ (smbios_lookup_f)smbios_info_extmemarray, "extmemarray" },
	{ (smbios_lookup_f)smbios_info_memarrmap, "memarrmap" },
	{ (smbios_lookup_f)smbios_info_memdevice, "memdevice" },
	{ (smbios_lookup_f)smbios_info_memdevmap, "memdevmap" },
	{ (smbios_lookup_f)smbios_info_vprobe, "vprobe" },
	{ (smbios_lookup_f)smbios_info_cooldev, "cooldev" },
	{ (smbios_lookup_f)smbios_info_tprobe, "tprobe" },
	{ (smbios_lookup_f)smbios_info_iprobe, "iprobe" },
	{ (smbios_lookup_f)smbios_info_powersup, "powersup" },
	{ (smbios_lookup_f)smbios_info_addinfo_nents, "addinfo" },
	{ (smbios_lookup_f)smbios_info_pciexrc, "pciexrc" },
	{ (smbios_lookup_f)smbios_info_processor_info, "processor_info" },
	{ (smbios_lookup_f)smbios_info_processor_riscv, "processor_riscv" },
	{ (smbios_lookup_f)smbios_info_strprop, "strprop" },
	{ (smbios_lookup_f)smbios_info_fwinfo, "fwinfo" }
};

/*
 * Go through and verify that if we give an explicit lookup a bad id, it
 * properly detects that and errors. We simply use SMB_ID_NOTSUP, which should
 * always trigger the internal lookup to fail. In addition, we always pass NULL
 * for the actual data pointer to make sure that if we get further, we'll crash
 * on writing to a NULL pointer.
 */
boolean_t
smbios_test_verify_badids(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;

	for (size_t i = 0; i < ARRAY_SIZE(smbios_lookup_funcs); i++) {
		if (smbios_lookup_funcs[i].sif_func(hdl, SMB_ID_NOTSUP, NULL) !=
		    -1) {
			warnx("smbios_info_%s somehow didn't fail?!",
			    smbios_lookup_funcs[i].sif_name);
			ret = B_FALSE;
		}
	}

	return (ret);
}
