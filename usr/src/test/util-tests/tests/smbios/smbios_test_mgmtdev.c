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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Basic tests for the SMBIOS Management Device and Component. Types 34 and 35.
 */

#include "smbios_test.h"

static const char *smbios_dev_desc = "Black Mage";
static const char *smbios_comp_desc = "White Mage";

boolean_t
smbios_test_mgmtdev_mktable(smbios_test_table_t *table)
{
	smb_mgmtdev_t md;

	bzero(&md, sizeof (md));
	md.smbmgd_hdr.smbh_type = SMB_TYPE_MGMTDEV;
	md.smbmgd_hdr.smbh_len = sizeof (md);
	md.smbmgd_desc = 1;
	md.smbmgd_dtype = SMB_MGMTDEV_DT_LM79;
	md.smbmgd_addr = 0x42;
	md.smbmgd_atype = SMB_MGMTDEV_AT_SMBUS;

	(void) smbios_test_table_append(table, &md, sizeof (md));
	smbios_test_table_append_string(table, smbios_dev_desc);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_mgmtdev_verify(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_mgmtdev_t md;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_MGMTDEV, &sp) == -1) {
		warnx("failed to lookup SMBIOS management device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_mgmtdev(hdl, sp.smbstr_id, &md) == -1) {
		warnx("failed to get management device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (strcmp(md.smbmd_desc, smbios_dev_desc) != 0) {
		warnx("management device description mismatch: found %s, "
		    "expected %s", md.smbmd_desc, smbios_dev_desc);
		ret = B_FALSE;
	}

	if (md.smbmd_dtype != SMB_MGMTDEV_DT_LM79) {
		warnx("management device device type mismatch: found 0x%x, "
		    "expected 0x%x", md.smbmd_dtype, SMB_MGMTDEV_DT_LM79);
		ret = B_FALSE;
	}

	if (md.smbmd_addr != 0x42) {
		warnx("management device address mismatch: found 0x%x, "
		    "expected 0x42", md.smbmd_addr);
		ret = B_FALSE;
	}

	if (md.smbmd_atype != SMB_MGMTDEV_AT_SMBUS) {
		warnx("management device address type mismatch: found 0x%x, "
		    "expected 0x%x", md.smbmd_atype, SMB_MGMTDEV_AT_SMBUS);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_mgmtcomp_mktable(smbios_test_table_t *table)
{
	smb_mgmtcomp_t mc;

	bzero(&mc, sizeof (mc));
	mc.smbmgc_hdr.smbh_type = SMB_TYPE_MGMTDEVCP;
	mc.smbmgc_hdr.smbh_len = sizeof (mc);
	mc.smbmgc_desc = 1;
	mc.smbmgc_mgmtdev = 0x1234;
	mc.smbmgc_comp = 0x5678;
	mc.smbmgc_thresh = 0x789a;

	(void) smbios_test_table_append(table, &mc, sizeof (mc));
	smbios_test_table_append_string(table, smbios_comp_desc);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_mgmtcomp_verify(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_mgmtcomp_t mc;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_MGMTDEVCP, &sp) == -1) {
		warnx("failed to lookup SMBIOS management component: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_mgmtcomp(hdl, sp.smbstr_id, &mc) == -1) {
		warnx("failed to get management component: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (strcmp(mc.smbmc_desc, smbios_comp_desc) != 0) {
		warnx("management component description mismatch: found %s, "
		    "expected %s", mc.smbmc_desc, smbios_comp_desc);
		ret = B_FALSE;
	}

	if (mc.smbmc_mgmtdev != 0x1234) {
		warnx("management component mgmt dev handle mismatch: found "
		    "0x%" _PRIxID ", expected 0x1234", mc.smbmc_mgmtdev);
		ret = B_FALSE;
	}

	if (mc.smbmc_comp != 0x5678) {
		warnx("management component component handle mismatch: found "
		    "0x%" _PRIxID ", expected 0x5678", mc.smbmc_comp);
		ret = B_FALSE;
	}

	if (mc.smbmc_thresh != 0x789a) {
		warnx("management component threshold handle mismatch: found "
		    "0x%" _PRIxID ", expected 0x789a", mc.smbmc_thresh);
		ret = B_FALSE;
	}

	return (ret);
}
