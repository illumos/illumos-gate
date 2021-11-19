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
 * Tests for SMBIOS type 46 - SMB_TYPE_STRPROP.
 */

#include "smbios_test.h"

static const char *smbios_strprop_path = "/not/really/uefi";
static uint16_t smbios_strprop_hdl = 0xcafe;

boolean_t
smbios_test_strprop_mktable_basic(smbios_test_table_t *table)
{
	smb_strprop_t str;

	str.smbstrp_hdr.smbh_type = SMB_TYPE_STRPROP;
	str.smbstrp_hdr.smbh_len = sizeof (str);
	str.smbstrp_prop_id = htole16(SMB_STRP_UEFI_DEVPATH);
	str.smbstrp_prop_val = 1;
	str.smbstrp_phdl = htole16(smbios_strprop_hdl);

	(void) smbios_test_table_append(table, &str, sizeof (str));
	smbios_test_table_append_string(table, smbios_strprop_path);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_strprop_mktable_badstr(smbios_test_table_t *table)
{
	smb_strprop_t str;

	str.smbstrp_hdr.smbh_type = SMB_TYPE_STRPROP;
	str.smbstrp_hdr.smbh_len = sizeof (str);
	str.smbstrp_prop_id = htole16(SMB_STRP_UEFI_DEVPATH);
	str.smbstrp_prop_val = 0x23;
	str.smbstrp_phdl = htole16(smbios_strprop_hdl);

	(void) smbios_test_table_append(table, &str, sizeof (str));
	smbios_test_table_append_string(table, smbios_strprop_path);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_strprop_mktable_invlen1(smbios_test_table_t *table)
{
	smb_header_t hdr;

	hdr.smbh_type = SMB_TYPE_STRPROP;
	hdr.smbh_len = sizeof (hdr);

	(void) smbios_test_table_append(table, &hdr, sizeof (hdr));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_strprop_mktable_invlen2(smbios_test_table_t *table)
{
	smb_strprop_t str;
	const uint8_t endstring = 0;

	str.smbstrp_hdr.smbh_type = SMB_TYPE_STRPROP;
	str.smbstrp_hdr.smbh_len = sizeof (str) + 1;
	str.smbstrp_prop_id = htole16(0);
	str.smbstrp_prop_val = 0;
	str.smbstrp_phdl = htole16(0);

	/*
	 * Append the end string again as to get us to our additional byte of
	 * actual table length.
	 */
	(void) smbios_test_table_append(table, &str, sizeof (str));
	(void) smbios_test_table_append_raw(table, &endstring,
	    sizeof (endstring));
	(void) smbios_test_table_append_string(table, smbios_strprop_path);
	(void) smbios_test_table_append_raw(table, &endstring,
	    sizeof (endstring));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

static boolean_t
smbios_test_strprop_verify_badtable(smbios_hdl_t *hdl, int smberr)
{
	smbios_struct_t sp;
	smbios_strprop_t prop;

	if (smbios_lookup_type(hdl, SMB_TYPE_STRPROP, &sp) == -1) {
		warnx("failed to lookup SMBIOS strprop: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_strprop(hdl, sp.smbstr_id, &prop) != -1) {
		warnx("accidentally parsed invalid strprop information as "
		    "valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != smberr) {
		warnx("encountered wrong error for strprop, expected: "
		    "0x%x, found: 0x%x", smberr, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
smbios_test_strprop_verify_invlen1(smbios_hdl_t *hdl)
{
	return (smbios_test_strprop_verify_badtable(hdl, ESMB_SHORT));
}

boolean_t
smbios_test_strprop_verify_invlen2(smbios_hdl_t *hdl)
{
	return (smbios_test_strprop_verify_badtable(hdl, ESMB_CORRUPT));
}

boolean_t
smbios_test_strprop_verify_badtype(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_strprop_t prop;

	/*
	 * Here we've explicitly created a table with a memory device that we're
	 * going to try and look up as well, not that.
	 */
	if (smbios_lookup_type(hdl, SMB_TYPE_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_strprop(hdl, sp.smbstr_id, &prop) != -1) {
		warnx("accidentally parsed invalid strprop information as "
		    "valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_TYPE) {
		warnx("encountered wrong error for strprop, expected: "
		    "0x%x, found: 0x%x", ESMB_TYPE, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);

}

boolean_t
smbios_test_strprop_verify_basic(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_strprop_t prop;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_STRPROP, &sp) == -1) {
		warnx("failed to lookup SMBIOS strprop: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_strprop(hdl, sp.smbstr_id, &prop) != 0) {
		warnx("failed to get SMBIOS strprop: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (prop.smbsp_prop_id != SMB_STRP_UEFI_DEVPATH) {
		warnx("property id incorrect, expected 0x%x, found 0x %x",
		    SMB_STRP_UEFI_DEVPATH, prop.smbsp_prop_id);
		ret = B_FALSE;
	}

	if (strcmp(smbios_strprop_id_desc(prop.smbsp_prop_id),
	    "UEFI device path") != 0) {
		warnx("property id string incorrect, found %s",
		    smbios_strprop_id_desc(prop.smbsp_prop_id));
		ret = B_FALSE;
	}

	if (strcmp(prop.smbsp_prop_val, smbios_strprop_path) != 0) {
		warnx("property value incorrect, found %s",
		    prop.smbsp_prop_val);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_strprop_verify_badstr(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_strprop_t prop;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_STRPROP, &sp) == -1) {
		warnx("failed to lookup SMBIOS strprop: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_strprop(hdl, sp.smbstr_id, &prop) != 0) {
		warnx("failed to get SMBIOS strprop: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (prop.smbsp_prop_id != SMB_STRP_UEFI_DEVPATH) {
		warnx("property id incorrect, expected 0x%x, found 0x %x",
		    SMB_STRP_UEFI_DEVPATH, prop.smbsp_prop_id);
		ret = B_FALSE;
	}

	if (strcmp(smbios_strprop_id_desc(prop.smbsp_prop_id),
	    "UEFI device path") != 0) {
		warnx("property id string incorrect, found %s",
		    smbios_strprop_id_desc(prop.smbsp_prop_id));
		ret = B_FALSE;
	}

	if (strcmp(prop.smbsp_prop_val, "") != 0) {
		warnx("property value incorrect, found %s",
		    prop.smbsp_prop_val);
		ret = B_FALSE;
	}

	return (ret);
}
