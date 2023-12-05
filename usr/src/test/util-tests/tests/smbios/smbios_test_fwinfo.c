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

static const char *smbios_fwinfo_name = "Sheikah Slate";
static const char *smbios_fwinfo_vers = "1.3.1";
static const char *smbios_fwinfo_id = "ganon";
static const char *smbios_fwinfo_reldate = "2017-03-03";
static const char *smbios_fwinfo_mfg = "The Goddess Hylia";
static const char *smbios_fwinfo_lsv = "zelda";
static const uint64_t smbios_fwinfo_size = 0xb0111b;
static const uint_t smbios_fwinfo_ncomps = 23;
static const uint8_t smbios_fwinfo_versid = 0x66;

static void
smbios_test_fwinfo_mktable_common_fwinfo(smb_fwinfo_t *fw)
{
	fw->smbfwii_hdr.smbh_type = SMB_TYPE_FWINFO;
	fw->smbfwii_hdr.smbh_len = sizeof (*fw);
	fw->smbfwii_name = 1;
	fw->smbfwii_vers = 2;
	fw->smbfwii_vers_fmt = smbios_fwinfo_versid;
	fw->smbfwii_id = 3;
	fw->smbfwii_id_fmt = smbios_fwinfo_versid;
	fw->smbfwii_reldate = 4;
	fw->smbfwii_mfg = 5;
	fw->smbfwii_lsv = 6;
	fw->smbfwii_imgsz = htole64(smbios_fwinfo_size);
	fw->smbfwii_chars = SMB_FWC_WP;
	fw->smbfwii_state = SMB_FWS_UA_OFFLINE;
	fw->smbfwii_ncomps = 0;
}

static void
smbios_test_fwinfo_mktable_common_fini(smbios_test_table_t *table)
{
	smbios_test_table_append_string(table, smbios_fwinfo_name);
	smbios_test_table_append_string(table, smbios_fwinfo_vers);
	smbios_test_table_append_string(table, smbios_fwinfo_id);
	smbios_test_table_append_string(table, smbios_fwinfo_reldate);
	smbios_test_table_append_string(table, smbios_fwinfo_mfg);
	smbios_test_table_append_string(table, smbios_fwinfo_lsv);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);
}

/*
 * Generate a table that's too short to get basic info.
 */
boolean_t
smbios_test_fwinfo_mktable_invlen_base(smbios_test_table_t *table)
{
	smb_header_t hdr;

	hdr.smbh_type = SMB_TYPE_FWINFO;
	hdr.smbh_len = sizeof (hdr);

	(void) smbios_test_table_append(table, &hdr, sizeof (hdr));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

/*
 * Generate a table where the table is too short for a specified number of
 * components.
 */
boolean_t
smbios_test_fwinfo_mktable_invlen_comps(smbios_test_table_t *table)
{
	smb_fwinfo_t fw;

	smbios_test_fwinfo_mktable_common_fwinfo(&fw);
	fw.smbfwii_ncomps = smbios_fwinfo_ncomps;
	(void) smbios_test_table_append(table, &fw, sizeof (fw));
	smbios_test_fwinfo_mktable_common_fini(table);

	return (B_TRUE);
}

boolean_t
smbios_test_fwinfo_mktable_nocomps(smbios_test_table_t *table)
{
	smb_fwinfo_t fw;

	smbios_test_fwinfo_mktable_common_fwinfo(&fw);
	(void) smbios_test_table_append(table, &fw, sizeof (fw));
	smbios_test_fwinfo_mktable_common_fini(table);

	return (B_TRUE);
}

boolean_t
smbios_test_fwinfo_mktable_comps(smbios_test_table_t *table)
{
	smb_fwinfo_t fw;

	smbios_test_fwinfo_mktable_common_fwinfo(&fw);

	fw.smbfwii_hdr.smbh_len += smbios_fwinfo_ncomps * sizeof (uint16_t);
	fw.smbfwii_ncomps = smbios_fwinfo_ncomps;
	(void) smbios_test_table_append(table, &fw, sizeof (fw));

	for (uint_t i = 0; i < fw.smbfwii_ncomps; i++) {
		uint16_t comp = 0x2300 + i;

		smbios_test_table_append_raw(table, &comp, sizeof (comp));
	}
	smbios_test_fwinfo_mktable_common_fini(table);

	return (B_TRUE);
}

boolean_t
smbios_test_fwinfo_verify_badtype(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_fwinfo_t fw;

	if (smbios_lookup_type(hdl, SMB_TYPE_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_fwinfo(hdl, sp.smbstr_id, &fw) != -1) {
		warnx("accidentally parsed invalid fwinfo information as "
		    "valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_TYPE) {
		warnx("encountered wrong error for fwinfo, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
smbios_test_fwinfo_verify_invlen_base(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_fwinfo_t fw;

	if (smbios_lookup_type(hdl, SMB_TYPE_FWINFO, &sp) == -1) {
		warnx("failed to lookup SMBIOS fwinfo: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_fwinfo(hdl, sp.smbstr_id, &fw) != -1) {
		warnx("accidentally parsed invalid fwinfo information as "
		    "valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for fwinfo, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
smbios_test_fwinfo_verify_common(smbios_hdl_t *hdl, smbios_struct_t *sp,
    const smbios_fwinfo_t *fw)
{
	boolean_t ret = B_TRUE;
	smbios_info_t info;

	if (strcmp(fw->smbfw_name, smbios_fwinfo_name) != 0) {
		warnx("firmware inventory name mismatch, found %s",
		    fw->smbfw_name);
		ret = B_FALSE;
	}

	if (strcmp(fw->smbfw_id, smbios_fwinfo_id) != 0) {
		warnx("firmware inventory id mismatch, found %s",
		    fw->smbfw_id);
		ret = B_FALSE;
	}

	if (strcmp(fw->smbfw_reldate, smbios_fwinfo_reldate) != 0) {
		warnx("firmware inventory release date mismatch, found %s",
		    fw->smbfw_reldate);
		ret = B_FALSE;
	}

	if (strcmp(fw->smbfw_lsv, smbios_fwinfo_lsv) != 0) {
		warnx("firmware inventory lsv mismatch, found %s",
		    fw->smbfw_lsv);
		ret = B_FALSE;
	}

	if (fw->smbfw_imgsz != smbios_fwinfo_size) {
		warnx("firmware inventory size mismatch, found 0x%" PRIx64,
		    fw->smbfw_imgsz);
		ret = B_FALSE;
	}

	if (fw->smbfw_chars != SMB_FWC_WP) {
		warnx("firmware inventory chars mismatch, found 0x%x",
		    fw->smbfw_chars);
		ret = B_FALSE;
	}

	if (fw->smbfw_state != SMB_FWS_UA_OFFLINE) {
		warnx("firmware inventory state mismatch, found 0x%x",
		    fw->smbfw_state);
		ret = B_FALSE;
	}

	if (fw->smbfw_vers_fmt != smbios_fwinfo_versid) {
		warnx("firmware inventory version format mismatch, found 0x%x",
		    fw->smbfw_vers_fmt);
		ret = B_FALSE;
	}

	if (fw->smbfw_id_fmt != smbios_fwinfo_versid) {
		warnx("firmware inventory ID format mismatch, found 0x%x",
		    fw->smbfw_id_fmt);
		ret = B_FALSE;
	}

	if (smbios_info_common(hdl, sp->smbstr_id, &info) == -1) {
		warnx("failed to get firmware inventory common items: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (strcmp(info.smbi_manufacturer, smbios_fwinfo_mfg) != 0) {
		warnx("firmware inventory manufacturer mismatch, found %s",
		    info.smbi_manufacturer);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_version, smbios_fwinfo_vers) != 0) {
		warnx("firmware inventory version mismatch, found %s",
		    info.smbi_version);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_fwinfo_verify_nocomps(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_fwinfo_t fw;
	uint_t ncomps;
	smbios_fwinfo_comp_t *comps;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_FWINFO, &sp) == -1) {
		warnx("failed to lookup SMBIOS fwinfo: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_fwinfo(hdl, sp.smbstr_id, &fw) == -1) {
		warnx("failed to get firmware inventory: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_fwinfo_verify_common(hdl, &sp, &fw)) {
		ret = B_FALSE;
	}

	if (fw.smbfw_ncomps != 0) {
		warnx("firmware inventory ncomps mismatch, found 0x%x",
		    fw.smbfw_ncomps);
		ret = B_FALSE;
	}

	if (smbios_info_fwinfo_comps(hdl, sp.smbstr_id, &ncomps, &comps) != 0) {
		warnx("failed to get components: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		ret = B_FALSE;
	}

	if (ncomps != 0) {
		warnx("smbios_info_fwinfo_comps() returned wrong number of "
		    "comps: 0x%x", ncomps);
		ret = B_FALSE;
	}

	if (comps != NULL) {
		warnx("smbios_info_fwinfo_comps() gave a non-NULL comps "
		    "pointer: %p", comps);
		ret = B_FALSE;
	}

	smbios_info_fwinfo_comps_free(hdl, ncomps, comps);

	return (ret);
}

boolean_t
smbios_test_fwinfo_verify_invlen_comps(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_fwinfo_t fw;
	uint_t ncomps;
	smbios_fwinfo_comp_t *comps;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_FWINFO, &sp) == -1) {
		warnx("failed to lookup SMBIOS fwinfo: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_fwinfo(hdl, sp.smbstr_id, &fw) == -1) {
		warnx("failed to get firmware inventory: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_fwinfo_verify_common(hdl, &sp, &fw)) {
		ret = B_FALSE;
	}

	if (fw.smbfw_ncomps != smbios_fwinfo_ncomps) {
		warnx("firmware inventory ncomps mismatch, found 0x%x",
		    fw.smbfw_ncomps);
		ret = B_FALSE;
	}

	if (smbios_info_fwinfo_comps(hdl, sp.smbstr_id, &ncomps, &comps) !=
	    -1) {
		warnx("accidentally parsed invalid fwinfo components as "
		    "valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for fwinfo comps, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (ret);
}



boolean_t
smbios_test_fwinfo_verify_comps(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_fwinfo_t fw;
	uint_t ncomps;
	smbios_fwinfo_comp_t *comps;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_FWINFO, &sp) == -1) {
		warnx("failed to lookup SMBIOS fwinfo: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_fwinfo(hdl, sp.smbstr_id, &fw) == -1) {
		warnx("failed to get firmware inventory: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_fwinfo_verify_common(hdl, &sp, &fw)) {
		ret = B_FALSE;
	}

	if (fw.smbfw_ncomps != smbios_fwinfo_ncomps) {
		warnx("firmware inventory ncomps mismatch, found 0x%x",
		    fw.smbfw_ncomps);
		ret = B_FALSE;
	}

	if (smbios_info_fwinfo_comps(hdl, sp.smbstr_id, &ncomps, &comps) != 0) {
		warnx("failed to get components: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		ret = B_FALSE;
	}

	if (ncomps != smbios_fwinfo_ncomps) {
		warnx("smbios_info_fwinfo_comps() returned wrong number of "
		    "comps: 0x%x", ncomps);
		ret = B_FALSE;
	}

	if (comps == NULL) {
		warnx("smbios_info_fwinfo_comps() gave a NULL comps pointer");
		ret = B_FALSE;
	} else {
		for (uint_t i = 0; i < smbios_fwinfo_ncomps; i++) {
			if (comps[i].smbfwe_id != 0x2300 + i) {
				warnx("component id %u is wrong: 0x%" _PRIxID,
				    i, comps[i].smbfwe_id);
				ret = B_FALSE;
			}
		}
	}

	smbios_info_fwinfo_comps_free(hdl, ncomps, comps);

	return (ret);
}
