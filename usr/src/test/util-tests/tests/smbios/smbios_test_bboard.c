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
 * Tests for SMBIOS Baseboard, Type 2.
 */

#include "smbios_test.h"

static const char *bb_mfg = "Symphonia";
static const char *bb_prod = "Abyss";
static const char *bb_version = "Arise";
static const char *bb_serial = "Vesperia";
static const char *bb_asset = "Xilia";
static const char *bb_location = "Destiny";
static const uint16_t bb_chassis = 0x4224;
static const uint8_t bb_flags = SMB_BBFL_MOTHERBOARD | SMB_BBFL_HOTSWAP;
static const uint8_t bb_type = SMB_BBT_CSWITCH;
static const uint16_t bb_ents[] = { 0x42, 0x169, 0x7777, UINT16_MAX };

boolean_t
smbios_test_bboard_mktable_short(smbios_test_table_t *table)
{
	smb_header_t hdr;

	hdr.smbh_type = SMB_TYPE_BASEBOARD;
	hdr.smbh_len = sizeof (hdr);

	(void) smbios_test_table_append(table, &hdr, sizeof (hdr));
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_bboard_mktable(smbios_test_table_t *table)
{
	smb_bboard_t bboard;

	bboard.smbbb_hdr.smbh_type = SMB_TYPE_BASEBOARD;
	bboard.smbbb_hdr.smbh_len = sizeof (bboard);

	bboard.smbbb_manufacturer = 1;
	bboard.smbbb_product = 2;
	bboard.smbbb_version = 3;
	bboard.smbbb_serial = 4;
	bboard.smbbb_asset = 5;
	bboard.smbbb_flags = bb_flags;
	bboard.smbbb_location = 6;
	bboard.smbbb_chassis = bb_chassis;
	bboard.smbbb_type = bb_type;
	bboard.smbbb_cn = 0;

	(void) smbios_test_table_append(table, &bboard, sizeof (bboard));
	smbios_test_table_append_string(table, bb_mfg);
	smbios_test_table_append_string(table, bb_prod);
	smbios_test_table_append_string(table, bb_version);
	smbios_test_table_append_string(table, bb_serial);
	smbios_test_table_append_string(table, bb_asset);
	smbios_test_table_append_string(table, bb_location);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_bboard_mktable_ents(smbios_test_table_t *table)
{
	smb_bboard_t bboard;

	bboard.smbbb_hdr.smbh_type = SMB_TYPE_BASEBOARD;
	bboard.smbbb_hdr.smbh_len = sizeof (bboard) + sizeof (bb_ents);

	bboard.smbbb_manufacturer = 1;
	bboard.smbbb_product = 2;
	bboard.smbbb_version = 3;
	bboard.smbbb_serial = 4;
	bboard.smbbb_asset = 5;
	bboard.smbbb_flags = bb_flags;
	bboard.smbbb_location = 6;
	bboard.smbbb_chassis = bb_chassis;
	bboard.smbbb_type = bb_type;
	bboard.smbbb_cn = ARRAY_SIZE(bb_ents);

	(void) smbios_test_table_append(table, &bboard, sizeof (bboard));
	(void) smbios_test_table_append_raw(table, bb_ents, sizeof (bb_ents));
	smbios_test_table_append_string(table, bb_mfg);
	smbios_test_table_append_string(table, bb_prod);
	smbios_test_table_append_string(table, bb_version);
	smbios_test_table_append_string(table, bb_serial);
	smbios_test_table_append_string(table, bb_asset);
	smbios_test_table_append_string(table, bb_location);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_bboard_mktable_short_ents(smbios_test_table_t *table)
{
	smb_bboard_t bboard;

	bboard.smbbb_hdr.smbh_type = SMB_TYPE_BASEBOARD;
	bboard.smbbb_hdr.smbh_len = sizeof (bboard) + sizeof (bb_ents) / 2;

	bboard.smbbb_manufacturer = 1;
	bboard.smbbb_product = 2;
	bboard.smbbb_version = 3;
	bboard.smbbb_serial = 4;
	bboard.smbbb_asset = 5;
	bboard.smbbb_flags = bb_flags;
	bboard.smbbb_location = 6;
	bboard.smbbb_chassis = bb_chassis;
	bboard.smbbb_type = bb_type;
	bboard.smbbb_cn = ARRAY_SIZE(bb_ents);

	(void) smbios_test_table_append(table, &bboard, sizeof (bboard));
	(void) smbios_test_table_append_raw(table, bb_ents, sizeof (bb_ents));
	smbios_test_table_append_string(table, bb_mfg);
	smbios_test_table_append_string(table, bb_prod);
	smbios_test_table_append_string(table, bb_version);
	smbios_test_table_append_string(table, bb_serial);
	smbios_test_table_append_string(table, bb_asset);
	smbios_test_table_append_string(table, bb_location);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

static boolean_t
smbios_test_bboard_verify_base(smbios_hdl_t *hdl, smbios_struct_t *sp,
    uint_t nents)
{
	boolean_t ret = B_TRUE;
	smbios_bboard_t bboard;

	if (smbios_info_bboard(hdl, sp->smbstr_id, &bboard) != 0) {
		warnx("failed to get baseboard information: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (bboard.smbb_chassis != bb_chassis) {
		warnx("found wrong chassis hdl 0x%" _PRIxID ", expected 0x%x",
		    bboard.smbb_chassis, bb_chassis);
		ret = B_FALSE;
	}

	if (bboard.smbb_flags != bb_flags) {
		warnx("found wrong flags value 0x%x, expected 0x%x",
		    bboard.smbb_flags, bb_flags);
		ret = B_FALSE;
	}

	if (bboard.smbb_type != bb_type) {
		warnx("found wrong type value 0x%x, expected 0x%x",
		    bboard.smbb_type, bb_type);
		ret = B_FALSE;
	}

	if (bboard.smbb_contn != nents) {
		warnx("found wrong object count 0x%x, expected 0x%x",
		    bboard.smbb_contn, nents);
		ret = B_FALSE;
	}

	return (ret);
}

static boolean_t
smbios_test_bboard_verify_common(smbios_hdl_t *hdl, smbios_struct_t *sp)
{
	boolean_t ret = B_TRUE;
	smbios_info_t info;

	if (smbios_info_common(hdl, sp->smbstr_id, &info) != 0) {
		warnx("failed to get baseboard common information: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (strcmp(info.smbi_manufacturer, bb_mfg) != 0) {
		warnx("found wrong manufacturer: expected %s, found %s",
		    bb_mfg, info.smbi_manufacturer);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_product, bb_prod) != 0) {
		warnx("found wrong product: expected %s, found %s",
		    bb_prod, info.smbi_product);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_version, bb_version) != 0) {
		warnx("found wrong version: expected %s, found %s",
		    bb_version, info.smbi_version);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_serial, bb_serial) != 0) {
		warnx("found wrong serial: expected %s, found %s",
		    bb_serial, info.smbi_serial);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_asset, bb_asset) != 0) {
		warnx("found wrong asset: expected %s, found %s",
		    bb_asset, info.smbi_asset);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_location, bb_location) != 0) {
		warnx("found wrong location: expected %s, found %s",
		    bb_location, info.smbi_location);
		ret = B_FALSE;
	}

	if (*info.smbi_part != '\0') {
		warnx("found unexpected part string: %s", info.smbi_part);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_bboard_verify_noents(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	boolean_t ret = B_TRUE;
	id_t ids[4];
	int cret;

	if (smbios_lookup_type(hdl, SMB_TYPE_BASEBOARD, &sp) == -1) {
		warnx("failed to lookup SMBIOS baseboard: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_bboard_verify_base(hdl, &sp, 0))
		ret = B_FALSE;

	if (!smbios_test_bboard_verify_common(hdl, &sp))
		ret = B_FALSE;

	cret = smbios_info_contains(hdl, sp.smbstr_id, 0, NULL);
	if (cret != 0) {
		warnx("got contains count of %d: expected 0 (no ids arg)",
		    cret);
		ret = B_FALSE;
	}

	cret = smbios_info_contains(hdl, sp.smbstr_id, ARRAY_SIZE(ids), ids);
	if (cret != 0) {
		warnx("returned count of %d: expected 0 (with ids arg)",
		    cret);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_bboard_verify_ents(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	boolean_t ret = B_TRUE;
	id_t ids[ARRAY_SIZE(bb_ents)], lids[ARRAY_SIZE(bb_ents) * 4];
	int cret;

	if (smbios_lookup_type(hdl, SMB_TYPE_BASEBOARD, &sp) == -1) {
		warnx("failed to lookup SMBIOS baseboard: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_bboard_verify_base(hdl, &sp, ARRAY_SIZE(bb_ents)))
		ret = B_FALSE;

	if (!smbios_test_bboard_verify_common(hdl, &sp))
		ret = B_FALSE;

	(void) memset(ids, 0x23, sizeof (ids));
	(void) memset(lids, 0x23, sizeof (lids));
	cret = smbios_info_contains(hdl, sp.smbstr_id, 0, NULL);
	if (cret != ARRAY_SIZE(bb_ents)) {
		warnx("got contains count of %d: expected %zu (no ids arg)",
		    cret, ARRAY_SIZE(bb_ents));
		ret = B_FALSE;
	}

	cret = smbios_info_contains(hdl, sp.smbstr_id, ARRAY_SIZE(ids), ids);
	if (cret != ARRAY_SIZE(bb_ents)) {
		warnx("returned count of %d: expected %zu (with ids arg)",
		    cret, ARRAY_SIZE(bb_ents));
		ret = B_FALSE;
	}

	cret = smbios_info_contains(hdl, sp.smbstr_id, ARRAY_SIZE(lids), lids);
	if (cret != ARRAY_SIZE(bb_ents)) {
		warnx("returned count of %d: expected %zu (with lids arg)",
		    cret, ARRAY_SIZE(bb_ents));
		ret = B_FALSE;
	}

	for (size_t i = 0; i < ARRAY_SIZE(bb_ents); i++) {
		if (ids[i] != bb_ents[i]) {
			warnx("ids[%zu] has wrong value 0x%" _PRIxID
			    ", expected 0x%x", i, ids[i], bb_ents[i]);
			ret = B_FALSE;
		}

		if (lids[i] != bb_ents[i]) {
			warnx("lids[%zu] has wrong value 0x%" _PRIxID
			    ", expected 0x%x", i, lids[i], bb_ents[i]);
			ret = B_FALSE;
		}
	}

	for (size_t i = ARRAY_SIZE(bb_ents); i < ARRAY_SIZE(lids); i++) {
		if (lids[i] != 0x23232323) {
			warnx("smbios_info_contains() clobbered entry %zu with "
			    "0x%" _PRIxID, i, lids[i]);
			ret = B_FALSE;
		}
	}

	return (ret);
}

boolean_t
smbios_test_bboard_verify_short(smbios_hdl_t *hdl)
{
	smbios_bboard_t bboard;
	smbios_struct_t sp;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_BASEBOARD, &sp) == -1) {
		warnx("failed to lookup SMBIOS baseboard: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_bboard(hdl, sp.smbstr_id, &bboard) != -1) {
		warnx("accidentally parsed invalid baseboard data as valid");
		ret = B_FALSE;
	} else if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for baseboard, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		ret = B_FALSE;
	}

	if (smbios_info_contains(hdl, sp.smbstr_id, 0, NULL) != -1) {
		warnx("smbios_info_contains() passed despite corrupt table");
		ret = B_FALSE;
	} else if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for short contains, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_bboard_verify_short_ents(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_BASEBOARD, &sp) == -1) {
		warnx("failed to lookup SMBIOS baseboard: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	/*
	 * We should be able to parse the base structure as we have enough data
	 * here. We skip trying to parse the common data as it technically fits
	 * in here, but the string pointers will be in the wrong spots; however,
	 * there's not a lot that we can do right now in the library about that.
	 */
	if (!smbios_test_bboard_verify_base(hdl, &sp, ARRAY_SIZE(bb_ents)))
		ret = B_FALSE;

	if (smbios_info_contains(hdl, sp.smbstr_id, 0, NULL) != -1) {
		warnx("smbios_info_contains() passed despite corrupt table");
		ret = B_FALSE;
	} else if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for short contains, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		ret = B_FALSE;
	}

	return (ret);
}
