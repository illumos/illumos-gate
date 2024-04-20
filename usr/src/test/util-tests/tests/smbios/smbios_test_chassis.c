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
 * Tests for SMBIOS Type 3 - SMB_TYPE_CHASSIS.
 */

#include "smbios_test.h"

static const char *smbios_chassis_mfg = "Shrina";
static const char *smbios_chassis_vers = "7R";
static const char *smbios_chassis_serial = "What's my number?";
static const char *smbios_chassis_asset = "lost";
static const char *smbios_chassis_sku = "Proud";
static const uint32_t smbios_chassis_oem = 0x36105997;
static const uint8_t smbios_chassis_uheight = 7;

boolean_t
smbios_test_chassis_mktable_invlen_base(smbios_test_table_t *table)
{
	smb_header_t hdr;

	hdr.smbh_type = SMB_TYPE_CHASSIS;
	hdr.smbh_len = sizeof (hdr);

	(void) smbios_test_table_append(table, &hdr, sizeof (hdr));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

static void
smbios_test_chassis_mktable_fill_chassis(smb_chassis_t *ch)
{
	ch->smbch_hdr.smbh_type = SMB_TYPE_CHASSIS;
	ch->smbch_hdr.smbh_len = sizeof (*ch);
	ch->smbch_manufacturer = 1;
	ch->smbch_type = SMB_CHT_LUNCHBOX;
	ch->smbch_version = 2;
	ch->smbch_serial = 3;
	ch->smbch_asset = 4;
	ch->smbch_bustate = SMB_CHST_SAFE;
	ch->smbch_psstate = SMB_CHST_NONREC;
	ch->smbch_thstate = SMB_CHST_WARNING;
	ch->smbch_security = SMB_CHSC_NONE;
	ch->smbch_oemdata = htole32(smbios_chassis_oem);
	ch->smbch_uheight = smbios_chassis_uheight;
	ch->smbch_cords = smbios_chassis_uheight - 1;
	ch->smbch_cn = 0;
	ch->smbch_cm = sizeof (smb_chassis_entry_t);
}

static void
smbios_test_chassis_mktable_fill_entries(smb_chassis_entry_t *ents)
{
	ents[0].smbce_type = SMB_TYPE_COOLDEV | (1 << 7);
	ents[0].smbce_min = 1;
	ents[0].smbce_max = 42;
	ents[1].smbce_type = SMB_BBT_IO;
	ents[1].smbce_min = 5;
	ents[1].smbce_max = 123;
}

static void
smbios_test_chassis_mktable_append_strings(smbios_test_table_t *table)
{
	smbios_test_table_append_string(table, smbios_chassis_mfg);
	smbios_test_table_append_string(table, smbios_chassis_vers);
	smbios_test_table_append_string(table, smbios_chassis_serial);
	smbios_test_table_append_string(table, smbios_chassis_asset);
}

/*
 * This is an SMBIOS 2.4-esque table.
 */
boolean_t
smbios_test_chassis_mktable_base(smbios_test_table_t *table)
{
	smb_chassis_t ch;

	smbios_test_chassis_mktable_fill_chassis(&ch);
	(void) smbios_test_table_append(table, &ch, sizeof (ch));
	smbios_test_chassis_mktable_append_strings(table);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

/*
 * A variant of the base that doesn't include the element length becaue there
 * are no elements.
 */
boolean_t
smbios_test_chassis_mktable_part(smbios_test_table_t *table)
{
	smb_chassis_t ch;
	size_t len = offsetof(smb_chassis_t, smbch_cn);

	smbios_test_chassis_mktable_fill_chassis(&ch);
	ch.smbch_hdr.smbh_len = len;
	(void) smbios_test_table_append(table, &ch, len);
	smbios_test_chassis_mktable_append_strings(table);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_chassis_mktable_comps(smbios_test_table_t *table)
{
	smb_chassis_t ch;
	smb_chassis_entry_t ents[2];

	smbios_test_chassis_mktable_fill_chassis(&ch);
	smbios_test_chassis_mktable_fill_entries(ents);
	ch.smbch_hdr.smbh_len += sizeof (ents);
	ch.smbch_cn = 2;
	(void) smbios_test_table_append(table, &ch, sizeof (ch));
	smbios_test_table_append_raw(table, ents, sizeof (ents));
	smbios_test_chassis_mktable_append_strings(table);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_chassis_mktable_sku_nocomps(smbios_test_table_t *table)
{
	smb_chassis_t ch;
	const uint8_t sku_str = 5;

	smbios_test_chassis_mktable_fill_chassis(&ch);
	ch.smbch_hdr.smbh_len++;
	(void) smbios_test_table_append(table, &ch, sizeof (ch));
	smbios_test_table_append_raw(table, &sku_str, sizeof (sku_str));
	smbios_test_chassis_mktable_append_strings(table);
	smbios_test_table_append_string(table, smbios_chassis_sku);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_chassis_mktable_sku(smbios_test_table_t *table)
{
	smb_chassis_t ch;
	const uint8_t sku_str = 5;
	smb_chassis_entry_t ents[2];

	ch.smbch_cn = 2;

	smbios_test_chassis_mktable_fill_chassis(&ch);
	smbios_test_chassis_mktable_fill_entries(ents);
	ch.smbch_hdr.smbh_len += sizeof (ents) + 1;
	(void) smbios_test_table_append(table, &ch, sizeof (ch));
	smbios_test_table_append_raw(table, &sku_str, sizeof (sku_str));
	smbios_test_chassis_mktable_append_strings(table);
	smbios_test_table_append_string(table, smbios_chassis_sku);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_chassis_verify_invlen(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_chassis_t ch;

	if (smbios_lookup_type(hdl, SMB_TYPE_CHASSIS, &sp) == -1) {
		warnx("failed to lookup SMBIOS chassis: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_chassis(hdl, sp.smbstr_id, &ch) != -1) {
		warnx("accidentally parsed invalid chassis as valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for chassis, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
smbios_test_chassis_verify_common(smbios_hdl_t *hdl, smbios_struct_t *sp,
    smbios_chassis_t *ch)
{
	boolean_t ret = B_TRUE;
	smbios_info_t info;

	if (ch->smbc_oemdata != smbios_chassis_oem) {
		warnx("chassis state mismatch, found unexpected oem data: 0x%x",
		    ch->smbc_oemdata);
		ret = B_FALSE;
	}

	if (ch->smbc_lock != 0) {
		warnx("chassis state mismatch, found unexpected lock: 0x%x",
		    ch->smbc_lock);
		ret = B_FALSE;
	}

	if (ch->smbc_type != SMB_CHT_LUNCHBOX) {
		warnx("chassis state mismatch, found unexpected type: 0x%x",
		    ch->smbc_type);
		ret = B_FALSE;
	}

	if (ch->smbc_bustate != SMB_CHST_SAFE) {
		warnx("chassis state mismatch, found unexpected boot state: "
		    "0x%x", ch->smbc_bustate);
		ret = B_FALSE;
	}

	if (ch->smbc_psstate != SMB_CHST_NONREC) {
		warnx("chassis state mismatch, found unexpected power state: "
		    "0x%x", ch->smbc_psstate);
		ret = B_FALSE;
	}

	if (ch->smbc_thstate != SMB_CHST_WARNING) {
		warnx("chassis state mismatch, found unexpected thermal state: "
		    "0x%x", ch->smbc_thstate);
		ret = B_FALSE;
	}

	if (ch->smbc_security != SMB_CHSC_NONE) {
		warnx("chassis state mismatch, found unexpected security "
		    "value: 0x%x", ch->smbc_security);
		ret = B_FALSE;
	}

	if (ch->smbc_uheight != smbios_chassis_uheight) {
		warnx("chassis state mismatch, found unexpected uheight value: "
		    "0x%x", ch->smbc_uheight);
		ret = B_FALSE;
	}

	if (ch->smbc_cords != smbios_chassis_uheight - 1) {
		warnx("chassis state mismatch, found unexpected cords value: "
		    "0x%x", ch->smbc_cords);
		ret = B_FALSE;
	}

	if (smbios_info_common(hdl, sp->smbstr_id, &info) != 0) {
		warnx("failed to get common chassis info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (strcmp(info.smbi_manufacturer, smbios_chassis_mfg) != 0) {
		warnx("chassis state mismatch, found unexpected mfg: "
		    "%s", info.smbi_manufacturer);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_version, smbios_chassis_vers) != 0) {
		warnx("chassis state mismatch, found unexpected version: %s",
		    info.smbi_version);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_serial, smbios_chassis_serial) != 0) {
		warnx("chassis state mismatch, found unexpected serial: %s",
		    info.smbi_serial);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_asset, smbios_chassis_asset) != 0) {
		warnx("chassis state mismatch, found unexpected asset: %s",
		    info.smbi_asset);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_chassis_verify_base(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;
	smbios_struct_t sp;
	smbios_chassis_t ch;
	smbios_chassis_entry_t *elts;
	uint_t nelts;

	if (smbios_lookup_type(hdl, SMB_TYPE_CHASSIS, &sp) == -1) {
		warnx("failed to lookup SMBIOS chassis: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_chassis(hdl, sp.smbstr_id, &ch) == -1) {
		warnx("failed to get chassis: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_chassis_verify_common(hdl, &sp, &ch)) {
		ret = B_FALSE;
	}

	if (ch.smbc_elems != 0) {
		warnx("chassis state mismatch, found unexpected number of "
		    "elements: 0x%x", ch.smbc_elems);
		ret = B_FALSE;
	}

	if (strcmp(ch.smbc_sku, "") != 0) {
		warnx("chassis state mismatch, found unexpected sku: %s",
		    ch.smbc_sku);
		ret = B_FALSE;
	}

	if (smbios_info_chassis_elts(hdl, sp.smbstr_id, &nelts, &elts) != 0) {
		warnx("failed to get chassis elements: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (nelts != 0) {
		warnx("chassis state mismatch, smbios_info_chassis_elts() "
		    "returned a non-zero number of entries: %u", nelts);
		ret = B_FALSE;
	}

	if (elts != NULL) {
		warnx("chassis state mismatch, smbios_info_chassis_elts() "
		    "returned a non-NULL pointer: %p", elts);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_chassis_verify_sku_nocomps(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;
	smbios_struct_t sp;
	smbios_chassis_t ch;
	smbios_chassis_entry_t *elts;
	uint_t nelts;

	if (smbios_lookup_type(hdl, SMB_TYPE_CHASSIS, &sp) == -1) {
		warnx("failed to lookup SMBIOS chassis: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_chassis(hdl, sp.smbstr_id, &ch) == -1) {
		warnx("failed to get chassis: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_chassis_verify_common(hdl, &sp, &ch)) {
		ret = B_FALSE;
	}

	if (ch.smbc_elems != 0) {
		warnx("chassis state mismatch, found unexpected number of "
		    "elements: 0x%x", ch.smbc_elems);
		ret = B_FALSE;
	}

	if (ch.smbc_elemlen != sizeof (smb_chassis_entry_t)) {
		warnx("chassis state mismatch, found unexpected elemlen value: "
		    "0x%x", ch.smbc_elemlen);
		ret = B_FALSE;
	}

	if (strcmp(ch.smbc_sku, smbios_chassis_sku) != 0) {
		warnx("chassis state mismatch, found unexpected sku: %s",
		    ch.smbc_sku);
		ret = B_FALSE;
	}

	if (smbios_info_chassis_elts(hdl, sp.smbstr_id, &nelts, &elts) != 0) {
		warnx("failed to get chassis elements: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (nelts != 0) {
		warnx("chassis state mismatch, smbios_info_chassis_elts() "
		    "returned a non-zero number of entries: %u", nelts);
		ret = B_FALSE;
	}

	if (elts != NULL) {
		warnx("chassis state mismatch, smbios_info_chassis_elts() "
		    "returned a non-NULL pointer: %p", elts);
		ret = B_FALSE;
	}


	return (ret);
}

static boolean_t
smbios_test_chassis_verify_common_comps(smbios_hdl_t *hdl, smbios_struct_t *sp)
{
	boolean_t ret = B_TRUE;
	smbios_chassis_entry_t *elts;
	uint_t nelts;

	if (smbios_info_chassis_elts(hdl, sp->smbstr_id, &nelts, &elts) != 0) {
		warnx("failed to get chassis elements: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (nelts != 2) {
		warnx("chassis state mismatch, smbios_info_chassis_elts() "
		    "returned the wrong number of entries: %u", nelts);
		return (B_FALSE);
	}

	if (elts[0].smbce_type != SMB_CELT_SMBIOS) {
		warnx("chassis elts[0] type mismatch, found: %u",
		    elts[0].smbce_type);
		ret = B_FALSE;
	}

	if (elts[0].smbce_elt != SMB_TYPE_COOLDEV) {
		warnx("chassis elts[0] elt type mismatch, found: %u",
		    elts[0].smbce_elt);
		ret = B_FALSE;
	}

	if (elts[0].smbce_min != 1) {
		warnx("chassis elts[0] minimum number mismatch, found: %u",
		    elts[0].smbce_min);
		ret = B_FALSE;
	}

	if (elts[0].smbce_max != 42) {
		warnx("chassis elts[0] maximum number mismatch, found: %u",
		    elts[0].smbce_max);
		ret = B_FALSE;
	}

	if (elts[1].smbce_type != SMB_CELT_BBOARD) {
		warnx("chassis elts[1] type mismatch, found: %u",
		    elts[1].smbce_type);
		ret = B_FALSE;
	}

	if (elts[1].smbce_elt != SMB_BBT_IO) {
		warnx("chassis elts[1] elt type mismatch, found: %u",
		    elts[1].smbce_elt);
		ret = B_FALSE;
	}

	if (elts[1].smbce_min != 5) {
		warnx("chassis elts[1] minimum number mismatch, found: %u",
		    elts[1].smbce_min);
		ret = B_FALSE;
	}

	if (elts[1].smbce_max != 123) {
		warnx("chassis elts[1] maximum number mismatch, found: %u",
		    elts[1].smbce_max);
		ret = B_FALSE;
	}
	return (ret);
}

boolean_t
smbios_test_chassis_verify_comps(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;
	smbios_struct_t sp;
	smbios_chassis_t ch;

	if (smbios_lookup_type(hdl, SMB_TYPE_CHASSIS, &sp) == -1) {
		warnx("failed to lookup SMBIOS chassis: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_chassis(hdl, sp.smbstr_id, &ch) == -1) {
		warnx("failed to get chassis: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_chassis_verify_common(hdl, &sp, &ch)) {
		ret = B_FALSE;
	}

	if (ch.smbc_elems != 2) {
		warnx("chassis state mismatch, found unexpected number of "
		    "elements: 0x%x", ch.smbc_elems);
		ret = B_FALSE;
	}

	if (ch.smbc_elemlen != sizeof (smb_chassis_entry_t)) {
		warnx("chassis state mismatch, found unexpected elemlen value: "
		    "0x%x", ch.smbc_elemlen);
		ret = B_FALSE;
	}

	if (strcmp(ch.smbc_sku, "") != 0) {
		warnx("chassis state mismatch, found unexpected sku: %s",
		    ch.smbc_sku);
		ret = B_FALSE;
	}

	if (!smbios_test_chassis_verify_common_comps(hdl, &sp)) {
		ret = B_FALSE;
	}

	return (ret);
}


boolean_t
smbios_test_chassis_verify_sku(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;
	smbios_struct_t sp;
	smbios_chassis_t ch;

	if (smbios_lookup_type(hdl, SMB_TYPE_CHASSIS, &sp) == -1) {
		warnx("failed to lookup SMBIOS chassis: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_chassis(hdl, sp.smbstr_id, &ch) == -1) {
		warnx("failed to get chassis: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_chassis_verify_common(hdl, &sp, &ch)) {
		ret = B_FALSE;
	}

	if (ch.smbc_elems != 2) {
		warnx("chassis state mismatch, found unexpected number of "
		    "elements: 0x%x", ch.smbc_elems);
		ret = B_FALSE;
	}

	if (ch.smbc_elemlen != sizeof (smb_chassis_entry_t)) {
		warnx("chassis state mismatch, found unexpected elemlen value: "
		    "0x%x", ch.smbc_elemlen);
		ret = B_FALSE;
	}

	if (strcmp(ch.smbc_sku, smbios_chassis_sku) != 0) {
		warnx("chassis state mismatch, found unexpected sku: %s",
		    ch.smbc_sku);
		ret = B_FALSE;
	}

	if (!smbios_test_chassis_verify_common_comps(hdl, &sp)) {
		ret = B_FALSE;
	}

	return (ret);
}
