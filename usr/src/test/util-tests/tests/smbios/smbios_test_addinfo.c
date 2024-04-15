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
 * Test SMBIOS Type 40 Additional Information. We try to cover a variety of
 * cases with and without entries, entries with and without additional data, and
 * several invalid length entries. Nothing currently checks that handles are
 * meaningful beyond that they are replicated.
 */

#include "smbios_test.h"

static const uint16_t smbios_addinfo_ent0_hdl = 0x7777;
static const uint8_t smbios_addinfo_ent0_off = 0x97;
static const char *smbios_addinfo_ent0_str = "Sephiroth";
static const uint32_t smbios_addinfo_ent0_data = 9999;
static const uint16_t smbios_addinfo_ent1_hdl = 0x1234;
static const uint8_t smbios_addinfo_ent1_off = 4;
static const char *smbios_addinfo_ent1_str = "Himmel";
static const uint16_t smbios_addinfo_ent2_hdl = 0x4321;
static const uint8_t smbios_addinfo_ent2_off = 0xfe;
static const char *smbios_addinfo_ent2_str = "Knights of the Round";
static const char *smbios_addinfo_ent2_data = "Galahad, Gawain, Lancelot";

static boolean_t
smbios_test_addinfo_verify_base(smbios_hdl_t *hdl, smbios_struct_t *sp,
    uint_t exp)
{
	uint_t nents;
	boolean_t ret = B_TRUE;
	smbios_addinfo_ent_t *ent;

	if (smbios_lookup_type(hdl, SMB_TYPE_ADDINFO, sp) == -1) {
		warnx("failed to lookup SMBIOS addinfo: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_addinfo_nents(hdl, sp->smbstr_id, &nents) != 0) {
		warnx("failed to get additional information entry count: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (nents != exp) {
		warnx("additional information entry mismatch: expected 0x%x, "
		    "found 0x%x", exp, nents);
		ret = B_FALSE;
	}

	if (smbios_info_addinfo_ent(hdl, sp->smbstr_id, exp, &ent) != -1) {
		warnx("incorrectly parsed non-existent entity");
		smbios_info_addinfo_ent_free(hdl, ent);
		ret = B_FALSE;
	} else if (smbios_errno(hdl) != ESMB_REQVAL) {
		warnx("encountered wrong error for addinfo ent, expected: "
		    "0x%x, found: 0x%x", ESMB_REQVAL, smbios_errno(hdl));
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * Basic entry without valid entries. Strictly speaking this may be illegal per
 * the spec.
 */
boolean_t
smbios_test_addinfo_mktable_noent(smbios_test_table_t *table)
{
	smb_addinfo_t add;

	add.smbai_hdr.smbh_type = SMB_TYPE_ADDINFO;
	add.smbai_hdr.smbh_len = sizeof (add);
	add.smbai_nents = 0;

	(void) smbios_test_table_append(table, &add, sizeof (add));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_addinfo_verify_noent(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;

	return (smbios_test_addinfo_verify_base(hdl, &sp, 0));
}

/*
 * Complex case with three entries, each with varying data and strings.
 */
boolean_t
smbios_test_addinfo_mktable_ents(smbios_test_table_t *table)
{
	smb_addinfo_t add;
	smb_addinfo_ent_t ent0, ent1, ent2;
	size_t slen;

	add.smbai_hdr.smbh_type = SMB_TYPE_ADDINFO;
	add.smbai_hdr.smbh_len = sizeof (add);
	add.smbai_nents = 3;

	ent0.smbaie_len = sizeof (smb_addinfo_ent_t) +
	    sizeof (smbios_addinfo_ent0_data);
	ent0.smbaie_rhdl = htole16(smbios_addinfo_ent0_hdl);
	ent0.smbaie_off = smbios_addinfo_ent0_off;
	ent0.smbaie_str = 1;
	add.smbai_hdr.smbh_len += ent0.smbaie_len;

	ent1.smbaie_len = sizeof (smb_addinfo_ent_t);
	ent1.smbaie_rhdl = htole16(smbios_addinfo_ent1_hdl);
	ent1.smbaie_off = smbios_addinfo_ent1_off;
	ent1.smbaie_str = 2;
	add.smbai_hdr.smbh_len += ent1.smbaie_len;

	slen = strlen(smbios_addinfo_ent2_data) + 1;
	ent2.smbaie_len = sizeof (smb_addinfo_ent_t) + slen;
	ent2.smbaie_rhdl = htole16(smbios_addinfo_ent2_hdl);
	ent2.smbaie_off = smbios_addinfo_ent2_off;
	ent2.smbaie_str = 3;
	add.smbai_hdr.smbh_len += ent2.smbaie_len;

	(void) smbios_test_table_append(table, &add, sizeof (add));
	(void) smbios_test_table_append_raw(table, &ent0, sizeof (ent0));
	(void) smbios_test_table_append_raw(table, &smbios_addinfo_ent0_data,
	    sizeof (smbios_addinfo_ent0_data));
	(void) smbios_test_table_append_raw(table, &ent1, sizeof (ent1));
	(void) smbios_test_table_append_raw(table, &ent2, sizeof (ent2));
	(void) smbios_test_table_append_raw(table, smbios_addinfo_ent2_data,
	    slen);
	smbios_test_table_append_string(table, smbios_addinfo_ent0_str);
	smbios_test_table_append_string(table, smbios_addinfo_ent1_str);
	smbios_test_table_append_string(table, smbios_addinfo_ent2_str);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_addinfo_verify_ents(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	boolean_t ret = B_TRUE;
	smbios_addinfo_ent_t *ent;

	if (!smbios_test_addinfo_verify_base(hdl, &sp, 3)) {
		return (B_FALSE);
	}

	if (smbios_info_addinfo_ent(hdl, sp.smbstr_id, 0, &ent) != 0) {
		warnx("failed to lookup additional entry 0: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (ent->smbai_ref != smbios_addinfo_ent0_hdl) {
		warnx("entry 0 mismatch, found unexpected reference handle: "
		    "0x%lx", ent->smbai_ref);
		ret = B_FALSE;
	}
	if (ent->smbai_ref_off != smbios_addinfo_ent0_off) {
		warnx("entry 0 mismatch, found unexpected reference offset: "
		    "0x%x", ent->smbai_ref_off);
		ret = B_FALSE;
	}
	if (ent->smbai_dlen != sizeof (smbios_addinfo_ent0_data)) {
		warnx("entry 0 mismatch, found unexpected data length: 0x%x",
		    ent->smbai_dlen);
		ret = B_FALSE;
	}
	if (memcmp(ent->smbai_data, &smbios_addinfo_ent0_data,
	    ent->smbai_dlen) != 0) {
		warnx("entry 0 mismatch, additional data mismatched");
		ret = B_FALSE;
	}
	smbios_info_addinfo_ent_free(hdl, ent);

	if (smbios_info_addinfo_ent(hdl, sp.smbstr_id, 1, &ent) != 0) {
		warnx("failed to lookup additional entry 1: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (ent->smbai_ref != smbios_addinfo_ent1_hdl) {
		warnx("entry 1 mismatch, found unexpected reference handle: "
		    "0x%lx", ent->smbai_ref);
		ret = B_FALSE;
	}
	if (ent->smbai_ref_off != smbios_addinfo_ent1_off) {
		warnx("entry 1 mismatch, found unexpected reference offset: "
		    "0x%x", ent->smbai_ref_off);
		ret = B_FALSE;
	}
	if (ent->smbai_dlen != 0) {
		warnx("entry 1 mismatch, found unexpected data length: 0x%x",
		    ent->smbai_dlen);
		ret = B_FALSE;
	}
	if (ent->smbai_data != NULL) {
		warnx("entry 1 mismatch, found unexpected data pointer");
		ret = B_FALSE;
	}
	smbios_info_addinfo_ent_free(hdl, ent);

	if (smbios_info_addinfo_ent(hdl, sp.smbstr_id, 2, &ent) != 0) {
		warnx("failed to lookup additional entry 2: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (ent->smbai_ref != smbios_addinfo_ent2_hdl) {
		warnx("entry 2 mismatch, found unexpected reference handle: "
		    "0x%lx", ent->smbai_ref);
		ret = B_FALSE;
	}
	if (ent->smbai_ref_off != smbios_addinfo_ent2_off) {
		warnx("entry 2 mismatch, found unexpected reference offset: "
		    "0x%x", ent->smbai_ref_off);
		ret = B_FALSE;
	}
	if (ent->smbai_dlen != strlen(smbios_addinfo_ent2_data) + 1) {
		warnx("entry 2 mismatch, found unexpected data length: 0x%x",
		    ent->smbai_dlen);
		ret = B_FALSE;
	}
	if (memcmp(ent->smbai_data, smbios_addinfo_ent2_data,
	    ent->smbai_dlen) != 0) {
		warnx("entry 2 mismatch, additional data mismatched");
		ret = B_FALSE;
	}
	smbios_info_addinfo_ent_free(hdl, ent);

	return (ret);
}

/*
 * Generate a table that's too short to get basic info.
 */
boolean_t
smbios_test_addinfo_mktable_invlen_base(smbios_test_table_t *table)
{
	smb_header_t hdr;

	hdr.smbh_type = SMB_TYPE_ADDINFO;
	hdr.smbh_len = sizeof (hdr);

	(void) smbios_test_table_append(table, &hdr, sizeof (hdr));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_addinfo_verify_invlen_base(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	uint_t nents;

	if (smbios_lookup_type(hdl, SMB_TYPE_ADDINFO, &sp) == -1) {
		warnx("failed to lookup SMBIOS addinfo: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_addinfo_nents(hdl, sp.smbstr_id, &nents) != -1) {
		warnx("accidentally parsed invalid addinfo information as "
		    "valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for addinfo, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * A table that's long enough to have valid entries, but too short for the first
 * entry.
 */
boolean_t
smbios_test_addinfo_mktable_invlen_ent(smbios_test_table_t *table)
{
	smb_addinfo_t add;
	smb_addinfo_ent_t ent = { 0 };
	size_t entoff = offsetof(smb_addinfo_ent_t, smbaie_rhdl);

	add.smbai_hdr.smbh_type = SMB_TYPE_ADDINFO;
	add.smbai_hdr.smbh_len = sizeof (add) + entoff;
	add.smbai_nents = 1;

	(void) smbios_test_table_append(table, &add, sizeof (add));
	(void) smbios_test_table_append_raw(table, &ent, entoff);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_addinfo_verify_invlen_ent(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_addinfo_ent_t *ent;
	boolean_t ret = B_TRUE;

	if (!smbios_test_addinfo_verify_base(hdl, &sp, 1)) {
		return (B_FALSE);
	}

	if (smbios_info_addinfo_ent(hdl, sp.smbstr_id, 0, &ent) != -1) {
		warnx("incorrectly parsed additional information entry 0: "
		    "expected bad length");
		ret = B_FALSE;
	} else if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for addinfo ent, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * Make sure even if we parse the first entity correctly, we fail on the second
 * one being too short.
 */
boolean_t
smbios_test_addinfo_mktable_invlen_multient(smbios_test_table_t *table)
{
	smb_addinfo_t add;
	smb_addinfo_ent_t ent0, ent1 = { 0 };
	size_t entoff = offsetof(smb_addinfo_ent_t, smbaie_rhdl);

	add.smbai_hdr.smbh_type = SMB_TYPE_ADDINFO;
	add.smbai_hdr.smbh_len = sizeof (add);
	add.smbai_nents = 2;

	ent0.smbaie_len = sizeof (smb_addinfo_ent_t) +
	    sizeof (smbios_addinfo_ent0_data);
	ent0.smbaie_rhdl = htole16(smbios_addinfo_ent0_hdl);
	ent0.smbaie_off = smbios_addinfo_ent0_off;
	ent0.smbaie_str = 1;
	add.smbai_hdr.smbh_len += ent0.smbaie_len;

	ent1.smbaie_len = sizeof (smb_addinfo_ent_t);
	add.smbai_hdr.smbh_len += entoff;

	(void) smbios_test_table_append(table, &add, sizeof (add));
	(void) smbios_test_table_append_raw(table, &ent0, sizeof (ent0));
	(void) smbios_test_table_append_raw(table, &smbios_addinfo_ent0_data,
	    sizeof (smbios_addinfo_ent0_data));
	(void) smbios_test_table_append_raw(table, &ent1, entoff);

	smbios_test_table_append_string(table, smbios_addinfo_ent0_str);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);


	(void) smbios_test_table_append(table, &add, sizeof (add));
	(void) smbios_test_table_append_raw(table, &ent1, entoff);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_addinfo_verify_invlen_multient(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_addinfo_ent_t *ent;
	boolean_t ret = B_TRUE;

	if (!smbios_test_addinfo_verify_base(hdl, &sp, 2)) {
		return (B_FALSE);
	}

	if (smbios_info_addinfo_ent(hdl, sp.smbstr_id, 1, &ent) != -1) {
		warnx("incorrectly parsed additional information entry 1: "
		    "expected bad length");
		ret = B_FALSE;
	} else if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for addinfo ent, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		ret = B_FALSE;
	}

	if (smbios_info_addinfo_ent(hdl, sp.smbstr_id, 0, &ent) != 0) {
		warnx("failed to lookup additional entry 0: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (ent->smbai_ref != smbios_addinfo_ent0_hdl) {
		warnx("entry 0 mismatch, found unexpected reference handle: "
		    "0x%lx", ent->smbai_ref);
		ret = B_FALSE;
	}
	if (ent->smbai_ref_off != smbios_addinfo_ent0_off) {
		warnx("entry 0 mismatch, found unexpected reference offset: "
		    "0x%x", ent->smbai_ref_off);
		ret = B_FALSE;
	}
	if (ent->smbai_dlen != sizeof (smbios_addinfo_ent0_data)) {
		warnx("entry 0 mismatch, found unexpected data length: 0x%x",
		    ent->smbai_dlen);
		ret = B_FALSE;
	}
	if (memcmp(ent->smbai_data, &smbios_addinfo_ent0_data,
	    ent->smbai_dlen) != 0) {
		warnx("entry 0 mismatch, additional data mismatched");
		ret = B_FALSE;
	}
	smbios_info_addinfo_ent_free(hdl, ent);

	return (ret);
}

/*
 * Make sure we get the case where the length of the entity is longer than the
 * table.
 */
boolean_t
smbios_test_addinfo_mktable_invlen_entdata(smbios_test_table_t *table)
{
	smb_addinfo_t add;
	smb_addinfo_ent_t ent;

	add.smbai_hdr.smbh_type = SMB_TYPE_ADDINFO;
	add.smbai_hdr.smbh_len = sizeof (add) + sizeof (ent);
	add.smbai_nents = 1;

	(void) memset(&ent, 0, sizeof (ent));
	ent.smbaie_len = sizeof (ent) + 3;

	(void) smbios_test_table_append(table, &add, sizeof (add));
	(void) smbios_test_table_append_raw(table, &ent, sizeof (ent));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_addinfo_verify_invlen_entdata(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_addinfo_ent_t *ent;
	boolean_t ret = B_TRUE;

	if (!smbios_test_addinfo_verify_base(hdl, &sp, 1)) {
		return (B_FALSE);
	}

	if (smbios_info_addinfo_ent(hdl, sp.smbstr_id, 0, &ent) != -1) {
		warnx("incorrectly parsed additional information entry 0: "
		    "expected bad length");
		ret = B_FALSE;
	} else if (smbios_errno(hdl) != ESMB_CORRUPT) {
		warnx("encountered wrong error for addinfo ent, expected: "
		    "0x%x, found: 0x%x", ESMB_CORRUPT, smbios_errno(hdl));
		ret = B_FALSE;
	}

	return (ret);
}
