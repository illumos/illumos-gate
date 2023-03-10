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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Tests for the old Sun OEM SMBIOS Type 145, memory device extended
 * information.
 */

#include "smbios_test.h"

/*
 * Please keep the ncs value the same as the mktable_cs() array size.
 */
static const uint8_t smbios_extmemdevice_ncs = 23;
static const uint16_t smbios_extmemdevice_mdev = 6;
static const uint8_t smbios_extmemdevice_dchan = 7;

static void
smbios_test_extmem_mktable_common(smb_memdevice_ext_t *ext)
{
	ext->smbmdeve_hdr.smbh_type = SUN_OEM_EXT_MEMDEVICE;
	ext->smbmdeve_hdr.smbh_len = sizeof (*ext);
	ext->smbmdeve_mdev = htole16(smbios_extmemdevice_mdev);
	ext->smbmdeve_dchan = smbios_extmemdevice_dchan;
	ext->smbmdeve_ncs = 0;
}

boolean_t
smbios_test_extmem_mktable_invlen_cs(smbios_test_table_t *table)
{
	smb_memdevice_ext_t ext;

	smbios_test_extmem_mktable_common(&ext);
	ext.smbmdeve_ncs = smbios_extmemdevice_ncs;
	(void) smbios_test_table_append(table, &ext, sizeof (ext));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_extmem_mktable_nocs(smbios_test_table_t *table)
{
	smb_memdevice_ext_t ext;

	smbios_test_extmem_mktable_common(&ext);
	(void) smbios_test_table_append(table, &ext, sizeof (ext));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_extmem_mktable_cs(smbios_test_table_t *table)
{
	smb_memdevice_ext_t ext;
	uint8_t cs[23];

	for (uint8_t i = 0; i < ARRAY_SIZE(cs); i++) {
		cs[i] = i;
	}

	smbios_test_extmem_mktable_common(&ext);
	ext.smbmdeve_ncs = smbios_extmemdevice_ncs;
	ext.smbmdeve_hdr.smbh_len += sizeof (cs);
	(void) smbios_test_table_append(table, &ext, sizeof (ext));
	smbios_test_table_append_raw(table, &cs, sizeof (cs));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

static boolean_t
smbios_test_extmem_verify_common(const smbios_memdevice_ext_t *ext, uint_t ncs)
{
	boolean_t ret = B_TRUE;

	if (ext->smbmdeve_md != smbios_extmemdevice_mdev) {
		warnx("memory device mismatch, found 0x%x, expected 0x%x",
		    ext->smbmdeve_md, smbios_extmemdevice_mdev);
		ret = B_FALSE;

	}

	if (ext->smbmdeve_drch != smbios_extmemdevice_dchan) {
		warnx("dram channel mismatch, found 0x%x, expected 0x%x",
		    ext->smbmdeve_drch, smbios_extmemdevice_dchan);
		ret = B_FALSE;

	}

	if (ext->smbmdeve_ncs != ncs) {
		warnx("cs count mismatch, found 0x%x, expected 0x%x",
		    ext->smbmdeve_ncs, ncs);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_extmem_verify_invlen_cs(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_memdevice_ext_t ext;
	boolean_t ret = B_TRUE;
	uint_t ncs;
	uint8_t *cs;

	if (smbios_lookup_type(hdl, SUN_OEM_EXT_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS extended memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
	}

	if (smbios_info_extmemdevice(hdl, sp.smbstr_id, &ext) == -1) {
		warnx("failed to get extended memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_extmem_verify_common(&ext, smbios_extmemdevice_ncs)) {
		ret = B_FALSE;
	}

	if (smbios_info_extmemdevice_cs(hdl, sp.smbstr_id, &ncs, &cs) == 0) {
		warnx("getting cs succeeded when it should have failed");
		smbios_info_extmemdevice_cs_free(hdl, ncs, cs);
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for cs info, expected: 0x%x, "
		    "found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_extmem_verify_nocs(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_memdevice_ext_t ext;
	boolean_t ret = B_TRUE;
	uint_t ncs;
	uint8_t *cs;

	if (smbios_lookup_type(hdl, SUN_OEM_EXT_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS extended memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
	}

	if (smbios_info_extmemdevice(hdl, sp.smbstr_id, &ext) == -1) {
		warnx("failed to get extended memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_extmem_verify_common(&ext, 0)) {
		ret = B_FALSE;
	}

	if (smbios_info_extmemdevice_cs(hdl, sp.smbstr_id, &ncs, &cs) == -1) {
		warnx("failed to get extended memory device cs: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (ncs != 0 || cs != NULL) {
		warnx("non-cs case turned up 0x%x cs entries with address %p",
		    ncs, cs);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_extmem_verify_cs(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_memdevice_ext_t ext;
	boolean_t ret = B_TRUE;
	uint_t ncs;
	uint8_t *cs;

	if (smbios_lookup_type(hdl, SUN_OEM_EXT_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS extended memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
	}

	if (smbios_info_extmemdevice(hdl, sp.smbstr_id, &ext) == -1) {
		warnx("failed to get extended memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_extmem_verify_common(&ext, smbios_extmemdevice_ncs)) {
		ret = B_FALSE;
	}

	if (smbios_info_extmemdevice_cs(hdl, sp.smbstr_id, &ncs, &cs) == -1) {
		warnx("failed to get extended memory device cs: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (ncs != smbios_extmemdevice_ncs) {
		warnx("smbios_info_extmemdevice_cs returned wrong number of "
		    "cs, expected 0x%x, found 0x%x", smbios_extmemdevice_ncs,
		    ncs);
		ret = B_FALSE;
	}

	if (cs == NULL) {
		warnx("somehow got NULL pointer for valid cs case");
		ret = B_FALSE;
	}

	for (uint_t i = 0; i < ncs; i++) {
		if (cs[i] != i) {
			warnx("cs %u has wrong value 0x%x, expected 0x%x", i,
			    cs[i], i);
			ret = B_FALSE;
		}
	}

	smbios_info_extmemdevice_cs_free(hdl, ncs, cs);
	return (ret);
}
