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
 * Basic tests for the SMBIOS Type 43 TPM
 */

#include "smbios_test.h"

static const uint8_t smbios_tpm_vid[4] = { 't', 'r', 'a', 'p' };
static const char *smbios_tpm_desc = "Very Secure";
static const uint8_t smbios_tpm_major = 0x23;
static const uint8_t smbios_tpm_minor = 0x42;
static const uint32_t smbios_tpm_fwv1 = 0xff7777;
static const uint32_t smbios_tpm_fwv2 = 0x1234567;
static const uint64_t smbios_tpm_chars = 0xf0e1d2c3b4a59687;
static const uint32_t smbios_tpm_oem = 0xdeadbeef;

boolean_t
smbios_test_tpm_mktable_short(smbios_test_table_t *table)
{
	smb_tpm_t tpm;

	arc4random_buf(&tpm, sizeof (tpm));
	tpm.smbtpm_hdr.smbh_type = SMB_TYPE_TPM;
	tpm.smbtpm_hdr.smbh_len = sizeof (tpm) / 2;
	(void) smbios_test_table_append(table, &tpm, sizeof (tpm) / 2);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_tpm_mktable(smbios_test_table_t *table)
{
	smb_tpm_t tpm;

	bzero(&tpm, sizeof (tpm));
	tpm.smbtpm_hdr.smbh_type = SMB_TYPE_TPM;
	tpm.smbtpm_hdr.smbh_len = sizeof (tpm);
	bcopy(smbios_tpm_vid, tpm.smbtpm_vid, sizeof (smbios_tpm_vid));
	tpm.smbtpm_major = smbios_tpm_major;
	tpm.smbtpm_minor = smbios_tpm_minor;
	tpm.smbtpm_fwv1 = smbios_tpm_fwv1;
	tpm.smbtpm_fwv2 = smbios_tpm_fwv2;
	tpm.smbtpm_desc = 1;
	tpm.smbtpm_chars = smbios_tpm_chars;
	tpm.smbtpm_oem = smbios_tpm_oem;

	(void) smbios_test_table_append(table, &tpm, sizeof (tpm));
	smbios_test_table_append_string(table, smbios_tpm_desc);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_tpm_verify_short(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_tpm_t tpm;

	if (smbios_lookup_type(hdl, SMB_TYPE_TPM, &sp) == -1) {
		warnx("failed to lookup SMBIOS tpm: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_tpm(hdl, sp.smbstr_id, &tpm) != -1) {
		warnx("accidentally parsed invalid tpm as valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for chassis, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
smbios_test_tpm_verify_badtype(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_tpm_t tpm;

	if (smbios_lookup_type(hdl, SMB_TYPE_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_tpm(hdl, sp.smbstr_id, &tpm) != -1) {
		warnx("accidentally parsed invalid tpm information as "
		    "valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_TYPE) {
		warnx("encountered wrong error for tpm, expected: "
		    "0x%x, found: 0x%x", ESMB_TYPE, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
smbios_test_tpm_verify(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_tpm_t tpm;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_TPM, &sp) == -1) {
		warnx("failed to lookup SMBIOS tpm: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_tpm(hdl, sp.smbstr_id, &tpm) == -1) {
		warnx("failed to get tpm: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (strcmp(tpm.smbtpm_desc, smbios_tpm_desc) != 0) {
		warnx("tpm description mismatch: found %s, expected %s",
		    tpm.smbtpm_desc, smbios_tpm_desc);
		ret = B_FALSE;
	}

	if (bcmp(tpm.smbtpm_vid, smbios_tpm_vid, sizeof (smbios_tpm_vid)) !=
	    0) {
		warnx("tpm vendor mismatch: found \\x%2x \\x%2x \\x%2x \\x%2x",
		    tpm.smbtpm_vid[0], tpm.smbtpm_vid[1],
		    tpm.smbtpm_vid[2], tpm.smbtpm_vid[3]);
		ret = B_FALSE;
	}

	if (tpm.smbtpm_major != smbios_tpm_major) {
		warnx("tpm major version mismatch: found 0x%x, expected 0x%x",
		    tpm.smbtpm_major, smbios_tpm_major);
		ret = B_FALSE;
	}

	if (tpm.smbtpm_minor != smbios_tpm_minor) {
		warnx("tpm minor version mismatch: found 0x%x, expected 0x%x",
		    tpm.smbtpm_minor, smbios_tpm_minor);
		ret = B_FALSE;
	}

	if (tpm.smbtpm_fwv1 != smbios_tpm_fwv1) {
		warnx("tpm firmware version 1 mismatch: found 0x%x, "
		    "expected 0x%x", tpm.smbtpm_fwv1, smbios_tpm_fwv1);
		ret = B_FALSE;
	}

	if (tpm.smbtpm_fwv2 != smbios_tpm_fwv2) {
		warnx("tpm firmware version 2 mismatch: found 0x%x, "
		    "expected 0x%x", tpm.smbtpm_fwv2, smbios_tpm_fwv2);
		ret = B_FALSE;
	}

	if (tpm.smbtpm_chars != smbios_tpm_chars) {
		warnx("tpm characteristics mismatch: found 0x%" PRIx64
		    ", expected 0x%" PRIx64, tpm.smbtpm_chars,
		    smbios_tpm_chars);
		ret = B_FALSE;
	}

	if (tpm.smbtpm_oem != smbios_tpm_oem) {
		warnx("tpm OEM-defined mismatch: found 0x%x, expected 0x%x",
		    tpm.smbtpm_oem, smbios_tpm_oem);
		ret = B_FALSE;
	}

	return (ret);
}
