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
 * Basic tests for SMBIOS System Boot Information, Type 32.
 */

#include "smbios_test.h"

static const char *boot_data = "three rings for elven kings";

boolean_t
smbios_test_boot_mktable_short_base(smbios_test_table_t *table)
{
	smb_header_t hdr;

	hdr.smbh_type = SMB_TYPE_BOOT;
	hdr.smbh_len = sizeof (hdr);

	(void) smbios_test_table_append(table, &hdr, sizeof (hdr));
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_boot_mktable_short_data(smbios_test_table_t *table)
{
	smb_boot_t boot;

	(void) memset(&boot, 0, sizeof (smb_boot_t));
	boot.smbbo_hdr.smbh_type = SMB_TYPE_BOOT;
	boot.smbbo_hdr.smbh_len = sizeof (smb_boot_t) - 1;

	(void) smbios_test_table_append(table, &boot, sizeof (boot) - 1);
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_boot_mktable(smbios_test_table_t *table)
{
	smb_boot_t boot;
	size_t dlen = strlen(boot_data);

	(void) memset(&boot, 0, sizeof (smb_boot_t));
	boot.smbbo_hdr.smbh_type = SMB_TYPE_BOOT;
	boot.smbbo_hdr.smbh_len = sizeof (smb_boot_t) + dlen - 1;
	boot.smbbo_status[0] = boot_data[0];

	(void) smbios_test_table_append(table, &boot, sizeof (boot));
	smbios_test_table_append_raw(table, &boot_data[1], dlen - 1);
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_boot_mktable_nodata(smbios_test_table_t *table)
{
	smb_boot_t boot;

	(void) memset(&boot, 0, sizeof (smb_boot_t));
	boot.smbbo_hdr.smbh_type = SMB_TYPE_BOOT;
	boot.smbbo_hdr.smbh_len = sizeof (smb_boot_t);
	boot.smbbo_status[0] = 0x42;

	(void) smbios_test_table_append(table, &boot, sizeof (boot));
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_boot_verify_short(smbios_hdl_t *hdl)
{
	smbios_boot_t boot;

	if (smbios_info_boot(hdl, &boot) != -1) {
		warnx("accidentally parsed invalid boot data as valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for boot, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
smbios_test_boot_verify(smbios_hdl_t *hdl)
{
	smbios_boot_t boot;
	boolean_t ret = B_TRUE;

	if (smbios_info_boot(hdl, &boot) == -1) {
		warnx("failed to get boot data: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (boot.smbt_status != boot_data[0]) {
		warnx("found wrong boot status: expected 0x%x, found 0x%x",
		    boot_data[0], boot.smbt_status);
		ret = B_FALSE;
	}

	size_t len = strlen(boot_data);
	if (boot.smbt_size != len - 1) {
		warnx("found wrong data length: expected %zu, found %zu",
		    len - 1, boot.smbt_size);
		ret = B_FALSE;
	} else if (bcmp(boot.smbt_data, &boot_data[1], boot.smbt_size) != 0) {
		warnx("boot data mismatch encountered");
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_boot_verify_nodata(smbios_hdl_t *hdl)
{
	smbios_boot_t boot;
	boolean_t ret = B_TRUE;

	boot.smbt_data = (void *)(uintptr_t)0x7777;
	boot.smbt_size = 0x7777;

	if (smbios_info_boot(hdl, &boot) == -1) {
		warnx("failed to get boot data: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (boot.smbt_status != 0x42) {
		warnx("found wrong boot status: expected 0x42, found 0x%x",
		    boot.smbt_status);
		ret = B_FALSE;
	}

	if (boot.smbt_size != 0) {
		warnx("found non-zero data size: 0x%zx", boot.smbt_size);
		ret = B_FALSE;
	}

	if (boot.smbt_data != NULL) {
		warnx("found non-NULL data pointer: 0x%p", boot.smbt_data);
		ret = B_FALSE;
	}

	return (ret);
}
