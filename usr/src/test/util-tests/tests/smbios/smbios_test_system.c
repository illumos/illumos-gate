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
 * Tests for SMBIOS System, Type 1.
 *
 * We basically create three different types of tables. Those that mimic 2.0 and
 * therefore stop short of the UUID. Those that mimic 2.1-2.3 which fall short
 * of the family string. And those that have everything.
 */

#include "smbios_test.h"

#include <sys/uuid.h>

static const char *sys_mfg = "manufacturer";
static const char *sys_product = "product";
static const char *sys_version = "version";
static const char *sys_serial = "serial";
static const uint8_t sys_uuid[UUID_LEN] = { 0x01, 0x02, 0x03, 0x4, 0x5, 0x6,
    0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe };
static const uint8_t sys_wakeup = 0x42;
static const char *sys_sku = "SKU";
static const char *sys_family = "family";

static void
smbios_test_system_mktable_common(smbios_test_table_t *table, size_t len)
{
	smb_system_t sys;

	sys.smbsi_hdr.smbh_type = SMB_TYPE_SYSTEM;
	sys.smbsi_hdr.smbh_len = len;

	sys.smbsi_manufacturer = 1;
	sys.smbsi_product = 2;
	sys.smbsi_version = 3;
	sys.smbsi_serial = 4;
	(void) memcpy(sys.smbsi_uuid, sys_uuid, ARRAY_SIZE(sys_uuid));
	sys.smbsi_wakeup = sys_wakeup;
	sys.smbsi_sku = 5;
	sys.smbsi_family = 6;

	(void) smbios_test_table_append(table, &sys, len);
	if (len > offsetof(smb_system_t, smbsi_manufacturer))
		smbios_test_table_append_string(table, sys_mfg);
	if (len > offsetof(smb_system_t, smbsi_product))
		smbios_test_table_append_string(table, sys_product);
	if (len > offsetof(smb_system_t, smbsi_version))
		smbios_test_table_append_string(table, sys_version);
	if (len > offsetof(smb_system_t, smbsi_serial))
		smbios_test_table_append_string(table, sys_serial);
	if (len > offsetof(smb_system_t, smbsi_sku))
		smbios_test_table_append_string(table, sys_sku);
	if (len > offsetof(smb_system_t, smbsi_family))
		smbios_test_table_append_string(table, sys_family);
	if (len > offsetof(smb_system_t, smbsi_manufacturer))
		smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);
}

boolean_t
smbios_test_system_mktable_2p0(smbios_test_table_t *table)
{
	smbios_test_system_mktable_common(table, offsetof(smb_system_t,
	    smbsi_uuid));
	return (B_TRUE);
}

boolean_t
smbios_test_system_mktable_2p3(smbios_test_table_t *table)
{
	smbios_test_system_mktable_common(table, offsetof(smb_system_t,
	    smbsi_family));
	return (B_TRUE);
}

boolean_t
smbios_test_system_mktable(smbios_test_table_t *table)
{
	smbios_test_system_mktable_common(table, sizeof (smb_system_t));
	return (B_TRUE);
}

static boolean_t
smbios_test_system_verify_common(smbios_hdl_t *hdl, size_t len)
{
	boolean_t ret = B_TRUE;
	id_t id;
	smbios_struct_t sp;
	smbios_system_t sys;
	smbios_info_t info;

	if (smbios_lookup_type(hdl, SMB_TYPE_SYSTEM, &sp) == -1) {
		warnx("failed to lookup SMBIOS system: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	id = smbios_info_system(hdl, &sys);
	if (id < 0) {
		warnx("failed to get system information: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (id != sp.smbstr_id) {
		warnx("found mismatched IDs: smbios_info_system() returned 0x%"
		    _PRIxID ", but lookup gave us 0x%" _PRIxID, id,
		    sp.smbstr_id);
		return (B_FALSE);
	}

	if (smbios_info_common(hdl, id, &info) != 0) {
		warnx("failed to get system common information: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	/*
	 * Everything should always have a manufacturer, product, version, and
	 * serial.
	 */
	if (strcmp(info.smbi_manufacturer, sys_mfg) != 0) {
		warnx("found wrong manufacturer %s: expected %s",
		    info.smbi_manufacturer, sys_mfg);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_product, sys_product) != 0) {
		warnx("found wrong product %s: expected %s",
		    info.smbi_product, sys_product);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_version, sys_version) != 0) {
		warnx("found wrong version %s: expected %s",
		    info.smbi_version, sys_version);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_serial, sys_serial) != 0) {
		warnx("found wrong serial %s: expected %s",
		    info.smbi_serial, sys_serial);
		ret = B_FALSE;
	}

	if (len >= offsetof(smb_system_t, smbsi_wakeup)) {
		if (sys.smbs_uuidlen != ARRAY_SIZE(sys_uuid)) {
			warnx("found wrong uuid length %u: expected %zu",
			    sys.smbs_uuidlen, ARRAY_SIZE(sys_uuid));
			ret = B_FALSE;
		}

		if (sys.smbs_uuid == NULL) {
			warnx("found unexpected NULL uuid pointer");
			ret = B_FALSE;
		}

		if (sys.smbs_uuidlen == ARRAY_SIZE(sys_uuid) &&
		    sys.smbs_uuid != NULL && memcmp(sys.smbs_uuid,
		    sys_uuid, sizeof (sys_uuid)) != 0) {
			warnx("encountered UUID mismatch");
			ret = B_FALSE;
		}
	} else {
		if (sys.smbs_uuid != NULL) {
			warnx("found unexpected non-NULL uuid pointer");
			ret = B_FALSE;
		}

		if (sys.smbs_uuidlen != 0) {
			warnx("found unexpected non-zero uuid length: %u",
			    sys.smbs_uuidlen);
			ret = B_FALSE;
		}
	}

	if (len >= offsetof(smb_system_t, smbsi_sku)) {
		if (sys.smbs_wakeup != sys_wakeup) {
			warnx("found wrong wakeup 0x%x: expected 0x%x",
			    sys.smbs_wakeup, sys_wakeup);
			ret = B_FALSE;
		}
	} else if (sys.smbs_wakeup != 0) {
		warnx("found wrong wakeup 0x%x: expected none",
		    sys.smbs_wakeup);
		ret = B_FALSE;
	}

	if (len >= offsetof(smb_system_t, smbsi_family)) {
		if (strcmp(sys.smbs_sku, sys_sku) != 0) {
			warnx("found wrong sku %s: expected %s",
			    sys.smbs_sku, sys_sku);
			ret = B_FALSE;
		}
	} else if (strcmp(sys.smbs_sku, "") != 0) {
		warnx("found wrong sku %s: expected none", sys.smbs_sku);
		ret = B_FALSE;
	}

	if (len >= sizeof (smb_system_t)) {
		if (strcmp(sys.smbs_family, sys_family) != 0) {
			warnx("found wrong family %s: expected %s",
			    sys.smbs_family, sys_family);
			ret = B_FALSE;
		}
	} else if (strcmp(sys.smbs_family, "") != 0) {
		warnx("found wrong family %s: expected none", sys.smbs_family);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_system_verify_2p0(smbios_hdl_t *hdl)
{
	return (smbios_test_system_verify_common(hdl, offsetof(smb_system_t,
	    smbsi_uuid)));
}

boolean_t
smbios_test_system_verify_2p3(smbios_hdl_t *hdl)
{
	return (smbios_test_system_verify_common(hdl, offsetof(smb_system_t,
	    smbsi_family)));
}

boolean_t
smbios_test_system_verify(smbios_hdl_t *hdl)
{
	return (smbios_test_system_verify_common(hdl, sizeof (smb_system_t)));
}
