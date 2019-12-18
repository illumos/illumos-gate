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
 * Copyright 2019 Robert Mustacchi
 */

/*
 * Basic testing of the SMBIOS 3.3 memory device extensions. We test these in a
 * few different ways:
 *
 * 1. Using a 3.2 table with a 3.2 library to make sure we get the old fields.
 * We also need to verify that we don't clobber memory in this case.
 * 2. Using a 3.2 table with a 3.3 library to make sure we get the new fields.
 * populated with the corresponding 3.2 values.
 * 3. Using a 3.3 table with only the old values as valid.
 * 4. Using a 3.3 table with both the old and new values as valid.
 * memory.
 */

#include <stdlib.h>
#include "smbios_test.h"

static uint16_t smbios_memdevice_speed = 0xdeed;
static uint16_t smbios_memdevice_clkspeed = 0xf00f;
static uint32_t smbios_memdevice_extspeed = 0xbaddeed;
static uint32_t smbios_memdevice_extclkspeed = 0xbadf00f;

/*
 * Fill in the basics of a single memory device. Callers need to fill in the
 * speed, extspeed, clkspeed, and extclkspeed members.
 */
static void
smbios_test_memdevice_fill(smb_memdevice_t *mem)
{
	mem->smbmdev_hdr.smbh_type = SMB_TYPE_MEMDEVICE;
	mem->smbmdev_hdr.smbh_len = sizeof (smb_memdevice_t);

	mem->smbmdev_array = 0xffff;
	mem->smbmdev_error = htole16(0xfffe);
	mem->smbmdev_twidth = 64;
	mem->smbmdev_dwidth = 64;
	mem->smbmdev_size = 0x7fff;
	mem->smbmdev_form = SMB_MDFF_FBDIMM;
	mem->smbmdev_set = 0;
	mem->smbmdev_dloc = 0;
	mem->smbmdev_bloc = 0;
	mem->smbmdev_type = SMB_MDT_DDR4;
	mem->smbmdev_manufacturer = 0;
	mem->smbmdev_asset = 0;
	mem->smbmdev_part = 0;
	mem->smbmdev_attrs = 2;
	mem->smbmdev_extsize = htole32(0x123456);
	mem->smbmdev_minvolt = 0;
	mem->smbmdev_maxvolt = 0;
	mem->smbmdev_confvolt = 0;
	mem->smbmdev_memtech = 0;
	mem->smbmdev_opmode = 1 << 3;
	mem->smbmdev_fwver = 0;
	mem->smbmdev_modulemfgid = 0;
	mem->smbmdev_moduleprodid = 0;
	mem->smbmdev_memsysmfgid = 0;
	mem->smbmdev_memsysprodid = 0;
	mem->smbmdev_nvsize = htole64(UINT64_MAX);
	mem->smbmdev_volsize = htole64(UINT64_MAX);
	mem->smbmdev_cachesize = htole64(UINT64_MAX);
	mem->smbmdev_logicalsize = htole64(UINT64_MAX);
}

boolean_t
smbios_test_memdevice_mktable_32(smbios_test_table_t *table)
{
	smb_memdevice_t mem;
	size_t len = 0x54;

	smbios_test_memdevice_fill(&mem);
	mem.smbmdev_speed = htole16(smbios_memdevice_speed);
	mem.smbmdev_clkspeed = htole16(smbios_memdevice_clkspeed);
	mem.smbmdev_extspeed = htole32(0);
	mem.smbmdev_extclkspeed = htole32(0);

	/*
	 * Because we're emulating an SMBIOS 3.2 table, we have to set it to the
	 * specification's defined size for that revision - 0x54.
	 */
	mem.smbmdev_hdr.smbh_len = len;
	(void) smbios_test_table_append(table, &mem, len);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_memdevice_mktable_33(smbios_test_table_t *table)
{
	smb_memdevice_t mem;

	smbios_test_memdevice_fill(&mem);
	mem.smbmdev_speed = htole16(smbios_memdevice_speed);
	mem.smbmdev_clkspeed = htole16(smbios_memdevice_clkspeed);
	mem.smbmdev_extspeed = htole32(0);
	mem.smbmdev_extclkspeed = htole32(0);

	(void) smbios_test_table_append(table, &mem, sizeof (mem));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_memdevice_mktable_33ext(smbios_test_table_t *table)
{
	smb_memdevice_t mem;

	smbios_test_memdevice_fill(&mem);
	mem.smbmdev_speed = htole16(0xffff);
	mem.smbmdev_clkspeed = htole16(0xffff);
	mem.smbmdev_extspeed = htole32(smbios_memdevice_extspeed);
	mem.smbmdev_extclkspeed = htole32(smbios_memdevice_extclkspeed);

	(void) smbios_test_table_append(table, &mem, sizeof (mem));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

static boolean_t
smbios_test_memdevice_verify_common(smbios_memdevice_t *mem)
{
	boolean_t ret = B_TRUE;

	if (mem->smbmd_dwidth != 64) {
		warnx("found wrong dwidth: %u", mem->smbmd_dwidth);
		ret = B_FALSE;
	}

	if (mem->smbmd_twidth != 64) {
		warnx("found wrong twidth: %u", mem->smbmd_twidth);
		ret = B_FALSE;
	}

	if (mem->smbmd_form != SMB_MDFF_FBDIMM) {
		warnx("found wrong form: %u", mem->smbmd_form);
		ret = B_FALSE;
	}

	if (mem->smbmd_size != 0x123456ULL * 1024 * 1024) {
		warnx("found wrong size: %u", mem->smbmd_size);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_memdevice_verify_32(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_memdevice_t mem;
	boolean_t ret = B_TRUE;
	uint64_t rval;

	/*
	 * We expect that the SMBIOS 3.2 memory device values should not be
	 * touched here. As such we set them to a random value to verify and
	 * verify that it hasn't been set.
	 */
	arc4random_buf(&rval, sizeof (rval));
	mem.smbmd_extspeed = rval;
	mem.smbmd_extclkspeed = rval;

	if (smbios_lookup_type(hdl, SMB_TYPE_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_memdevice(hdl, sp.smbstr_id, &mem) != 0) {
		warnx("failed to get SMBIOS memory device info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (mem.smbmd_extspeed != rval || mem.smbmd_extclkspeed != rval) {
		warnx("smbios_memdevice_t had its memory cloberred!");
		return (B_FALSE);
	}

	if (!smbios_test_memdevice_verify_common(&mem)) {
		return (B_FALSE);
	}

	if (mem.smbmd_speed != smbios_memdevice_speed) {
		warnx("found wrong device speed: %u", mem.smbmd_speed);
		ret = B_FALSE;
	}

	if (mem.smbmd_clkspeed != smbios_memdevice_clkspeed) {
		warnx("found wrong device clkspeed: %u", mem.smbmd_clkspeed);
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * This is a variant of smbios_test_memdevice_verify_32(), but instead of using
 * an SMBIOS 3.2 library, we use an SMBIOS 3.3 handle. This means that we expect
 * the extended values to be populated with the base values.
 */
boolean_t
smbios_test_memdevice_verify_32_33(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_memdevice_t mem;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_memdevice(hdl, sp.smbstr_id, &mem) != 0) {
		warnx("failed to get SMBIOS memory device info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_memdevice_verify_common(&mem)) {
		return (B_FALSE);
	}

	if (mem.smbmd_speed != smbios_memdevice_speed) {
		warnx("found wrong device speed: %u", mem.smbmd_speed);
		ret = B_FALSE;
	}

	if (mem.smbmd_clkspeed != smbios_memdevice_clkspeed) {
		warnx("found wrong device clkspeed: %u", mem.smbmd_clkspeed);
		ret = B_FALSE;
	}

	if (mem.smbmd_extspeed != smbios_memdevice_speed) {
		warnx("found wrong device speed: %u", mem.smbmd_extspeed);
		ret = B_FALSE;
	}

	if (mem.smbmd_extclkspeed != smbios_memdevice_clkspeed) {
		warnx("found wrong device clkspeed: %u", mem.smbmd_extclkspeed);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_memdevice_verify_33(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_memdevice_t mem;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_memdevice(hdl, sp.smbstr_id, &mem) != 0) {
		warnx("failed to get SMBIOS memory device info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_memdevice_verify_common(&mem)) {
		return (B_FALSE);
	}

	if (mem.smbmd_speed != smbios_memdevice_speed) {
		warnx("found wrong device speed: %u", mem.smbmd_speed);
		ret = B_FALSE;
	}

	if (mem.smbmd_clkspeed != smbios_memdevice_clkspeed) {
		warnx("found wrong device clkspeed: %u", mem.smbmd_clkspeed);
		ret = B_FALSE;
	}

	if (mem.smbmd_extspeed != smbios_memdevice_speed) {
		warnx("found wrong device speed: %u", mem.smbmd_extspeed);
		ret = B_FALSE;
	}

	if (mem.smbmd_extclkspeed != smbios_memdevice_clkspeed) {
		warnx("found wrong device clkspeed: %u", mem.smbmd_extclkspeed);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_memdevice_verify_33ext(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_memdevice_t mem;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS memory device: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_memdevice(hdl, sp.smbstr_id, &mem) != 0) {
		warnx("failed to get SMBIOS memory device info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_memdevice_verify_common(&mem)) {
		return (B_FALSE);
	}

	if (mem.smbmd_speed != 0xffff) {
		warnx("found wrong device speed: %u", mem.smbmd_speed);
		ret = B_FALSE;
	}

	if (mem.smbmd_clkspeed != 0xffff) {
		warnx("found wrong device clkspeed: %u", mem.smbmd_clkspeed);
		ret = B_FALSE;
	}

	if (mem.smbmd_extspeed != smbios_memdevice_extspeed) {
		warnx("found wrong device speed: %u", mem.smbmd_extspeed);
		ret = B_FALSE;
	}

	if (mem.smbmd_extclkspeed != smbios_memdevice_extclkspeed) {
		warnx("found wrong device clkspeed: %u", mem.smbmd_extclkspeed);
		ret = B_FALSE;
	}

	return (ret);
}
