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
 * Tests for Sun OEM Port, Type 136.
 */

#include "smbios_test.h"

static const uint16_t port_chassis = 0x1234;
static const uint16_t port_port = 0x7777;
static const uint8_t port_dtype = 0x23;
static const uint16_t port_devhdl = 0xbeef;
static const uint8_t port_phy = 0x42;

boolean_t
smbios_test_extport_mktable_short(smbios_test_table_t *table)
{
	smb_header_t hdr;

	smbios_test_table_add_sunoem(table);

	hdr.smbh_type = SUN_OEM_EXT_PORT;
	hdr.smbh_len = sizeof (hdr);

	(void) smbios_test_table_append(table, &hdr, sizeof (hdr));
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_extport_mktable(smbios_test_table_t *table)
{
	smb_port_ext_t port;

	smbios_test_table_add_sunoem(table);

	port.smbpoe_hdr.smbh_type = SUN_OEM_EXT_PORT;
	port.smbpoe_hdr.smbh_len = sizeof (port);

	port.smbpoe_chassis = port_chassis;
	port.smbpoe_port = port_port;
	port.smbpoe_dtype = port_dtype;
	port.smbpoe_devhdl = port_devhdl;
	port.smbpoe_phy = port_phy;

	(void) smbios_test_table_append(table, &port, sizeof (port));
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_extport_verify_short(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_port_ext_t port;

	if (smbios_lookup_type(hdl, SUN_OEM_EXT_PORT, &sp) == -1) {
		warnx("failed to lookup SMBIOS Sun OEM port: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_extport(hdl, sp.smbstr_id, &port) != -1) {
		warnx("accidentally parsed invalid extended port as valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for extended port, expected: "
		    "0x%x, found: 0x%x", ESMB_SHORT, smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
smbios_test_extport_verify(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_port_ext_t port;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SUN_OEM_EXT_PORT, &sp) == -1) {
		warnx("failed to lookup SMBIOS Sun OEM port: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_extport(hdl, sp.smbstr_id, &port) == -1) {
		warnx("failed to get extended port information: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (port.smbporte_chassis != port_chassis) {
		warnx("found wrong port chassis 0x%x: expected 0x%x",
		    port.smbporte_chassis, port_chassis);
		ret = B_FALSE;
	}

	if (port.smbporte_port != port_port) {
		warnx("found wrong port connector 0x%x: expected 0x%x",
		    port.smbporte_port, port_port);
		ret = B_FALSE;
	}

	if (port.smbporte_dtype != port_dtype) {
		warnx("found wrong port dtype 0x%x: expected 0x%x",
		    port.smbporte_dtype, port_dtype);
		ret = B_FALSE;
	}

	if (port.smbporte_devhdl != port_devhdl) {
		warnx("found wrong port devhdl 0x%x: expected 0x%x",
		    port.smbporte_devhdl, port_devhdl);
		ret = B_FALSE;
	}

	if (port.smbporte_phy != port_phy) {
		warnx("found wrong port phy 0x%x: expected 0x%x",
		    port.smbporte_phy, port_phy);
		ret = B_FALSE;
	}

	return (ret);
}
