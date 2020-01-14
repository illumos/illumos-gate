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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Basic testing of the SMBIOS 3.2 Slot extensions.
 */

#include "smbios_test.h"

static const char *smbios_test_name = "The One Slot";

boolean_t
smbios_test_slot_mktable(smbios_test_table_t *table)
{
	smb_slot_t slot;
	smb_slot_peer_t peers[2];
	const uint8_t endstring = 0;

	slot.smbsl_hdr.smbh_type = SMB_TYPE_SLOT;
	slot.smbsl_hdr.smbh_len = sizeof (smb_slot_t) + sizeof (peers);

	slot.smbsl_name = 1;
	slot.smbsl_type = SMB_SLT_PCIE3G16;
	slot.smbsl_width = SMB_SLW_16X;
	slot.smbsl_length = SMB_SLL_SHORT;
	slot.smbsl_id = htole16(1);
	slot.smbsl_ch1 = SMB_SLCH1_33V;
	slot.smbsl_ch2 = SMB_SLCH2_PME;
	slot.smbsl_sg = htole16(1);
	slot.smbsl_bus = 0x42;
	slot.smbsl_df = 0x23;
	slot.smbsl_dbw = SMB_SLW_16X;
	slot.smbsl_npeers = 2;
	peers[0].smbspb_group_no = htole16(1);
	peers[0].smbspb_bus = 0x42;
	peers[0].smbspb_df = 0x42;
	peers[0].smbspb_width = SMB_SLW_8X;

	peers[1].smbspb_group_no = htole16(1);
	peers[1].smbspb_bus = 0x23;
	peers[1].smbspb_df = 0x31;
	peers[1].smbspb_width = SMB_SLW_8X;

	(void) smbios_test_table_append(table, &slot, sizeof (slot));
	(void) smbios_test_table_append_raw(table, peers, sizeof (peers));
	(void) smbios_test_table_append_string(table, smbios_test_name);
	(void) smbios_test_table_append_raw(table, &endstring,
	    sizeof (endstring));

	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_slot_verify(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_slot_t slot;
	uint_t npeers;
	smbios_slot_peer_t *peers;
	uint_t errs = 0;

	if (smbios_lookup_type(hdl, SMB_TYPE_SLOT, &sp) == -1) {
		warnx("failed to lookup SMBIOS slot: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_slot(hdl, sp.smbstr_id, &slot) != 0) {
		warnx("failed to get SMBIOS slot info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	/*
	 * Verify everything we'd expect about the slot.
	 */
	if (strcmp(slot.smbl_name, smbios_test_name) != 0) {
		warnx("slot name mismatch, expected %s, found %s",
		    smbios_test_name, slot.smbl_name);
		errs++;
	}

	if (slot.smbl_type != SMB_SLT_PCIE3G16) {
		warnx("incorrect slot type, found %u", slot.smbl_type);
		errs++;
	}

	if (slot.smbl_width != SMB_SLW_16X) {
		warnx("incorrect slot width, found %u", slot.smbl_width);
		errs++;
	}

	if (slot.smbl_length != SMB_SLL_SHORT) {
		warnx("incorrect slot length, found %u", slot.smbl_length);
		errs++;
	}

	if (slot.smbl_dbw != SMB_SLW_16X) {
		warnx("incorrect slot data bus width, found %u", slot.smbl_dbw);
		errs++;
	}

	if (slot.smbl_npeers != 2) {
		warnx("incorrect number of slot peers, found %u",
		    slot.smbl_npeers);
		errs++;
	}

	if (smbios_info_slot_peers(hdl, sp.smbstr_id, &npeers, &peers) != 0) {
		warnx("failed to get SMBIOS peer info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (npeers != 2) {
		warnx("got wrong number of slot peers: %u\n",
		    npeers);
		return (B_FALSE);
	}

	if (peers[0].smblp_group != 1) {
		warnx("incorrect group for peer 0: %u", peers[0].smblp_group);
		errs++;
	}

	if (peers[0].smblp_data_width != SMB_SLW_8X) {
		warnx("incorrect data width for peer 0: %u",
		    peers[0].smblp_data_width);
		errs++;
	}

	if (peers[0].smblp_device != (0x42 >> 3)) {
		warnx("incorrect PCI device for peer 0: %u",
		    peers[0].smblp_device);
		errs++;
	}

	if (peers[0].smblp_function != (0x42 & 0x7)) {
		warnx("incorrect PCI function for peer 0: %u",
		    peers[0].smblp_function);
		errs++;
	}

	if (peers[1].smblp_group != 1) {
		warnx("incorrect group for peer 1: %u", peers[1].smblp_group);
		errs++;
	}

	if (peers[1].smblp_device != (0x31 >> 3)) {
		warnx("incorrect PCI device for peer 1: %u",
		    peers[1].smblp_device);
		errs++;
	}

	if (peers[1].smblp_function != (0x31 & 0x7)) {
		warnx("incorrect PCI function for peer 1: %u",
		    peers[1].smblp_function);
		errs++;
	}

	if (peers[1].smblp_data_width != SMB_SLW_8X) {
		warnx("incorrect data width for peer 1: %u",
		    peers[1].smblp_data_width);
		errs++;
	}

	smbios_info_slot_peers_free(hdl, npeers, peers);

	if (errs > 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}
