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
 * Copyright 2021 Oxide Computer Company
 */

/*
 * Basic testing of the SMBIOS 3.2 Slot extensions.
 */

#include "smbios_test.h"

static const char *smbios_test_name = "The One Slot";
static uint8_t smbios_slot_bus = 0x42;
static uint8_t smbios_slot_df = 0x23;
static uint8_t smbios_slot_info = 0x65;
static uint16_t smbios_slot_pitch = 0x12af;

static size_t smbios_slot_34_contlen = offsetof(smb_slot_cont_t, smbsl_height);

static void
smbios_test_slot_fill(smb_slot_t *slot)
{
	bzero(slot, sizeof (smb_slot_t));
	slot->smbsl_hdr.smbh_type = SMB_TYPE_SLOT;
	slot->smbsl_hdr.smbh_len = sizeof (smb_slot_t);
	slot->smbsl_name = 1;
	slot->smbsl_type = SMB_SLT_PCIE3G16;
	slot->smbsl_width = SMB_SLW_16X;
	slot->smbsl_length = SMB_SLL_SHORT;
	slot->smbsl_id = htole16(1);
	slot->smbsl_ch1 = SMB_SLCH1_33V;
	slot->smbsl_ch2 = SMB_SLCH2_PME;
	slot->smbsl_sg = htole16(1);
	slot->smbsl_bus = smbios_slot_bus;
	slot->smbsl_df = smbios_slot_df;
	slot->smbsl_dbw = SMB_SLW_16X;
}

boolean_t
smbios_test_slot_mktable(smbios_test_table_t *table)
{
	smb_slot_t slot;
	smb_slot_peer_t peers[2];

	smbios_test_slot_fill(&slot);

	slot.smbsl_hdr.smbh_len += sizeof (peers);
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
	smbios_test_table_append_raw(table, peers, sizeof (peers));
	smbios_test_table_append_string(table, smbios_test_name);
	smbios_test_table_str_fini(table);

	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

static boolean_t
smbios_test_slot_mktable_nopeers(smbios_test_table_t *table, boolean_t is_35)
{
	smb_slot_t slot;
	smb_slot_cont_t cont;
	size_t contlen;

	if (is_35) {
		contlen = sizeof (cont);
	} else {
		contlen = smbios_slot_34_contlen;
	}

	smbios_test_slot_fill(&slot);
	slot.smbsl_hdr.smbh_len = SMB_SLOT_CONT_START + contlen;

	cont.smbsl_info = smbios_slot_info;
	cont.smbsl_pwidth = SMB_SLW_32X;
	cont.smbsl_pitch = htole16(smbios_slot_pitch);
	cont.smbsl_height = SMB_SLHT_LP;

	(void) smbios_test_table_append(table, &slot, sizeof (slot));
	smbios_test_table_append_raw(table, &cont, contlen);
	smbios_test_table_append_string(table, smbios_test_name);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

/*
 * 3.4 introduced additional data after peers. This version constructs a variant
 * with no peers.
 */
boolean_t
smbios_test_slot_mktable_34_nopeers(smbios_test_table_t *table)
{
	return (smbios_test_slot_mktable_nopeers(table, B_FALSE));
}

boolean_t
smbios_test_slot_mktable_35(smbios_test_table_t *table)
{
	return (smbios_test_slot_mktable_nopeers(table, B_TRUE));
}

boolean_t
smbios_test_slot_mktable_34_peers(smbios_test_table_t *table)
{
	smb_slot_t slot;
	smb_slot_cont_t cont;
	smb_slot_peer_t peers[1];

	smbios_test_slot_fill(&slot);
	slot.smbsl_npeers = 1;
	slot.smbsl_hdr.smbh_len = SMB_SLOT_CONT_START + 5 * slot.smbsl_npeers +
	    smbios_slot_34_contlen;

	peers[0].smbspb_group_no = htole16(1);
	peers[0].smbspb_bus = 0x42;
	peers[0].smbspb_df = 0x9a;
	peers[0].smbspb_width = SMB_SLW_8X;

	cont.smbsl_info = smbios_slot_info;
	cont.smbsl_pwidth = SMB_SLW_32X;
	cont.smbsl_pitch = htole16(smbios_slot_pitch);

	(void) smbios_test_table_append(table, &slot, sizeof (slot));
	smbios_test_table_append_raw(table, peers, sizeof (peers));
	smbios_test_table_append_raw(table, &cont, smbios_slot_34_contlen);
	smbios_test_table_append_string(table, smbios_test_name);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

static boolean_t
smbios_test_slot_common(smbios_slot_t *slot)
{
	uint_t errs = 0;

	if (strcmp(slot->smbl_name, smbios_test_name) != 0) {
		warnx("slot name mismatch, expected %s, found %s",
		    smbios_test_name, slot->smbl_name);
		errs++;
	}

	if (slot->smbl_type != SMB_SLT_PCIE3G16) {
		warnx("incorrect slot type, found %u", slot->smbl_type);
		errs++;
	}

	if (slot->smbl_width != SMB_SLW_16X) {
		warnx("incorrect slot width, found %u", slot->smbl_width);
		errs++;
	}

	if (slot->smbl_length != SMB_SLL_SHORT) {
		warnx("incorrect slot length, found %u", slot->smbl_length);
		errs++;
	}

	if (slot->smbl_dbw != SMB_SLW_16X) {
		warnx("incorrect slot data bus width, found %u",
		    slot->smbl_dbw);
		errs++;
	}

	if (slot->smbl_bus != smbios_slot_bus) {
		warnx("incorrect slot bus id, found 0x%x\n", slot->smbl_bus);
	}

	if (slot->smbl_df != smbios_slot_df) {
		warnx("incorrect slot df id, found 0x%x\n", slot->smbl_df);
	}

	if (errs > 0) {
		return (B_FALSE);
	}

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

	if (!smbios_test_slot_common(&slot)) {
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
		warnx("got wrong number of slot peers: %u", npeers);
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

	if (slot.smbl_info != 0) {
		warnx("found wrong slot info: 0x%x", slot.smbl_info);
		errs++;
	}

	if (slot.smbl_pwidth != 0) {
		warnx("found wrong slot physical width: 0x%x",
		    slot.smbl_pwidth);
		errs++;
	}

	if (slot.smbl_pitch != 0) {
		warnx("found wrong slot pitch: 0x%x", slot.smbl_pitch);
		errs++;
	}

	if (errs > 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
smbios_test_slot_common_nopeers(smbios_hdl_t *hdl, smbios_struct_t *sp,
    smbios_slot_t *slot)
{
	uint_t errs = 0;
	uint_t npeers;
	smbios_slot_peer_t *peers;

	if (slot->smbl_npeers != 0) {
		warnx("incorrect number of slot peers, found %u",
		    slot->smbl_npeers);
		errs++;
	}

	if (smbios_info_slot_peers(hdl, sp->smbstr_id, &npeers, &peers) != 0) {
		warnx("failed to get SMBIOS peer info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (npeers != 0) {
		warnx("got wrong number of slot peers: %u", npeers);
		errs++;
	}

	if (peers != NULL) {
		warnx("expected NULL peers pointer, but found %p", peers);
		errs++;
	}

	smbios_info_slot_peers_free(hdl, npeers, peers);

	if (slot->smbl_info != smbios_slot_info) {
		warnx("found wrong slot info: 0x%x, expected 0x%x",
		    slot->smbl_info, smbios_slot_info);
		errs++;
	}

	if (slot->smbl_pwidth != SMB_SLW_32X) {
		warnx("found wrong slot physical width: 0x%x, expected 0x%x",
		    slot->smbl_pwidth, SMB_SLW_32X);
		errs++;
	}

	if (slot->smbl_pitch != smbios_slot_pitch) {
		warnx("found wrong slot pitch: 0x%x, expected 0x%x",
		    slot->smbl_pitch, smbios_slot_pitch);
		errs++;
	}

	return (errs == 0);
}

boolean_t
smbios_test_slot_verify_34_nopeers(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_slot_t slot;
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

	if (!smbios_test_slot_common(&slot)) {
		errs++;
	}

	if (!smbios_test_slot_common_nopeers(hdl, &sp, &slot)) {
		errs++;
	}

	if (errs > 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * This is a variant of smbios_test_slot_verify_34_nopeers() that specifically
 * uses an older library version and ensures that we don't overrun the
 * smbios_slot_t.
 */
boolean_t
smbios_test_slot_verify_34_overrun(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_slot_t slot;
	uint_t errs = 0;

	/*
	 * We purposefully set the values that are part of SMBIOS 3.5+ to bad
	 * values to make sure that we don't end up zeroing them.
	 */
	slot.smbl_height = 0xba;

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

	if (slot.smbl_height != 0xba) {
		warnx("smbios 3.4 slot structure was overrun, smbl_height "
		    "unexpectedly set to 0x%x", slot.smbl_height);
		errs++;
	}

	if (!smbios_test_slot_common(&slot)) {
		errs++;
	}

	if (!smbios_test_slot_common_nopeers(hdl, &sp, &slot)) {
		errs++;
	}

	if (errs > 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
smbios_test_slot_verify_35(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_slot_t slot;
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

	if (!smbios_test_slot_common(&slot)) {
		errs++;
	}

	if (!smbios_test_slot_common_nopeers(hdl, &sp, &slot)) {
		errs++;
	}

	if (slot.smbl_height != SMB_SLHT_LP) {
		warnx("found wrong slot height: 0x%x, expected 0x%x",
		    slot.smbl_height, SMB_SLHT_LP);
		errs++;
	}

	if (errs > 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
smbios_test_slot_verify_34_peers(smbios_hdl_t *hdl)
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

	if (!smbios_test_slot_common(&slot)) {
		errs++;
	}

	if (slot.smbl_npeers != 1) {
		warnx("incorrect number of slot peers, found %u",
		    slot.smbl_npeers);
		errs++;
	}

	if (smbios_info_slot_peers(hdl, sp.smbstr_id, &npeers, &peers) != 0) {
		warnx("failed to get SMBIOS peer info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (npeers != 1) {
		warnx("got wrong number of slot peers: %u", npeers);
		errs++;
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

	if (peers[0].smblp_bus != 0x42) {
		warnx("incorrect PCI bus for peer 0: %u",
		    peers[0].smblp_bus);
		errs++;
	}

	if (peers[0].smblp_device != (0x9a >> 3)) {
		warnx("incorrect PCI device for peer 0: %u",
		    peers[0].smblp_device);
		errs++;
	}

	if (peers[0].smblp_function != (0x9a & 0x7)) {
		warnx("incorrect PCI function for peer 0: %u",
		    peers[0].smblp_function);
		errs++;
	}

	smbios_info_slot_peers_free(hdl, npeers, peers);

	if (slot.smbl_info != smbios_slot_info) {
		warnx("found wrong slot info: 0x%x, expected 0x%x",
		    slot.smbl_info, smbios_slot_info);
		errs++;
	}

	if (slot.smbl_pwidth != SMB_SLW_32X) {
		warnx("found wrong slot physical width: 0x%x, expected 0x%x",
		    slot.smbl_pwidth, SMB_SLW_32X);
		errs++;
	}

	if (slot.smbl_pitch != smbios_slot_pitch) {
		warnx("found wrong slot pitch: 0x%x, expected 0x%x",
		    slot.smbl_pitch, smbios_slot_pitch);
		errs++;
	}

	if (errs > 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}
