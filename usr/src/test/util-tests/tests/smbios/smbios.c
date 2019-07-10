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
 * Primordial SMBIOS test suite. At the moment, the purpose of this is just to
 * test the recent SMBIOS 3.2 additions specific to the variable length slots.
 * This should be evolved into a much fuller test suite.
 */

#include <smbios.h>
#include <umem.h>
#include <stdint.h>
#include <endian.h>
#include <stdio.h>
#include <err.h>

#include <sys/smbios.h>
#include <sys/smbios_impl.h>

static const char *smbios_test_name = "The One Slot";

/*
 * Number of bytes we allocate at a given time for an SMBIOS table.
 */
#define	SMBIOS_TEST_ALLOC_SIZE	1024

typedef struct smbios_test_table {
	smbios_entry_point_t	stt_type;
	void			*stt_data;
	size_t			stt_buflen;
	size_t			stt_offset;
	uint_t			stt_nents;
	uint_t			stt_version;
	uint_t			stt_nextid;
	smbios_entry_t		stt_entry;
} smbios_test_table_t;

const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}

static smbios_test_table_t *
smbios_test_table_init(smbios_entry_point_t type, uint_t version)
{
	smbios_test_table_t *table;

	if (type != SMBIOS_ENTRY_POINT_30) {
		abort();
	}

	table = umem_zalloc(sizeof (smbios_test_table_t), UMEM_DEFAULT);
	if (table == NULL) {
		return (NULL);
	}

	table->stt_data = umem_zalloc(SMBIOS_TEST_ALLOC_SIZE, UMEM_DEFAULT);
	if (table->stt_data == NULL) {
		umem_free(table, sizeof (smbios_test_table_t));
		return (NULL);
	}
	table->stt_buflen = SMBIOS_TEST_ALLOC_SIZE;
	table->stt_type = type;
	table->stt_version = version;
	table->stt_nextid = 1;

	return (table);
}

static void *
smbios_test_table_append_common(smbios_test_table_t *table, const void *buf,
    size_t len)
{
	void *start;

	if (SIZE_MAX - table->stt_offset < len)
		abort();

	if (len + table->stt_offset >= table->stt_buflen) {
		void *newbuf;
		size_t newlen = table->stt_buflen + SMBIOS_TEST_ALLOC_SIZE;

		while (len + table->stt_offset >= newlen) {
			newlen += SMBIOS_TEST_ALLOC_SIZE;
		}

		newbuf = umem_zalloc(newlen, UMEM_DEFAULT);
		if (newbuf == NULL) {
			err(EXIT_FAILURE, "failed to umem_zalloc for %lu bytes",
			    newlen);
		}

		(void) memcpy(newbuf, table->stt_data, table->stt_buflen);
		umem_free(table->stt_data, table->stt_buflen);
		table->stt_data = newbuf;
		table->stt_buflen = newlen;
	}

	start = (void *)((uintptr_t)table->stt_data + table->stt_offset);
	(void) memcpy(start, buf, len);
	table->stt_offset += len;

	return (start);
}

static void
smbios_test_table_append_raw(smbios_test_table_t *table, const void *buf,
    size_t len)
{
	(void) smbios_test_table_append_common(table, buf, len);
}

static void
smbios_test_table_append_string(smbios_test_table_t *table, const char *str)
{
	size_t len = strlen(str) + 1;
	(void) smbios_test_table_append_common(table, str, len);
}

static uint16_t
smbios_test_table_append(smbios_test_table_t *table, const void *buf,
    size_t len)
{
	smb_header_t *hdr;
	uint16_t id;

	hdr = smbios_test_table_append_common(table, buf, len);
	table->stt_nents++;

	id = table->stt_nextid;
	hdr->smbh_hdl = htole16(table->stt_nextid);
	table->stt_nextid++;

	return (id);
}

static uint8_t
smbios_test_table_checksum(const uint8_t *buf, size_t len)
{
	uint8_t sum;
	size_t i;

	for (i = 0, sum = 0; i < len; i++) {
		sum += buf[i];
	}

	if (sum == 0)
		return (0);

	return ((uint8_t)(0x100 - sum));
}

static void
smbios_test_table_snapshot(smbios_test_table_t *table, smbios_entry_t **entryp,
    void **bufp, size_t *lenp)
{
	smbios_30_entry_t *ent30;

	switch (table->stt_type) {
	case SMBIOS_ENTRY_POINT_30:
		ent30 = &table->stt_entry.ep30;

		(void) memcpy(ent30->smbe_eanchor, SMB3_ENTRY_EANCHOR,
		    sizeof (ent30->smbe_eanchor));
		ent30->smbe_ecksum = 0;
		ent30->smbe_elen = sizeof (*ent30);
		ent30->smbe_major = (table->stt_version >> 8) & 0xff;
		ent30->smbe_minor = table->stt_version & 0xff;
		ent30->smbe_docrev = 0;
		ent30->smbe_revision = 1;
		ent30->smbe_reserved = 0;
		ent30->smbe_stlen = htole32(table->stt_offset);
		ent30->smbe_staddr = htole64(P2ROUNDUP(sizeof (*ent30), 16));

		ent30->smbe_ecksum = smbios_test_table_checksum((void *)ent30,
		    sizeof (*ent30));
		break;
	default:
		abort();
	}

	*entryp = &table->stt_entry;
	*bufp = table->stt_data;
	*lenp = table->stt_offset;
}

static void
smbios_test_table_fini(smbios_test_table_t *table)
{
	if (table == NULL) {
		return;
	}

	if (table->stt_data != NULL) {
		umem_free(table->stt_data, table->stt_buflen);
	}

	umem_free(table, sizeof (smbios_test_table_t));
}

static void
smbios_test_mktable(smbios_test_table_t *table)
{
	smb_slot_t slot;
	smb_slot_peer_t peers[2];
	smb_header_t eot;
	uint8_t endstring = 0;

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

	bzero(&eot, sizeof (eot));
	eot.smbh_type = SMB_TYPE_EOT;
	eot.smbh_len = 4;
	(void) smbios_test_table_append(table, &eot, sizeof (eot));
	(void) smbios_test_table_append_raw(table, &endstring,
	    sizeof (endstring));
	(void) smbios_test_table_append_raw(table, &endstring,
	    sizeof (endstring));
}

static void
smbios_test_verify_table(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_slot_t slot;
	uint_t npeers;
	smbios_slot_peer_t *peers;
	uint_t errs = 0;

	if (smbios_lookup_type(hdl, SMB_TYPE_SLOT, &sp) == -1) {
		errx(EXIT_FAILURE, "failed to lookup SMBIOS slot: %s",
		    smbios_errmsg(smbios_errno(hdl)));
	}

	if (smbios_info_slot(hdl, sp.smbstr_id, &slot) != 0) {
		errx(EXIT_FAILURE, "failed to get SMBIOS slot info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
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
		errx(EXIT_FAILURE, "failed to get SMBIOS peer info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
	}

	if (npeers != 2) {
		errx(EXIT_FAILURE, "got wrong number of slot peers: %u\n",
		    npeers);
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
		errx(EXIT_FAILURE, "encountered fatal errors");
	}
}

int
main(void)
{
	void *buf;
	size_t len;
	smbios_test_table_t *table;
	smbios_entry_t *entry;
	smbios_hdl_t *hdl;
	int err = 0;

	table = smbios_test_table_init(SMBIOS_ENTRY_POINT_30, SMB_VERSION_32);
	smbios_test_mktable(table);
	smbios_test_table_snapshot(table, &entry, &buf, &len);

	hdl = smbios_bufopen(entry, buf, len, SMB_VERSION_32, SMB_FL_DEBUG,
	    &err);
	if (hdl == NULL) {
		errx(EXIT_FAILURE, "failed to create fake smbios table: %s",
		    smbios_errmsg(err));
	}
	smbios_test_verify_table(hdl);
	smbios_close(hdl);
	smbios_test_table_fini(table);

	return (0);
}
