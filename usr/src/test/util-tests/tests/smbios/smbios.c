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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Primordial SMBIOS test suite. At the moment, the purpose of this is just to
 * test the recent SMBIOS 3.2 additions specific to the variable length slots.
 * This should be evolved into a much fuller test suite.
 */

#include <umem.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include "smbios_test.h"

static int test_dirfd = -1;

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

smbios_test_table_t *
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

void
smbios_test_table_append_raw(smbios_test_table_t *table, const void *buf,
    size_t len)
{
	(void) smbios_test_table_append_common(table, buf, len);
}

void
smbios_test_table_append_string(smbios_test_table_t *table, const char *str)
{
	size_t len = strlen(str) + 1;
	(void) smbios_test_table_append_common(table, str, len);
}

void
smbios_test_table_str_fini(smbios_test_table_t *table)
{
	const uint8_t endstring = 0;

	smbios_test_table_append_raw(table, &endstring, sizeof (endstring));
}

uint16_t
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

void
smbios_test_table_append_eot(smbios_test_table_t *table)
{
	smb_header_t eot;
	uint8_t endstring = 0;

	bzero(&eot, sizeof (eot));
	eot.smbh_type = SMB_TYPE_EOT;
	eot.smbh_len = 4;
	(void) smbios_test_table_append(table, &eot, sizeof (eot));
	(void) smbios_test_table_append_raw(table, &endstring,
	    sizeof (endstring));
	smbios_test_table_append_raw(table, &endstring,
	    sizeof (endstring));
	smbios_test_table_append_raw(table, &endstring,
	    sizeof (endstring));

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

static const smbios_test_t smbios_tests[] = {
	{
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = 0xffff,
	    .st_mktable = smbios_test_badvers_mktable,
	    .st_desc = "bad library version"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = 0,
	    .st_mktable = smbios_test_badvers_mktable,
	    .st_desc = "bad library version (zeros)"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_slot_mktable,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_verify_badids,
	    .st_desc = "smbios_info_* with bad id"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_slot_mktable,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_verify_strings,
	    .st_desc = "smbios string functions"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_32,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_slot_mktable,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_slot_verify,
	    .st_desc = "slot 3.2"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_34,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_slot_mktable_34_nopeers,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_slot_verify_34_nopeers,
	    .st_desc = "slot 3.4 without peers"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_34,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_slot_mktable_34_peers,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_slot_verify_34_peers,
	    .st_desc = "slot 3.4 with peers"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_35,
	    .st_libvers = SMB_VERSION_34,
	    .st_mktable = smbios_test_slot_mktable_35,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_slot_verify_34_overrun,
	    .st_desc = "slot 3.5 against 3.4 lib"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_35,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_slot_mktable_35,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_slot_verify_35,
	    .st_desc = "slot 3.5"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_32,
	    .st_libvers = SMB_VERSION_32,
	    .st_mktable = smbios_test_memdevice_mktable_32,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_memdevice_verify_32,
	    .st_desc = "memory device 3.2 % 3.2"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_32,
	    .st_libvers = SMB_VERSION_33,
	    .st_mktable = smbios_test_memdevice_mktable_32,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_memdevice_verify_32_33,
	    .st_desc = "memory device 3.2 % 3.3"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_32,
	    .st_libvers = SMB_VERSION_37,
	    .st_mktable = smbios_test_memdevice_mktable_32,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_memdevice_verify_32_37,
	    .st_desc = "memory device 3.2 % 3.7"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_33,
	    .st_libvers = SMB_VERSION_33,
	    .st_mktable = smbios_test_memdevice_mktable_33,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_memdevice_verify_33,
	    .st_desc = "memory device 3.3"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_33,
	    .st_libvers = SMB_VERSION_33,
	    .st_mktable = smbios_test_memdevice_mktable_33ext,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_memdevice_verify_33ext,
	    .st_desc = "memory device 3.3 with extended data"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_37,
	    .st_libvers = SMB_VERSION_37,
	    .st_mktable = smbios_test_memdevice_mktable_37,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_memdevice_verify_37,
	    .st_desc = "memory device 3.7"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_pinfo_mktable_amd64,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_pinfo_verify_amd64,
	    .st_desc = "processor additional information - amd64"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_pinfo_mktable_riscv,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_pinfo_verify_riscv,
	    .st_desc = "processor additional information - riscv"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_pinfo_mktable_invlen1,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_pinfo_verify_invlen1,
	    .st_desc = "processor additional information - bad table length 1"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_pinfo_mktable_invlen2,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_pinfo_verify_invlen2,
	    .st_desc = "processor additional information - bad table length 2"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_pinfo_mktable_invlen3,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_pinfo_verify_invlen3,
	    .st_desc = "processor additional information - bad table length 3"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_pinfo_mktable_invlen4,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_pinfo_verify_invlen4,
	    .st_desc = "processor additional information - bad table length 4"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_memdevice_mktable_32,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_pinfo_verify_badtype,
	    .st_desc = "processor additional information - bad type"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_strprop_mktable_invlen1,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_strprop_verify_invlen1,
	    .st_desc = "string property - bad table length 1"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_strprop_mktable_invlen2,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_strprop_verify_invlen2,
	    .st_desc = "string property - bad table length 2"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_memdevice_mktable_32,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_strprop_verify_badtype,
	    .st_desc = "string property - bad type"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_strprop_mktable_basic,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_strprop_verify_basic,
	    .st_desc = "string property - basic"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_strprop_mktable_badstr,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_strprop_verify_badstr,
	    .st_desc = "string property - bad string"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_fwinfo_mktable_invlen_base,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_fwinfo_verify_invlen_base,
	    .st_desc = "firmware inventory - bad base length"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_fwinfo_mktable_invlen_comps,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_fwinfo_verify_invlen_comps,
	    .st_desc = "firmware inventory - bad comp length"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_memdevice_mktable_32,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_fwinfo_verify_badtype,
	    .st_desc = "firmware inventory - bad type"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_fwinfo_mktable_nocomps,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_fwinfo_verify_nocomps,
	    .st_desc = "firmware inventory - no components"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_fwinfo_mktable_comps,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_fwinfo_verify_comps,
	    .st_desc = "firmware inventory - components"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_24,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_chassis_mktable_invlen_base,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_chassis_verify_invlen,
	    .st_desc = "chassis - bad length (2.4 table)"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_chassis_mktable_invlen_base,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_chassis_verify_invlen,
	    .st_desc = "chassis - bad length (latest version)"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_chassis_mktable_base,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_chassis_verify_invlen,
	    .st_desc = "chassis - bad length, expect sku"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_24,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_chassis_mktable_base,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_chassis_verify_base,
	    .st_desc = "chassis - basic 2.4 version"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_chassis_mktable_sku_nocomps,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_chassis_verify_sku_nocomps,
	    .st_desc = "chassis - sku, but no components"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_24,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_chassis_mktable_comps,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_chassis_verify_comps,
	    .st_desc = "chassis - 2.4 version with comps"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_chassis_mktable_sku_nocomps,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_chassis_verify_sku_nocomps,
	    .st_desc = "chassis - sku + comps"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_25,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_proc_mktable_25,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_proc_verify_25,
	    .st_desc = "SMBIOS 2.5 processor"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_36,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_proc_mktable_36,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_proc_verify_36,
	    .st_desc = "SMBIOS 3.6 processor"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_36,
	    .st_libvers = SMB_VERSION_25,
	    .st_mktable = smbios_test_proc_mktable_36,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_proc_verify_36_25,
	    .st_desc = "SMBIOS 3.6 processor, 2.5 client"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_extmem_mktable_cs,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_extmem_verify_cs,
	    .st_desc = "SMBIOS Sun extended memory device with cs"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_extmem_mktable_nocs,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_extmem_verify_nocs,
	    .st_desc = "SMBIOS Sun extended memory device with no cs"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_extmem_mktable_invlen_cs,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_extmem_verify_invlen_cs,
	    .st_desc = "SMBIOS Sun extended memory device invalid cs length"
	}
};

static boolean_t
smbios_test_run_one(const smbios_test_t *test)
{
	smbios_test_table_t *table = NULL;
	smbios_hdl_t *hdl = NULL;
	void *buf;
	size_t len;
	smbios_entry_t *entry;
	int err = 0;
	boolean_t ret = B_FALSE;

	table = smbios_test_table_init(test->st_entry, test->st_tvers);
	if (!test->st_mktable(table)) {
		goto out;
	}

	smbios_test_table_snapshot(table, &entry, &buf, &len);
	hdl = smbios_bufopen(entry, buf, len, test->st_libvers, SMB_FL_DEBUG,
	    &err);
	if (test->st_canopen) {
		if (hdl == NULL) {
			warnx("failed to create table for test %s: %s",
			    test->st_desc, smbios_errmsg(err));
			goto out;
		}
	} else {
		if (hdl != NULL) {
			warnx("accidentally created table for test %s, "
			    "expected failure", test->st_desc);
		} else {
			ret = B_TRUE;
		}
		goto out;
	}

	if (test->st_verify(hdl)) {
		ret = B_TRUE;
	}

	if (hdl != NULL && test_dirfd > -1) {
		int fd;
		char fname[PATH_MAX];

		(void) snprintf(fname, sizeof (fname), "%s.smbios",
		    test->st_desc);
		fd = openat(test_dirfd, fname, O_RDWR | O_CREAT, 0644);
		if (fd < 0) {
			warn("failed to dump test %s, failed to open output "
			    "file", test->st_desc);
		} else {
			if (smbios_write(hdl, fd) != 0) {
				warnx("failed to dump test %s: %s",
				    test->st_desc,
				    smbios_errmsg(smbios_errno(hdl)));
			} else {
				(void) close(fd);
			}
		}
	}
out:
	if (hdl != NULL) {
		smbios_close(hdl);
	}

	if (table != NULL) {
		smbios_test_table_fini(table);
	}

	if (ret) {
		(void) printf("TEST PASSED: %s\n", test->st_desc);
	} else {
		(void) printf("TEST FAILED: %s\n", test->st_desc);
	}

	return (ret);
}

int
main(int argc, char *argv[])
{
	int ret = 0, c;
	size_t i;
	const char *outdir = NULL;

	while ((c = getopt(argc, argv, ":d:")) != -1) {
		switch (c) {
		case 'd':
			outdir = optarg;
			break;
		case '?':
			errx(EXIT_FAILURE, "unknown option: -%c", optopt);
		case ':':
			errx(EXIT_FAILURE, "-%c requires an operand", optopt);
		}
	}

	if (outdir != NULL) {
		if ((test_dirfd = open(outdir, O_RDONLY)) < 0) {
			err(EXIT_FAILURE, "failed to open %s", outdir);
		}
	}

	for (i = 0; i < ARRAY_SIZE(smbios_tests); i++) {
		if (!smbios_test_run_one(&smbios_tests[i])) {
			ret = 1;
		}
	}

	if (ret == 0) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
