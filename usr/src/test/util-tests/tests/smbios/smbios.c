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

#include <umem.h>
#include "smbios_test.h"

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
	    .st_tvers = SMB_VERSION_32,
	    .st_libvers = SMB_VERSION,
	    .st_mktable = smbios_test_slot_mktable,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_slot_verify,
	    .st_desc = "slot tests"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION,
	    .st_libvers = 0xffff,
	    .st_mktable = smbios_test_badvers_mktable,
	    .st_desc = "bad library version"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_32,
	    .st_libvers = SMB_VERSION_32,
	    .st_mktable = smbios_test_memdevice_mktable_32,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_memdevice_verify_32,
	    .st_desc = "memory device 3.2 / 3.2"
	}, {
	    .st_entry = SMBIOS_ENTRY_POINT_30,
	    .st_tvers = SMB_VERSION_32,
	    .st_libvers = SMB_VERSION_33,
	    .st_mktable = smbios_test_memdevice_mktable_32,
	    .st_canopen = B_TRUE,
	    .st_verify = smbios_test_memdevice_verify_32_33,
	    .st_desc = "memory device 3.2 / 3.3"
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
	    .st_desc = "memory device 3.3"
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
	},

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
main(void)
{
	int err = 0;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(smbios_tests); i++) {
		if (!smbios_test_run_one(&smbios_tests[i])) {
			err = 1;
		}
	}

	return (err);
}
