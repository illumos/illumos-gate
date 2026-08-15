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
 * Tests for Sun OEM Extended Processor, Type 132.
 */

#include "smbios_test.h"

static uint16_t proc_hdl = 0x1234;
static uint8_t proc_fru = 0x23;
static uint16_t proc_apicid[] = { 0x23, 0x42, 0x169, 0x7777, UINT16_MAX };

boolean_t
smbios_test_extproc_mktable_short(smbios_test_table_t *table)
{
	smb_header_t hdr;

	smbios_test_table_add_sunoem(table);

	hdr.smbh_type = SUN_OEM_EXT_PROCESSOR;
	hdr.smbh_len = sizeof (hdr);

	(void) smbios_test_table_append(table, &hdr, sizeof (hdr));
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_extproc_mktable_noapic(smbios_test_table_t *table)
{
	smb_processor_ext_t proc;

	smbios_test_table_add_sunoem(table);

	proc.smbpre_hdr.smbh_type = SUN_OEM_EXT_PROCESSOR;
	proc.smbpre_hdr.smbh_len = sizeof (proc);

	proc.smbpre_processor = proc_hdl;
	proc.smbpre_fru = proc_fru;
	proc.smbpre_n = 0;
	(void) smbios_test_table_append(table, &proc, sizeof (proc));
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_extproc_mktable_short_apic(smbios_test_table_t *table)
{
	smb_processor_ext_t proc;

	smbios_test_table_add_sunoem(table);

	proc.smbpre_hdr.smbh_type = SUN_OEM_EXT_PROCESSOR;
	proc.smbpre_hdr.smbh_len = sizeof (proc);

	proc.smbpre_processor = proc_hdl;
	proc.smbpre_fru = proc_fru;
	proc.smbpre_n = ARRAY_SIZE(proc_apicid);
	(void) smbios_test_table_append(table, &proc, sizeof (proc));
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_extproc_mktable_apic(smbios_test_table_t *table)
{
	smb_processor_ext_t proc;

	smbios_test_table_add_sunoem(table);

	proc.smbpre_hdr.smbh_type = SUN_OEM_EXT_PROCESSOR;
	proc.smbpre_hdr.smbh_len = sizeof (proc) + sizeof (proc_apicid);

	proc.smbpre_processor = proc_hdl;
	proc.smbpre_fru = proc_fru;
	proc.smbpre_n = ARRAY_SIZE(proc_apicid);
	(void) smbios_test_table_append(table, &proc, sizeof (proc));
	smbios_test_table_append_raw(table, proc_apicid, sizeof (proc_apicid));
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}

boolean_t
smbios_test_extproc_verify_short(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_processor_ext_t proc;

	if (smbios_lookup_type(hdl, SUN_OEM_EXT_PROCESSOR, &sp) == -1) {
		warnx("failed to lookup SMBIOS Sun OEM processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_extprocessor(hdl, sp.smbstr_id, &proc) != -1) {
		warnx("accidentally parsed invalid extended processor as "
		    "valid");
		return (B_FALSE);
	}

	if (smbios_errno(hdl) != ESMB_SHORT) {
		warnx("encountered wrong error for extended processor, "
		    "expected: 0x%x, found: 0x%x", ESMB_SHORT,
		    smbios_errno(hdl));
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
smbios_test_extproc_verify_common(smbios_hdl_t *hdl, const uint16_t *apics,
    size_t napics)
{
	smbios_processor_ext_t proc;
	boolean_t ret = B_TRUE;
	smbios_struct_t sp;

	if (smbios_lookup_type(hdl, SUN_OEM_EXT_PROCESSOR, &sp) == -1) {
		warnx("failed to lookup SMBIOS Sun OEM processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_extprocessor(hdl, sp.smbstr_id, &proc) == -1) {
		warnx("failed to get extended processor information: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (proc.smbpe_processor != proc_hdl) {
		warnx("encountered wrong proc handle 0x%x, expected 0x%x",
		    proc.smbpe_processor, proc_hdl);
		ret = B_FALSE;
	}

	if (proc.smbpe_fru != proc_fru) {
		warnx("encountered wrong proc fru 0x%x, expected 0x%x",
		    proc.smbpe_fru, proc_fru);
		ret = B_FALSE;
	}

	if (proc.smbpe_n != napics) {
		warnx("encountered wrong apic id count 0x%x, expected 0x%zx",
		    proc.smbpe_n, napics);
		ret = B_FALSE;
	}

	if (napics > 0 && proc.smbpe_apicid == NULL) {
		warnx("expected 0x%zx apic ids, but found NULL APIC pointer",
		    napics);
		ret = B_FALSE;
	} else if (napics == 0 && proc.smbpe_apicid != NULL) {
		warnx("found non-NULL APIC pointer, but expected no APIC ids");
		ret = B_FALSE;
	}

	if (napics > 0 && proc.smbpe_n == napics && proc.smbpe_apicid != NULL) {
		for (size_t i = 0; i < napics; i++) {
			if (proc.smbpe_apicid[i] != apics[i]) {
				warnx("APIC ID %zu mismatch: found 0x%x, "
				    "expected 0x%x", i, proc.smbpe_apicid[i],
				    apics[i]);
				ret = B_FALSE;
			}
		}
	}

	return (ret);
}

boolean_t
smbios_test_extproc_verify_noapic(smbios_hdl_t *hdl)
{
	return (smbios_test_extproc_verify_common(hdl, NULL, 0));
}

boolean_t
smbios_test_extproc_verify_apic(smbios_hdl_t *hdl)
{
	return (smbios_test_extproc_verify_common(hdl, proc_apicid,
	    ARRAY_SIZE(proc_apicid)));
}
