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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * SMBIOS processor tests. We build three main processors:
 *
 *   1. An early SMBIOS one based on 2.5 that has the initial core count and
 *     related. A modern client should see the current values.
 *   2. One based on SMBIOS 3.6 that has different values for the processor
 *     counts to verify we use the newer fields both for cores counts and also
 *     the processor family. Most of those were 3.x based. We use 3.6 so we can
 *     get the newer threads enabled field. A pre-3.x client should not see the
 *     same core values as something 3.0+.
 *   3. One based on SMBIOS 3.8 that has the a socket type string listed.
 */

#include <stdlib.h>
#include "smbios_test.h"

/*
 * Older revisions lengths per the SMBIOS spec.
 */
#define	SMBIOS_PROC_LEN_25	0x28
#define	SMBIOS_PROC_LEN_36	0x33

static const char *smbios_proc_sock = "Gideon";
static const char *smbios_proc_mfg = "Harrow";
static const char *smbios_proc_vers = "Nona";
static const char *smbios_proc_serial = "Alecto";
static const char *smbios_proc_asset = "Matthias";
static const char *smbios_proc_pn = "Ortus";
static const char *smbios_proc_st = "Soul";
static const uint64_t smbios_proc_cpuid = 0x09099090;

/*
 * Construct a processor that we'll use throughout our tests. This fills in most
 * of the fields. Some bits may override it and others will only copy a smaller
 * length.
 */
static void
smbios_test_proc_fill(smb_processor_t *proc)
{
	proc->smbpr_hdr.smbh_type = SMB_TYPE_PROCESSOR;
	proc->smbpr_hdr.smbh_len = sizeof (smb_processor_t);
	proc->smbpr_socket = 1;
	proc->smbpr_type = SMB_PRT_CENTRAL;
	proc->smbpr_family = SMB_PRF_HOBBIT;
	proc->smbpr_manufacturer = 2;
	proc->smbpr_cpuid = htole64(smbios_proc_cpuid);
	proc->smbpr_version = 3;
	proc->smbpr_voltage = 0x8b;
	proc->smbpr_clkspeed = htole16(0x1234);
	proc->smbpr_maxspeed = htole16(0x5678);
	proc->smbpr_curspeed = htole16(0x3210);
	proc->smbpr_status = SMB_PRS_ENABLED | 0x40;
	proc->smbpr_upgrade = SMB_PRU_SP3;
	proc->smbpr_l1cache = htole16(0x11ca);
	proc->smbpr_l2cache = htole16(0x12ca);
	proc->smbpr_l3cache = htole16(0x13ca);
	proc->smbpr_serial = 4;
	proc->smbpr_asset = 5;
	proc->smbpr_part = 6;
	proc->smbpr_corecount = 0x77;
	proc->smbpr_coresenabled = 0x3;
	proc->smbpr_threadcount = 0x19;
	proc->smbpr_cflags = htole16(SMB_PRC_64BIT | SMB_PRC_NX);
	proc->smbpr_family2 = htole16(0);
	proc->smbpr_corecount2 = htole16(0);
	proc->smbpr_coresenabled2 = htole16(0);
	proc->smbpr_threadcount2 = htole16(0);
	proc->smbpr_threaden = htole16(11);
}

boolean_t
smbios_test_proc_mktable_25(smbios_test_table_t *table)
{
	smb_processor_t proc;

	smbios_test_proc_fill(&proc);
	proc.smbpr_hdr.smbh_len = SMBIOS_PROC_LEN_25;
	(void) smbios_test_table_append(table, &proc, SMBIOS_PROC_LEN_25);
	smbios_test_table_append_string(table, smbios_proc_sock);
	smbios_test_table_append_string(table, smbios_proc_mfg);
	smbios_test_table_append_string(table, smbios_proc_vers);
	smbios_test_table_append_string(table, smbios_proc_serial);
	smbios_test_table_append_string(table, smbios_proc_asset);
	smbios_test_table_append_string(table, smbios_proc_pn);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

/*
 * This is a 3.0 based table. The biggest difference here is that this table
 * fills in the values that allows us to use family 2, core count 2, etc.
 * fields.
 */
boolean_t
smbios_test_proc_mktable_36(smbios_test_table_t *table)
{
	smb_processor_t proc;

	smbios_test_proc_fill(&proc);
	proc.smbpr_hdr.smbh_len = sizeof (smb_processor_t);
	proc.smbpr_family = 0xfe;
	proc.smbpr_family2 = htole16(SMB_PRF_RV64);
	proc.smbpr_corecount = 0xff;
	proc.smbpr_corecount2 = htole16(0x171);
	proc.smbpr_coresenabled = 0xff;
	proc.smbpr_coresenabled2 = htole16(0x717);
	proc.smbpr_threadcount = 0xff;
	proc.smbpr_threadcount2 = htole16(0x5445);
	proc.smbpr_threaden = htole16(0x2232);
	(void) smbios_test_table_append(table, &proc, SMBIOS_PROC_LEN_36);
	smbios_test_table_append_string(table, smbios_proc_sock);
	smbios_test_table_append_string(table, smbios_proc_mfg);
	smbios_test_table_append_string(table, smbios_proc_vers);
	smbios_test_table_append_string(table, smbios_proc_serial);
	smbios_test_table_append_string(table, smbios_proc_asset);
	smbios_test_table_append_string(table, smbios_proc_pn);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

/*
 * This is basically the 3.6 table, but we also fill in the socket type string.
 */
boolean_t
smbios_test_proc_mktable_38(smbios_test_table_t *table)
{
	smb_processor_t proc;

	smbios_test_proc_fill(&proc);
	proc.smbpr_hdr.smbh_len = sizeof (smb_processor_t);
	proc.smbpr_family = 0xfe;
	proc.smbpr_family2 = htole16(SMB_PRF_RV64);
	proc.smbpr_corecount = 0xff;
	proc.smbpr_corecount2 = htole16(0x171);
	proc.smbpr_coresenabled = 0xff;
	proc.smbpr_coresenabled2 = htole16(0x717);
	proc.smbpr_threadcount = 0xff;
	proc.smbpr_threadcount2 = htole16(0x5445);
	proc.smbpr_threaden = htole16(0x2232);
	proc.smbpr_socktype = 7;
	(void) smbios_test_table_append(table, &proc, sizeof (smb_processor_t));
	smbios_test_table_append_string(table, smbios_proc_sock);
	smbios_test_table_append_string(table, smbios_proc_mfg);
	smbios_test_table_append_string(table, smbios_proc_vers);
	smbios_test_table_append_string(table, smbios_proc_serial);
	smbios_test_table_append_string(table, smbios_proc_asset);
	smbios_test_table_append_string(table, smbios_proc_pn);
	smbios_test_table_append_string(table, smbios_proc_st);
	smbios_test_table_str_fini(table);
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

/*
 * Verify common fields that'll be true across all tests. Verifying core,
 * thread, and related is left to higher level logic as those are changed up
 * between tests to cover the extensions.
 */
static boolean_t
smbios_test_proc_verify_common(smbios_hdl_t *hdl, smbios_struct_t *sp,
    smbios_processor_t *proc)
{
	boolean_t ret = B_TRUE;
	smbios_info_t info;

	if (proc->smbp_cpuid != smbios_proc_cpuid) {
		warnx("processor state mismatch, found unexpected cpuid: 0x%"
		    PRIx64, proc->smbp_cpuid);
		ret = B_FALSE;
	}

	if (SMB_PRV_LEGACY(proc->smbp_voltage)) {
		warnx("processor state mismatch, found legacy foltage: 0x%x",
		    proc->smbp_voltage);
		ret = B_FALSE;
	}

	if (SMB_PRV_VOLTAGE(proc->smbp_voltage) != 0xb) {
		warnx("processor state mismatch, found legacy foltage: 0x%x",
		    SMB_PRV_VOLTAGE(proc->smbp_voltage));
		ret = B_FALSE;
	}

	if (proc->smbp_status != (SMB_PRS_ENABLED | 0x40)) {
		warnx("processor state mismatch, found unexpected processor "
		    "status: 0x%x", proc->smbp_status);
		ret = B_FALSE;
	}

	if (proc->smbp_upgrade != SMB_PRU_SP3) {
		warnx("processor state mismatch, found unexpected processor "
		    "socket: 0x%x", proc->smbp_upgrade);
		ret = B_FALSE;
	}

	if (proc->smbp_clkspeed != 0x1234) {
		warnx("processor state mismatch, found unexpected clock speed: "
		    "0x%x", proc->smbp_clkspeed);
		ret = B_FALSE;
	}

	if (proc->smbp_maxspeed != 0x5678) {
		warnx("processor state mismatch, found unexpected max speed: "
		    "0x%x", proc->smbp_maxspeed);
		ret = B_FALSE;
	}

	if (proc->smbp_curspeed != 0x3210) {
		warnx("processor state mismatch, found unexpected current "
		    "speed: 0x%x", proc->smbp_curspeed);
		ret = B_FALSE;
	}


	if (proc->smbp_l1cache != 0x11ca) {
		warnx("processor state mismatch, found unexpected l1 cache id: "
		    "0x%" _PRIxID, proc->smbp_l1cache);
		ret = B_FALSE;
	}


	if (proc->smbp_l2cache != 0x12ca) {
		warnx("processor state mismatch, found unexpected l2 cache id: "
		    "0x%" _PRIxID, proc->smbp_l2cache);
		ret = B_FALSE;
	}

	if (proc->smbp_l3cache != 0x13ca) {
		warnx("processor state mismatch, found unexpected l3 cache id: "
		    "0x%" _PRIxID, proc->smbp_l3cache);
		ret = B_FALSE;
	}

	if (proc->smbp_cflags != (SMB_PRC_64BIT | SMB_PRC_NX)) {
		warnx("processor state mismatch, found unexpected "
		    "characteristic flags: 0x%x", proc->smbp_cflags);
		ret = B_FALSE;
	}

	if (smbios_info_common(hdl, sp->smbstr_id, &info) != 0) {
		warnx("failed to get common chassis info: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (strcmp(info.smbi_manufacturer, smbios_proc_mfg) != 0) {
		warnx("processor state mismatch, found unexpected mfg: %s",
		    info.smbi_manufacturer);
		ret = B_FALSE;
	}


	if (strcmp(info.smbi_version, smbios_proc_vers) != 0) {
		warnx("processor state mismatch, found unexpected vers: %s",
		    info.smbi_version);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_serial, smbios_proc_serial) != 0) {
		warnx("processor state mismatch, found unexpected serial: %s",
		    info.smbi_serial);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_asset, smbios_proc_asset) != 0) {
		warnx("processor state mismatch, found unexpected asset: %s",
		    info.smbi_asset);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_location, smbios_proc_sock) != 0) {
		warnx("processor state mismatch, found unexpected sock: %s",
		    info.smbi_location);
		ret = B_FALSE;
	}

	if (strcmp(info.smbi_part, smbios_proc_pn) != 0) {
		warnx("processor state mismatch, found unexpected pn: %s",
		    info.smbi_part);
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_proc_verify_25(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;
	smbios_struct_t sp;
	smbios_processor_t proc;

	if (smbios_lookup_type(hdl, SMB_TYPE_PROCESSOR, &sp) == -1) {
		warnx("failed to lookup SMBIOS processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_processor(hdl, sp.smbstr_id, &proc) == -1) {
		warnx("failed to get processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_proc_verify_common(hdl, &sp, &proc)) {
		ret = B_FALSE;
	}

	if (proc.smbp_family != SMB_PRF_HOBBIT) {
		warnx("processor state mismatch, found unexpected family: 0x%x",
		    proc.smbp_family);
		ret = B_FALSE;
	}

	if (proc.smbp_corecount != 0x77) {
		warnx("processor state mismatch, found unexpected core count: "
		    "0x%x",  proc.smbp_corecount);
		ret = B_FALSE;
	}

	if (proc.smbp_coresenabled != 0x3) {
		warnx("processor state mismatch, found unexpected cores "
		    "enabled count: 0x%x",  proc.smbp_coresenabled);
		ret = B_FALSE;
	}

	if (proc.smbp_threadcount != 0x19) {
		warnx("processor state mismatch, found unexpected thread "
		    "count: 0x%x",  proc.smbp_threadcount);
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * This verifies that the 3.6 based table with a 3.0+ client always sees the
 * values from the uint16_t extension values.
 */
boolean_t
smbios_test_proc_verify_36(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;
	smbios_struct_t sp;
	smbios_processor_t proc;

	if (smbios_lookup_type(hdl, SMB_TYPE_PROCESSOR, &sp) == -1) {
		warnx("failed to lookup SMBIOS processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_processor(hdl, sp.smbstr_id, &proc) == -1) {
		warnx("failed to get processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_proc_verify_common(hdl, &sp, &proc)) {
		ret = B_FALSE;
	}

	if (proc.smbp_family != SMB_PRF_RV64) {
		warnx("processor state mismatch, found unexpected family: 0x%x",
		    proc.smbp_family);
		ret = B_FALSE;
	}

	if (proc.smbp_corecount != 0x171) {
		warnx("processor state mismatch, found unexpected core count: "
		    "0x%x",  proc.smbp_corecount);
		ret = B_FALSE;
	}

	if (proc.smbp_coresenabled != 0x717) {
		warnx("processor state mismatch, found unexpected cores "
		    "enabled count: 0x%x",  proc.smbp_coresenabled);
		ret = B_FALSE;
	}

	if (proc.smbp_threadcount != 0x5445) {
		warnx("processor state mismatch, found unexpected thread "
		    "count: 0x%x",  proc.smbp_threadcount);
		ret = B_FALSE;
	}

	if (proc.smbp_threadsenabled != 0x2232) {
		warnx("processor state mismatch, found unexpected thread "
		    "enabled coun: 0x%x",  proc.smbp_threadsenabled);
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * This verifies that when a 2.5 based client uses a 3.x based table, we don't
 * know about the second flags and instead seed data just based off of the
 * original field with reserved and all.
 */
boolean_t
smbios_test_proc_verify_36_25(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;
	smbios_struct_t sp;
	smbios_processor_t proc;

	if (smbios_lookup_type(hdl, SMB_TYPE_PROCESSOR, &sp) == -1) {
		warnx("failed to lookup SMBIOS processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_processor(hdl, sp.smbstr_id, &proc) == -1) {
		warnx("failed to get processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_proc_verify_common(hdl, &sp, &proc)) {
		ret = B_FALSE;
	}

	if (proc.smbp_family != 0xfe) {
		warnx("processor state mismatch, found unexpected family: 0x%x",
		    proc.smbp_family);
		ret = B_FALSE;
	}

	if (proc.smbp_corecount != 0xff) {
		warnx("processor state mismatch, found unexpected core count: "
		    "0x%x",  proc.smbp_corecount);
		ret = B_FALSE;
	}

	if (proc.smbp_coresenabled != 0xff) {
		warnx("processor state mismatch, found unexpected cores "
		    "enabled count: 0x%x",  proc.smbp_coresenabled);
		ret = B_FALSE;
	}

	if (proc.smbp_threadcount != 0xff) {
		warnx("processor state mismatch, found unexpected thread "
		    "count: 0x%x",  proc.smbp_threadcount);
		ret = B_FALSE;
	}

	return (ret);
}


boolean_t
smbios_test_proc_verify_38(smbios_hdl_t *hdl)
{
	boolean_t ret = B_TRUE;
	smbios_struct_t sp;
	smbios_processor_t proc;

	if (smbios_lookup_type(hdl, SMB_TYPE_PROCESSOR, &sp) == -1) {
		warnx("failed to lookup SMBIOS processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_processor(hdl, sp.smbstr_id, &proc) == -1) {
		warnx("failed to get processor: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!smbios_test_proc_verify_36(hdl)) {
		ret = B_FALSE;
	}

	if (proc.smbp_socktype == NULL) {
		warnx("processor state mismatch: found NULL socket type");
		ret = B_FALSE;
	} else if (strcmp(proc.smbp_socktype, smbios_proc_st) != 0) {
		warnx("processor state mismatch: found unexpected socket type: "
		    "%s", proc.smbp_socktype);
		ret = B_FALSE;
	}

	return (ret);
}
