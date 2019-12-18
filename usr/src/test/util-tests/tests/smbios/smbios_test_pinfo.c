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
 * Tests for SMBIOS type 44 - SMB_TYPE_PROCESSOR_INFO and the per-CPU type
 * follow ups.
 */

#include "smbios_test.h"

static uint16_t smbios_pinfo_phandle = 0x1;
static uint64_t smbios_pinfo_isa = 0x4010d;
static uint8_t smbios_pinfo_hartid[16];
static uint8_t smbios_pinfo_vendid[16];
static uint8_t smbios_pinfo_archid[16];
static uint8_t smbios_pinfo_machid[16];
static uint8_t smbios_pinfo_metdi[16];
static uint8_t smbios_pinfo_mitdi[16];

boolean_t
smbios_test_pinfo_mktable_amd64(smbios_test_table_t *table)
{
	smb_processor_info_t pi;

	pi.smbpai_hdr.smbh_type = SMB_TYPE_PROCESSOR_INFO;
	pi.smbpai_hdr.smbh_len = sizeof (smb_processor_info_t);
	pi.smbpai_proc = htole16(smbios_pinfo_phandle);
	pi.smbpai_len = 0;
	pi.smbpai_type = SMB_PROCINFO_T_AMD64;

	(void) smbios_test_table_append(table, &pi, sizeof (pi));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

boolean_t
smbios_test_pinfo_verify_amd64(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_processor_info_t pinfo;
	smbios_processor_info_riscv_t rv;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_PROCESSOR_INFO, &sp) == -1) {
		warnx("failed to lookup SMBIOS processor additional "
		    "information: %s", smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_processor_info(hdl, sp.smbstr_id, &pinfo) != 0) {

		warnx("failed to get SMBIOS processor additional "
		    "information: %s", smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (pinfo.smbpi_processor != smbios_pinfo_phandle) {
		warnx("processor handle incorrect, found 0x%x",
		    pinfo.smbpi_processor);
		ret = B_FALSE;
	}

	if (pinfo.smbpi_ptype != SMB_PROCINFO_T_AMD64) {
		warnx("processor type incorrect, found 0x%x",
		    pinfo.smbpi_ptype);
		ret = B_FALSE;
	}

	if (strcmp(smbios_processor_info_type_desc(pinfo.smbpi_ptype),
	    "X64 (x86-64, Intel64, AMD64, EMT64)") != 0) {
		warnx("processor type incorrect, found %s",
		    smbios_processor_info_type_desc(pinfo.smbpi_ptype));
		ret = B_FALSE;
	}

	if (smbios_info_processor_riscv(hdl, sp.smbstr_id, &rv) != -1) {
		warnx("accidentally got riscv info on non-riscv handle");
		ret = B_FALSE;
	}

	if (smbios_errno(hdl) != ESMB_TYPE) {
		warnx("encountered wrong errno for RISC-V info, found: 0x%x",
		    smbios_errno(hdl));
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_pinfo_mktable_riscv(smbios_test_table_t *table)
{
	smb_processor_info_t pi;
	smb_processor_info_riscv_t rv;

	pi.smbpai_hdr.smbh_type = SMB_TYPE_PROCESSOR_INFO;
	pi.smbpai_hdr.smbh_len = sizeof (smb_processor_info_t) +
	    sizeof (smb_processor_info_riscv_t);
	pi.smbpai_proc = htole16(smbios_pinfo_phandle);
	pi.smbpai_len = sizeof (smb_processor_info_riscv_t);
	pi.smbpai_type = SMB_PROCINFO_T_RV64;

	(void) smbios_test_table_append(table, &pi, sizeof (pi));

	rv.smbpairv_vers = 1;
	rv.smbpairv_len = sizeof (smb_processor_info_riscv_t);
	arc4random_buf(smbios_pinfo_hartid, sizeof (smbios_pinfo_hartid));
	bcopy(smbios_pinfo_hartid, rv.smbpairv_hartid,
	    sizeof (smbios_pinfo_hartid));
	rv.smbpairv_boot = 1;
	arc4random_buf(smbios_pinfo_vendid, sizeof (smbios_pinfo_vendid));
	bcopy(smbios_pinfo_vendid, rv.smbpairv_vendid,
	    sizeof (smbios_pinfo_vendid));
	arc4random_buf(smbios_pinfo_archid, sizeof (smbios_pinfo_archid));
	bcopy(smbios_pinfo_archid, rv.smbpairv_archid,
	    sizeof (smbios_pinfo_archid));
	arc4random_buf(smbios_pinfo_machid, sizeof (smbios_pinfo_machid));
	bcopy(smbios_pinfo_machid, rv.smbpairv_machid,
	    sizeof (smbios_pinfo_machid));
	rv.smbpairv_boot = 1;
	rv.smbpairv_isa = htole64(smbios_pinfo_isa);
	rv.smbpairv_privlvl = SMB_RV_PRIV_M | SMB_RV_PRIV_S;
	arc4random_buf(smbios_pinfo_metdi, sizeof (smbios_pinfo_metdi));
	bcopy(smbios_pinfo_metdi, rv.smbpairv_metdi,
	    sizeof (smbios_pinfo_metdi));
	arc4random_buf(smbios_pinfo_mitdi, sizeof (smbios_pinfo_mitdi));
	bcopy(smbios_pinfo_mitdi, rv.smbpairv_mitdi,
	    sizeof (smbios_pinfo_mitdi));
	rv.smbpairv_xlen = SMB_RV_WIDTH_64B;
	rv.smbpairv_mxlen = SMB_RV_WIDTH_64B;
	rv.smbpairv_sxlen = SMB_RV_WIDTH_128B;
	rv.smbpairv_uxlen = SMB_RV_WIDTH_32B;

	smbios_test_table_append_raw(table, &rv, sizeof (rv));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

static void
smbios_test_pinfo_id_mismatch(uint8_t *act, uint8_t *exp)
{
	uint_t i;
	(void) fprintf(stderr, "found:    ");
	for (i = 0; i < 16; i++) {
		(void) fprintf(stderr, " %02x", act[i]);
	}
	(void) fprintf(stderr, "\nexpected: ");
	for (i = 0; i < 16; i++) {
		(void) fprintf(stderr, " %02x", exp[i]);
	}
	(void) fprintf(stderr, "\n");
}

boolean_t
smbios_test_pinfo_verify_riscv(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_processor_info_t pinfo;
	smbios_processor_info_riscv_t rv;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_PROCESSOR_INFO, &sp) == -1) {
		warnx("failed to lookup SMBIOS processor additional "
		    "information: %s", smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_processor_info(hdl, sp.smbstr_id, &pinfo) != 0) {
		warnx("failed to get SMBIOS processor additional "
		    "information: %s", smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (pinfo.smbpi_processor != smbios_pinfo_phandle) {
		warnx("processor handle incorrect, found 0x%x",
		    pinfo.smbpi_processor);
		ret = B_FALSE;
	}

	if (pinfo.smbpi_ptype != SMB_PROCINFO_T_RV64) {
		warnx("processor type incorrect, found 0x%x",
		    pinfo.smbpi_ptype);
		ret = B_FALSE;
	}

	if (strcmp(smbios_processor_info_type_desc(pinfo.smbpi_ptype),
	    "64-bit RISC-V (RV64)") != 0) {
		warnx("processor type incorrect, found %s",
		    smbios_processor_info_type_desc(pinfo.smbpi_ptype));
		ret = B_FALSE;
	}

	if (smbios_info_processor_riscv(hdl, sp.smbstr_id, &rv) != 0) {

		warnx("failed to get SMBIOS processor additional "
		    "information for RISC-V: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (bcmp(rv.smbpirv_hartid, smbios_pinfo_hartid,
	    sizeof (smbios_pinfo_hartid)) != 0) {
		warnx("RISC-V hart id's don't match");
		smbios_test_pinfo_id_mismatch(rv.smbpirv_hartid,
		    smbios_pinfo_hartid);
		ret = B_FALSE;
	}

	if (bcmp(rv.smbpirv_vendid, smbios_pinfo_vendid,
	    sizeof (smbios_pinfo_vendid)) != 0) {
		warnx("RISC-V vend id's don't match");
		smbios_test_pinfo_id_mismatch(rv.smbpirv_vendid,
		    smbios_pinfo_vendid);
		ret = B_FALSE;
	}

	if (bcmp(rv.smbpirv_archid, smbios_pinfo_archid,
	    sizeof (smbios_pinfo_archid)) != 0) {
		warnx("RISC-V arch id's don't match");
		smbios_test_pinfo_id_mismatch(rv.smbpirv_archid,
		    smbios_pinfo_archid);
		ret = B_FALSE;
	}

	if (bcmp(rv.smbpirv_machid, smbios_pinfo_machid,
	    sizeof (smbios_pinfo_machid)) != 0) {
		warnx("RISC-V mach id's don't match");
		smbios_test_pinfo_id_mismatch(rv.smbpirv_machid,
		    smbios_pinfo_machid);
		ret = B_FALSE;
	}

	if (bcmp(rv.smbpirv_metdi, smbios_pinfo_metdi,
	    sizeof (smbios_pinfo_metdi)) != 0) {
		warnx("RISC-V METDI don't match");
		smbios_test_pinfo_id_mismatch(rv.smbpirv_metdi,
		    smbios_pinfo_metdi);
		ret = B_FALSE;
	}

	if (bcmp(rv.smbpirv_mitdi, smbios_pinfo_mitdi,
	    sizeof (smbios_pinfo_mitdi)) != 0) {
		warnx("RISC-V METDI don't match");
		smbios_test_pinfo_id_mismatch(rv.smbpirv_mitdi,
		    smbios_pinfo_mitdi);
		ret = B_FALSE;
	}

	if (rv.smbpirv_isa != smbios_pinfo_isa) {
		warnx("RISC-V ISA mismatch");
		ret = B_FALSE;
	}

	if (rv.smbpirv_privlvl != (SMB_RV_PRIV_M | SMB_RV_PRIV_S)) {
		warnx("RISC-V privilege level mismatch, found: 0x%x",
		    rv.smbpirv_privlvl);
		ret = B_FALSE;
	}

	if (rv.smbpirv_xlen != SMB_RV_WIDTH_64B) {
		warnx("RISC-V xlen mismatch, found: 0x%x", rv.smbpirv_xlen);
		ret = B_FALSE;
	}

	if (rv.smbpirv_mxlen != SMB_RV_WIDTH_64B) {
		warnx("RISC-V mxlen mismatch, found: 0x%x", rv.smbpirv_mxlen);
		ret = B_FALSE;
	}

	if (rv.smbpirv_sxlen != SMB_RV_WIDTH_128B) {
		warnx("RISC-V sxlen mismatch, found: 0x%x", rv.smbpirv_sxlen);
		ret = B_FALSE;
	}

	if (rv.smbpirv_uxlen != SMB_RV_WIDTH_32B) {
		warnx("RISC-V uxlen mismatch, found: 0x%x", rv.smbpirv_uxlen);
		ret = B_FALSE;
	}

	/*
	 * Finally, use this to spot check several of the different RISC-V
	 * strings.
	 */
	if (strcmp(smbios_riscv_priv_desc(SMB_RV_PRIV_M), "Machine Mode") !=
	    0) {
		warnx("SMB_RV_PRIV_M string desc mismatch, found %s",
		    smbios_riscv_priv_desc(SMB_RV_PRIV_M));
		ret = B_FALSE;
	}

	if (strcmp(smbios_riscv_priv_name(SMB_RV_PRIV_U), "SMB_RV_PRIV_U") !=
	    0) {
		warnx("SMB_RV_PRIV_U string name mismatch, found %s",
		    smbios_riscv_priv_name(SMB_RV_PRIV_U));
		ret = B_FALSE;
	}

	if (strcmp(smbios_riscv_width_desc(SMB_RV_WIDTH_64B), "64-bit") !=
	    0) {
		warnx("SMB_RV_WIDTH_64B string desc mismatch, found %s",
		    smbios_riscv_width_desc(SMB_RV_WIDTH_64B));
		ret = B_FALSE;
	}

	if (strcmp(smbios_riscv_width_desc(SMB_RV_WIDTH_128B), "128-bit") !=
	    0) {
		warnx("SMB_RV_WIDTH_128B string desc mismatch, found %s",
		    smbios_riscv_width_desc(SMB_RV_WIDTH_128B));
		ret = B_FALSE;
	}

	if (strcmp(smbios_riscv_isa_desc(SMB_RV_ISA_A), "Atomic") != 0) {
		warnx("SMB_RV_ISA_A string desc mismatch, found %s",
		    smbios_riscv_isa_desc(SMB_RV_ISA_A));
		ret = B_FALSE;
	}

	if (strcmp(smbios_riscv_isa_desc(SMB_RV_ISA_C), "Compressed") != 0) {
		warnx("SMB_RV_ISA_Q string desc mismatch, found %s",
		    smbios_riscv_isa_desc(SMB_RV_ISA_C));
		ret = B_FALSE;
	}

	if (strcmp(smbios_riscv_isa_desc(SMB_RV_ISA_Q),
	    "Quad-precision floating-poit") != 0) {
		warnx("SMB_RV_ISA_Q string desc mismatch, found %s",
		    smbios_riscv_isa_desc(SMB_RV_ISA_Q));
		ret = B_FALSE;
	}

	if (strcmp(smbios_riscv_isa_name(SMB_RV_ISA_A), "SMB_RV_ISA_A") != 0) {
		warnx("SMB_RV_ISA_A string name mismatch, found %s",
		    smbios_riscv_isa_name(SMB_RV_ISA_A));
		ret = B_FALSE;
	}

	if (strcmp(smbios_riscv_isa_name(SMB_RV_ISA_C), "SMB_RV_ISA_C") != 0) {
		warnx("SMB_RV_ISA_Q string name mismatch, found %s",
		    smbios_riscv_isa_name(SMB_RV_ISA_C));
		ret = B_FALSE;
	}

	if (strcmp(smbios_riscv_isa_name(SMB_RV_ISA_Q), "SMB_RV_ISA_Q") != 0) {
		warnx("SMB_RV_ISA_Q string name mismatch, found %s",
		    smbios_riscv_isa_name(SMB_RV_ISA_Q));
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * This shows having an invalid table length.
 */
boolean_t
smbios_test_pinfo_mktable_invlen1(smbios_test_table_t *table)
{
	smb_processor_info_t pi;

	pi.smbpai_hdr.smbh_type = SMB_TYPE_PROCESSOR_INFO;
	pi.smbpai_hdr.smbh_len = 2;
	pi.smbpai_proc = htole16(smbios_pinfo_phandle);
	pi.smbpai_len = 0;
	pi.smbpai_type = SMB_PROCINFO_T_AMD64;

	(void) smbios_test_table_append(table, &pi, sizeof (pi));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

/*
 * This sets the internal length of the additional processor information data to
 * go beyond the length of the basic structure.
 */
boolean_t
smbios_test_pinfo_mktable_invlen2(smbios_test_table_t *table)
{
	smb_processor_info_t pi;
	smb_processor_info_riscv_t rv;

	pi.smbpai_hdr.smbh_type = SMB_TYPE_PROCESSOR_INFO;
	pi.smbpai_hdr.smbh_len = sizeof (smb_processor_info_t);
	pi.smbpai_proc = htole16(smbios_pinfo_phandle);
	pi.smbpai_len = sizeof (smb_processor_info_riscv_t);
	pi.smbpai_type = SMB_PROCINFO_T_RV64;

	(void) smbios_test_table_append(table, &pi, sizeof (pi));

	arc4random_buf(&rv, sizeof (rv));
	rv.smbpairv_vers = 1;
	rv.smbpairv_len = sizeof (smb_processor_info_riscv_t);

	smbios_test_table_append_raw(table, &rv, sizeof (rv));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

/*
 * This verifies that we can detect a header length that doesn't properly
 * contain both the risc-v and base structure.
 */
boolean_t
smbios_test_pinfo_mktable_invlen3(smbios_test_table_t *table)
{
	smb_processor_info_t pi;
	smb_processor_info_riscv_t rv;

	pi.smbpai_hdr.smbh_type = SMB_TYPE_PROCESSOR_INFO;
	pi.smbpai_hdr.smbh_len = sizeof (smb_processor_info_t);
	pi.smbpai_proc = htole16(smbios_pinfo_phandle);
	pi.smbpai_len = 0;
	pi.smbpai_type = SMB_PROCINFO_T_RV64;

	(void) smbios_test_table_append(table, &pi, sizeof (pi));

	arc4random_buf(&rv, sizeof (rv));
	rv.smbpairv_vers = 1;
	rv.smbpairv_len = sizeof (smb_processor_info_riscv_t);

	smbios_test_table_append_raw(table, &rv, sizeof (rv));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}

/*
 * This verifies that we can detect an inner risc-v additional processor
 * information section that declares its size to be beyond the header of the
 * structure.
 */
boolean_t
smbios_test_pinfo_mktable_invlen4(smbios_test_table_t *table)
{
	smb_processor_info_t pi;
	smb_processor_info_riscv_t rv;

	pi.smbpai_hdr.smbh_type = SMB_TYPE_PROCESSOR_INFO;
	pi.smbpai_hdr.smbh_len = sizeof (smb_processor_info_t) +
	    sizeof (smb_processor_info_riscv_t);
	pi.smbpai_proc = htole16(smbios_pinfo_phandle);
	pi.smbpai_len = sizeof (smb_processor_info_riscv_t);
	pi.smbpai_type = SMB_PROCINFO_T_RV64;

	(void) smbios_test_table_append(table, &pi, sizeof (pi));

	arc4random_buf(&rv, sizeof (rv));
	rv.smbpairv_vers = 1;
	rv.smbpairv_len = sizeof (smb_processor_info_riscv_t) * 2;

	smbios_test_table_append_raw(table, &rv, sizeof (rv));
	smbios_test_table_append_eot(table);

	return (B_TRUE);
}
static boolean_t
smbios_test_pinfo_verify_badtable(smbios_hdl_t *hdl, int smberr,
    boolean_t valid_pinfo)
{
	smbios_struct_t sp;
	smbios_processor_info_t pinfo;
	smbios_processor_info_riscv_t rv;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_PROCESSOR_INFO, &sp) == -1) {
		warnx("failed to lookup SMBIOS processor additional "
		    "information: %s", smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (!valid_pinfo) {
		if (smbios_info_processor_info(hdl, sp.smbstr_id, &pinfo) !=
		    -1) {
			warnx("accidentally parsed invalid processor "
			    "additional information as valid");
			ret = B_FALSE;
		}

		if (smbios_errno(hdl) != smberr) {
			warnx("encountered wrong error for processor info, "
			    "found: 0x%x", smbios_errno(hdl));
			ret = B_FALSE;
		}
	} else {
		if (smbios_info_processor_info(hdl, sp.smbstr_id, &pinfo) !=
		    0) {
			warnx("failed to get SMBIOS processor additional "
			    "information: %s",
			    smbios_errmsg(smbios_errno(hdl)));
			ret = B_FALSE;
		}
	}

	if (smbios_info_processor_riscv(hdl, sp.smbstr_id, &rv) != -1) {
		warnx("accidentally got riscv info on invalid handle");
		ret = B_FALSE;
	}

	if (smbios_errno(hdl) != smberr) {
		warnx("encountered wrong error for amd64 info, found: 0x%x",
		    smbios_errno(hdl));
		ret = B_FALSE;
	}

	return (ret);
}

boolean_t
smbios_test_pinfo_verify_invlen1(smbios_hdl_t *hdl)
{
	return (smbios_test_pinfo_verify_badtable(hdl, ESMB_SHORT, B_FALSE));
}

boolean_t
smbios_test_pinfo_verify_invlen2(smbios_hdl_t *hdl)
{
	return (smbios_test_pinfo_verify_badtable(hdl, ESMB_CORRUPT, B_FALSE));
}

boolean_t
smbios_test_pinfo_verify_invlen3(smbios_hdl_t *hdl)
{
	return (smbios_test_pinfo_verify_badtable(hdl, ESMB_SHORT, B_TRUE));
}

boolean_t
smbios_test_pinfo_verify_invlen4(smbios_hdl_t *hdl)
{
	return (smbios_test_pinfo_verify_badtable(hdl, ESMB_CORRUPT, B_TRUE));
}

boolean_t
smbios_test_pinfo_verify_badtype(smbios_hdl_t *hdl)
{
	smbios_struct_t sp;
	smbios_processor_info_t pinfo;
	smbios_processor_info_riscv_t rv;
	boolean_t ret = B_TRUE;

	if (smbios_lookup_type(hdl, SMB_TYPE_MEMDEVICE, &sp) == -1) {
		warnx("failed to lookup SMBIOS memory device information: %s",
		    smbios_errmsg(smbios_errno(hdl)));
		return (B_FALSE);
	}

	if (smbios_info_processor_info(hdl, sp.smbstr_id, &pinfo) != -1) {
		warnx("accidentally parsed invalid processor additional "
		    "information as valid");
		ret = B_FALSE;
	}

	if (smbios_errno(hdl) != ESMB_TYPE) {
		warnx("encountered wrong error for processor info, found: 0x%x",
		    smbios_errno(hdl));
		ret = B_FALSE;
	}

	if (smbios_info_processor_riscv(hdl, sp.smbstr_id, &rv) != -1) {
		warnx("accidentally got riscv info on invalid handle");
		ret = B_FALSE;
	}

	if (smbios_errno(hdl) != ESMB_TYPE) {
		warnx("encountered wrong error for processor info, found: 0x%x",
		    smbios_errno(hdl));
		ret = B_FALSE;
	}

	return (ret);
}
