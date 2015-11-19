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
 * Copyright 2016 Nexenta Systems, Inc.
 */

/*
 * functions for printing of NVMe data structures and their members
 */

#include <sys/byteorder.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stdarg.h>
#include <err.h>
#include <assert.h>

#include "nvmeadm.h"

static int nvme_strlen(const char *, int);

static void nvme_print_str(int, char *, int, const char *, int);
static void nvme_print_double(int, char *, double, int, char *);
static void nvme_print_uint64(int, char *, uint64_t, const char *, char *);
static void nvme_print_uint128(int, char *, nvme_uint128_t, char *, int, int);
static void nvme_print_bit(int, char *, int, char *, char *);

#define	ARRAYSIZE(x)		(sizeof (x) / sizeof (*(x)))

static const char *generic_status_codes[] = {
	"Successful Completion",
	"Invalid Command Opcode",
	"Invalid Field in Command",
	"Command ID Conflict",
	"Data Transfer Error",
	"Commands Aborted due to Power Loss Notification",
	"Internal Error",
	"Command Abort Requested",
	"Command Aborted due to SQ Deletion",
	"Command Aborted due to Failed Fused Command",
	"Command Aborted due to Missing Fused Command",
	"Invalid Namespace or Format",
	"Command Sequence Error",
	/* NVMe 1.1 */
	"Invalid SGL Segment Descriptor",
	"Invalid Number of SGL Descriptors",
	"Data SGL Length Invalid",
	"Metadata SGL Length Invalid",
	"SGL Descriptor Type Invalid",
	/* NVMe 1.2 */
	"Invalid Use of Controller Memory Buffer",
	"PRP Offset Invalid",
	"Atomic Write Unit Exceeded"
};

static const char *specific_status_codes[] = {
	"Completion Queue Invalid",
	"Invalid Queue Identifier",
	"Invalid Queue Size",
	"Abort Command Limit Exceeded",
	"Reserved",
	"Asynchronous Event Request Limit Exceeded",
	"Invalid Firmware Slot",
	"Invalid Firmware Image",
	"Invalid Interrupt Vector",
	"Invalid Log Page",
	"Invalid Format",
	"Firmware Activation Requires Conventional Reset",
	"Invalid Queue Deletion",
	/* NVMe 1.1 */
	"Feature Identifier Not Saveable",
	"Feature Not Changeable",
	"Feature Not Namespace Specific",
	"Firmware Activation Requires NVM Subsystem Reset",
	/* NVMe 1.2 */
	"Firmware Activation Requires Reset",
	"Firmware Activation Requires Maximum Time Violation",
	"Firmware Activation Prohibited",
	"Overlapping Range",
	"Namespace Insufficient Capacity",
	"Namespace Identifier Unavailable",
	"Reserved",
	"Namespace Already Attached",
	"Namespace Is Private",
	"Namespace Not Attached",
	"Thin Provisioning Not Supported",
	"Controller List Invalid"
};

static const char *generic_nvm_status_codes[] = {
	"LBA Out Of Range",
	"Capacity Exceeded",
	"Namespace Not Ready",
	/* NVMe 1.1 */
	"Reservation Conflict",
	/* NVMe 1.2 */
	"Format In Progress",
};

static const char *specific_nvm_status_codes[] = {
	"Conflicting Attributes",
	"Invalid Protection Information",
	"Attempted Write to Read Only Range"
};

static const char *media_nvm_status_codes[] = {
	"Write Fault",
	"Unrecovered Read Error",
	"End-to-End Guard Check Error",
	"End-to-End Application Tag Check Error",
	"End-to-End Reference Tag Check Error",
	"Compare Failure",
	"Access Denied",
	/* NVMe 1.2 */
	"Deallocated or Unwritten Logical Block"
};

static const char *status_code_types[] = {
	"Generic Command Status",
	"Command Specific Status",
	"Media Errors",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Vendor Specific"
};

static const char *lbaf_relative_performance[] = {
	"Best", "Better", "Good", "Degraded"
};

static const char *lba_range_types[] = {
	"Reserved", "Filesystem", "RAID", "Cache", "Page/Swap File"
};

/*
 * nvme_print
 *
 * This function prints a string indented by the specified number of spaces,
 * optionally followed by the specified index if it is >= 0. If a format string
 * is specified, a single colon and the required number of spaces for alignment
 * are printed before the format string and any remaining arguments are passed
 * vprintf.
 *
 * NVME_PRINT_ALIGN was chosen so that all values will be lined up nicely even
 * for the longest name at its default indentation.
 */

#define	NVME_PRINT_ALIGN	43

void
nvme_print(int indent, char *name, int index, const char *fmt, ...)
{
	int align = NVME_PRINT_ALIGN - (indent + strlen(name) + 1);
	va_list ap;

	if (index >= 0)
		align -= snprintf(NULL, 0, " %d", index);

	if (align < 0)
		align = 0;

	va_start(ap, fmt);

	(void) printf("%*s%s", indent, "", name);

	if (index >= 0)
		(void) printf(" %d", index);

	if (fmt != NULL) {
		(void) printf(": %*s", align, "");
		(void) vprintf(fmt, ap);
	}

	(void) printf("\n");
	va_end(ap);
}

/*
 * nvme_strlen -- return length of string without trailing whitespace
 */
static int
nvme_strlen(const char *str, int len)
{
	if (len < 0)
		return (0);

	while (str[--len] == ' ')
		;

	return (++len);
}

/*
 * nvme_print_str -- print a string up to the specified length
 */
static void
nvme_print_str(int indent, char *name, int index, const char *value, int len)
{
	if (len == 0)
		len = strlen(value);

	nvme_print(indent, name, index, "%.*s", nvme_strlen(value, len), value);
}

/*
 * nvme_print_double -- print a double up to a specified number of places with
 * optional unit
 */
static void
nvme_print_double(int indent, char *name, double value, int places, char *unit)
{
	if (unit == NULL)
		unit = "";

	nvme_print(indent, name, -1, "%.*g%s", places, value, unit);
}

/*
 * nvme_print_uint64 -- print uint64_t with optional unit in decimal or another
 * format specified
 */
static void
nvme_print_uint64(int indent, char *name, uint64_t value, const char *fmt,
    char *unit)
{
	char *tmp_fmt;

	if (unit == NULL)
		unit = "";

	if (fmt == NULL)
		fmt = "%"PRId64;

	if (asprintf(&tmp_fmt, "%s%%s", fmt) < 0)
		err(-1, "nvme_print_uint64()");

	nvme_print(indent, name, -1, tmp_fmt, value, unit);

	free(tmp_fmt);
}

/*
 * nvme_print_uint128 -- print a 128bit uint with optional unit, after applying
 * binary and/or decimal shifting
 */
static void
nvme_print_uint128(int indent, char *name, nvme_uint128_t value, char *unit,
    int scale_bits, int scale_tens)
{
	const char hex[] = "0123456789abcdef";
	uint8_t o[(128 + scale_bits) / 3];
	char p[sizeof (o) * 2];
	char *pp = &p[0];
	int i, x;
	uint64_t rem = 0;

	if (unit == NULL)
		unit = "";

	/*
	 * Don't allow binary shifting by more than 64 bits to keep the
	 * arithmetic simple. Also limit decimal shifting based on the size
	 * of any possible remainder from binary shifting.
	 */
	assert(scale_bits <= 64);
	assert(scale_tens <= (64 - scale_bits) / 3);

	bzero(o, sizeof (o));
	bzero(p, sizeof (p));

	/*
	 * Convert the two 64-bit numbers into a series of BCD digits using
	 * a double-dabble algorithm. By using more or less iterations than
	 * 128 we can do a binary shift in either direction.
	 */
	for (x = 0; x != 128 - scale_bits; x++) {
		for (i = 0; i != sizeof (o); i++) {
			if ((o[i] & 0xf0) > 0x40)
				o[i] += 0x30;

			if ((o[i] & 0xf) > 4)
				o[i] += 3;
		}

		for (i = 0; i != sizeof (o) - 1; i++)
			o[i] = (o[i] << 1) + (o[i+1] >> 7);

		o[i] = (o[i] << 1) + (value.hi >> 63);

		value.hi = (value.hi << 1) + (value.lo >> 63);
		value.lo = (value.lo << 1);
	}

	/*
	 * If we're supposed to do a decimal left shift (* 10^x), too,
	 * calculate the remainder of the previous binary shift operation.
	 */
	if (scale_tens > 0) {
		rem = value.hi >> (64 - scale_bits);

		for (i = 0; i != scale_tens; i++)
			rem *= 10;

		rem >>= scale_bits;
	}

	/*
	 * Construct the decimal number for printing. Skip leading zeros.
	 */
	for (i = 0; i < sizeof (o); i++)
		if (o[i] != 0)
			break;

	if (i == sizeof (o)) {
		/*
		 * The converted number is 0. Just print the calculated
		 * remainder and return.
		 */
		nvme_print(indent, name, -1, "%"PRId64"%s", rem, unit);
		return;
	} else {
		if (o[i] > 0xf)
			*pp++ = hex[o[i] >> 4];

		*pp++ = hex[o[i] & 0xf];

		for (i++; i < sizeof (o); i++) {
			*pp++ = hex[o[i] >> 4];
			*pp++ = hex[o[i] & 0xf];
		}
	}

	/*
	 * For negative decimal scaling, use the printf precision specifier to
	 * truncate the results according to the requested decimal scaling. For
	 * positive decimal scaling we print the remainder padded with 0.
	 */
	nvme_print(indent, name, -1, "%.*s%0.*"PRId64"%s",
	    strlen(p) + scale_tens, p,
	    scale_tens > 0 ? scale_tens : 0, rem,
	    unit);
}

/*
 * nvme_print_bit -- print a bit with optional names for both states
 */
static void
nvme_print_bit(int indent, char *name, int value, char *s_true, char *s_false)
{
	if (s_true == NULL)
		s_true = "supported";
	if (s_false == NULL)
		s_false = "unsupported";

	nvme_print(indent, name, -1, "%s", value ? s_true : s_false);
}

/*
 * nvme_print_ctrl_summary -- print a 1-line summary of the IDENTIFY CONTROLLER
 * data structure
 */
void
nvme_print_ctrl_summary(nvme_identify_ctrl_t *idctl, nvme_version_t *version)
{
	(void) printf("model: %.*s, serial: %.*s, FW rev: %.*s, NVMe v%d.%d\n",
	    nvme_strlen(idctl->id_model, sizeof (idctl->id_model)),
	    idctl->id_model,
	    nvme_strlen(idctl->id_serial, sizeof (idctl->id_serial)),
	    idctl->id_serial,
	    nvme_strlen(idctl->id_fwrev, sizeof (idctl->id_fwrev)),
	    idctl->id_fwrev,
	    version->v_major, version->v_minor);
}

/*
 * nvme_print_nsid_summary -- print a 1-line summary of the IDENTIFY NAMESPACE
 * data structure
 */
void
nvme_print_nsid_summary(nvme_identify_nsid_t *idns)
{
	int bsize = 1 << idns->id_lbaf[idns->id_flbas.lba_format].lbaf_lbads;

	(void) printf("Size = %"PRId64" MB, "
	    "Capacity = %"PRId64" MB, "
	    "Used = %"PRId64" MB\n",
	    idns->id_nsize * bsize / 1024 / 1024,
	    idns->id_ncap * bsize / 1024 / 1024,
	    idns->id_nuse * bsize / 1024 / 1024);

}

/*
 * nvme_print_identify_ctrl
 *
 * This function pretty-prints the structure returned by the IDENTIFY CONTROLLER
 * command.
 */
void
nvme_print_identify_ctrl(nvme_identify_ctrl_t *idctl,
    nvme_capabilities_t *cap, nvme_version_t *version)
{
	int i;

	nvme_print(0, "Identify Controller", -1, NULL);
	nvme_print(2, "Controller Capabilities and Features", -1, NULL);
	nvme_print_str(4, "Model", -1,
	    idctl->id_model, sizeof (idctl->id_model));
	nvme_print_str(4, "Serial", -1,
	    idctl->id_serial, sizeof (idctl->id_serial));
	nvme_print_str(4, "Firmware Revision", -1,
	    idctl->id_fwrev, sizeof (idctl->id_fwrev));
	if (verbose) {
		nvme_print_uint64(4, "PCI vendor ID",
		    idctl->id_vid, "0x%0.4"PRIx64, NULL);
		nvme_print_uint64(4, "subsystem vendor ID",
		    idctl->id_ssvid, "0x%0.4"PRIx64, NULL);
		nvme_print_uint64(4, "Recommended Arbitration Burst",
		    idctl->id_rab, NULL, NULL);
		nvme_print(4, "Vendor IEEE OUI", -1, "%0.2X-%0.2X-%0.2X",
		    idctl->id_oui[0], idctl->id_oui[1], idctl->id_oui[2]);
	}
	nvme_print(4, "Multi-Interface Capabilities", -1, NULL);
	nvme_print_bit(6, "Multiple PCI Express ports",
	    idctl->id_mic.m_multi_pci, NULL, NULL);

	if (NVME_VERSION_ATLEAST(version, 1, 1)) {
		nvme_print_bit(6, "Multiple Controllers",
		    idctl->id_mic.m_multi_ctrl, NULL, NULL);
		nvme_print_bit(6, "Is SR-IOV virtual function",
		    idctl->id_mic.m_sr_iov, "yes", "no");
	}
	if (idctl->id_mdts > 0)
		nvme_print_uint64(4, "Maximum Data Transfer Size",
		    (1 << idctl->id_mdts) * cap->mpsmin / 1024, NULL, "kB");
	else
		nvme_print_str(4, "Maximum Data Transfer Size", -1,
		    "unlimited", 0);

	if (NVME_VERSION_ATLEAST(version, 1, 1)) {
		nvme_print_uint64(4, "Unique Controller Identifier",
		    idctl->id_cntlid, "0x%0.4"PRIx64, NULL);
	}

	nvme_print(2, "Admin Command Set Attributes", -1, NULL);
	nvme_print(4, "Optional Admin Command Support", -1, NULL);
	nvme_print_bit(6, "Security Send & Receive",
	    idctl->id_oacs.oa_security, NULL, NULL);
	nvme_print_bit(6, "Format NVM",
	    idctl->id_oacs.oa_format, NULL, NULL);
	nvme_print_bit(6, "Firmware Activate & Download",
	    idctl->id_oacs.oa_firmware, NULL, NULL);
	if (verbose) {
		nvme_print_uint64(4, "Abort Command Limit",
		    (uint16_t)idctl->id_acl + 1, NULL, NULL);
		nvme_print_uint64(4, "Asynchronous Event Request Limit",
		    (uint16_t)idctl->id_aerl + 1, NULL, NULL);
	}
	nvme_print(4, "Firmware Updates", -1, NULL);
	nvme_print_bit(6, "Firmware Slot 1",
	    idctl->id_frmw.fw_readonly, "read-only", "writable");
	nvme_print_uint64(6, "No. of Firmware Slots",
	    idctl->id_frmw.fw_nslot, NULL, NULL);
	nvme_print(2, "Log Page Attributes", -1, NULL);
	nvme_print_bit(6, "per Namespace SMART/Health info",
	    idctl->id_lpa.lp_smart, NULL, NULL);
	nvme_print_uint64(4, "Error Log Page Entries",
	    (uint16_t)idctl->id_elpe + 1, NULL, NULL);
	nvme_print_uint64(4, "Number of Power States",
	    (uint16_t)idctl->id_npss + 1, NULL, NULL);
	if (verbose) {
		nvme_print_bit(4, "Admin Vendor-specific Command Format",
		    idctl->id_avscc.av_spec, "standard", "vendor-specific");
	}

	if (NVME_VERSION_ATLEAST(version, 1, 1)) {
		nvme_print_bit(4, "Autonomous Power State Transitions",
		    idctl->id_apsta.ap_sup, NULL, NULL);
	}

	nvme_print(2, "NVM Command Set Attributes", -1, NULL);
	if (verbose) {
		nvme_print(4, "Submission Queue Entry Size", -1,
		    "min %d, max %d",
		    1 << idctl->id_sqes.qes_min, 1 << idctl->id_sqes.qes_max);
		nvme_print(4, "Completion Queue Entry Size", -1,
		    "min %d, max %d",
		    1 << idctl->id_cqes.qes_min, 1 << idctl->id_cqes.qes_max);
	}
	nvme_print_uint64(4, "Number of Namespaces",
	    idctl->id_nn, NULL, NULL);
	nvme_print(4, "Optional NVM Command Support", -1, NULL);
	nvme_print_bit(6, "Compare",
	    idctl->id_oncs.on_compare, NULL, NULL);
	nvme_print_bit(6, "Write Uncorrectable",
	    idctl->id_oncs.on_wr_unc, NULL, NULL);
	nvme_print_bit(6, "Dataset Management",
	    idctl->id_oncs.on_dset_mgmt, NULL, NULL);

	if (NVME_VERSION_ATLEAST(version, 1, 1)) {
		nvme_print_bit(6, "Write Zeros",
		    idctl->id_oncs.on_wr_zero, NULL, NULL);
		nvme_print_bit(6, "Save/Select in Get/Set Features",
		    idctl->id_oncs.on_save, NULL, NULL);
		nvme_print_bit(6, "Reservations",
		    idctl->id_oncs.on_reserve, NULL, NULL);
	}

	nvme_print(4, "Fused Operation Support", -1, NULL);
	nvme_print_bit(6, "Compare and Write",
	    idctl->id_fuses.f_cmp_wr, NULL, NULL);
	nvme_print(4, "Format NVM Attributes", -1, NULL);
	nvme_print_bit(6, "per Namespace Format",
	    idctl->id_fna.fn_format == 0, NULL, NULL);
	nvme_print_bit(6, "per Namespace Secure Erase",
	    idctl->id_fna.fn_sec_erase == 0, NULL, NULL);
	nvme_print_bit(6, "Cryptographic Erase",
	    idctl->id_fna.fn_crypt_erase, NULL, NULL);
	nvme_print_bit(4, "Volatile Write Cache",
	    idctl->id_vwc.vwc_present, "present", "not present");
	nvme_print_uint64(4, "Atomic Write Unit Normal",
	    (uint32_t)idctl->id_awun + 1, NULL,
	    idctl->id_awun == 0 ? " block" : " blocks");
	nvme_print_uint64(4, "Atomic Write Unit Power Fail",
	    (uint32_t)idctl->id_awupf + 1, NULL,
	    idctl->id_awupf == 0 ? " block" : " blocks");

	if (verbose != 0)
		nvme_print_bit(4, "NVM Vendor-specific Command Format",
		    idctl->id_nvscc.nv_spec, "standard", "vendor-specific");

	if (NVME_VERSION_ATLEAST(version, 1, 1)) {
		nvme_print_uint64(4, "Atomic Compare & Write Size",
		    (uint32_t)idctl->id_acwu + 1, NULL,
		    idctl->id_acwu == 0 ? " block" : " blocks");
		nvme_print(4, "SGL Support", -1, NULL);
		nvme_print_bit(6, "SGLs in NVM commands",
		    idctl->id_sgls.sgl_sup, NULL, NULL);
		nvme_print_bit(6, "SGL Bit Bucket Descriptor",
		    idctl->id_sgls.sgl_bucket, NULL, NULL);
	}

	for (i = 0; i != idctl->id_npss + 1; i++) {
		double scale = 0.01;
		double power = 0;
		int places = 2;
		char *unit = "W";

		if (NVME_VERSION_ATLEAST(version, 1, 1) &&
		    idctl->id_psd[i].psd_mps == 1) {
			scale = 0.0001;
			places = 4;
		}

		power = (double)idctl->id_psd[i].psd_mp * scale;
		if (power < 1.0) {
			power *= 1000.0;
			unit = "mW";
		}

		nvme_print(4, "Power State Descriptor", i, NULL);
		nvme_print_double(6, "Maximum Power", power, places, unit);
		nvme_print_bit(6, "Non-Operational State",
		    idctl->id_psd[i].psd_nops, "yes", "no");
		nvme_print_uint64(6, "Entry Latency",
		    idctl->id_psd[i].psd_enlat, NULL, "us");
		nvme_print_uint64(6, "Exit Latency",
		    idctl->id_psd[i].psd_exlat, NULL, "us");
		nvme_print_uint64(6, "Relative Read Throughput (0 = best)",
		    idctl->id_psd[i].psd_rrt, NULL, NULL);
		nvme_print_uint64(6, "Relative Read Latency (0 = best)",
		    idctl->id_psd[i].psd_rrl, NULL, NULL);
		nvme_print_uint64(6, "Relative Write Throughput (0 = best)",
		    idctl->id_psd[i].psd_rwt, NULL, NULL);
		nvme_print_uint64(6, "Relative Write Latency (0 = best)",
		    idctl->id_psd[i].psd_rwl, NULL, NULL);
	}
}

/*
 * nvme_print_identify_nsid
 *
 * This function pretty-prints the structure returned by the IDENTIFY NAMESPACE
 * command.
 */
void
nvme_print_identify_nsid(nvme_identify_nsid_t *idns, nvme_version_t *version)
{
	int bsize = 1 << idns->id_lbaf[idns->id_flbas.lba_format].lbaf_lbads;
	int i;

	nvme_print(0, "Identify Namespace", -1, NULL);
	nvme_print(2, "Namespace Capabilities and Features", -1, NULL);
	nvme_print_uint64(4, "Namespace Size",
	    idns->id_nsize * bsize / 1024 / 1024, NULL, "MB");
	nvme_print_uint64(4, "Namespace Capacity",
	    idns->id_ncap * bsize / 1024 / 1024, NULL, "MB");
	nvme_print_uint64(4, "Namespace Utilization",
	    idns->id_nuse * bsize / 1024 / 1024, NULL, "MB");
	nvme_print(4, "Namespace Features", -1, NULL);
	nvme_print_bit(6, "Thin Provisioning",
	    idns->id_nsfeat.f_thin, NULL, NULL);
	nvme_print_uint64(4, "Number of LBA Formats",
	    (uint16_t)idns->id_nlbaf + 1, NULL, NULL);
	nvme_print(4, "Formatted LBA Size", -1, NULL);
	nvme_print_uint64(6, "LBA Format",
	    (uint16_t)idns->id_flbas.lba_format, NULL, NULL);
	nvme_print_bit(6, "Extended Data LBA",
	    idns->id_flbas.lba_extlba, "yes", "no");
	nvme_print(4, "Metadata Capabilities", -1, NULL);
	nvme_print_bit(6, "Extended Data LBA",
	    idns->id_mc.mc_extlba, NULL, NULL);
	nvme_print_bit(6, "Separate Metadata",
	    idns->id_mc.mc_separate, NULL, NULL);
	nvme_print(4, "End-to-End Data Protection Capabilities", -1, NULL);
	nvme_print_bit(6, "Protection Information Type 1",
	    idns->id_dpc.dp_type1, NULL, NULL);
	nvme_print_bit(6, "Protection Information Type 2",
	    idns->id_dpc.dp_type2, NULL, NULL);
	nvme_print_bit(6, "Protection Information Type 3",
	    idns->id_dpc.dp_type3, NULL, NULL);
	nvme_print_bit(6, "Protection Information first",
	    idns->id_dpc.dp_first, NULL, NULL);
	nvme_print_bit(6, "Protection Information last",
	    idns->id_dpc.dp_last, NULL, NULL);
	nvme_print(4, "End-to-End Data Protection Settings", -1, NULL);
	if (idns->id_dps.dp_pinfo == 0)
		nvme_print_str(6, "Protection Information", -1,
		    "disabled", 0);
	else
		nvme_print_uint64(6, "Protection Information Type",
		    idns->id_dps.dp_pinfo, NULL, NULL);
	nvme_print_bit(6, "Protection Information in Metadata",
	    idns->id_dps.dp_first, "first 8 bytes", "last 8 bytes");

	if (NVME_VERSION_ATLEAST(version, 1, 1)) {
		nvme_print(4, "Namespace Multi-Path I/O and Namespace Sharing "
		    "Capabilities", -1, NULL);
		nvme_print_bit(6, "Namespace is shared",
		    idns->id_nmic.nm_shared, "yes", "no");
		nvme_print(2, "Reservation Capabilities", -1, NULL);
		nvme_print_bit(6, "Persist Through Power Loss",
		    idns->id_rescap.rc_persist, NULL, NULL);
		nvme_print_bit(6, "Write Exclusive",
		    idns->id_rescap.rc_wr_excl, NULL, NULL);
		nvme_print_bit(6, "Exclusive Access",
		    idns->id_rescap.rc_excl, NULL, NULL);
		nvme_print_bit(6, "Write Exclusive - Registrants Only",
		    idns->id_rescap.rc_wr_excl_r, NULL, NULL);
		nvme_print_bit(6, "Exclusive Access - Registrants Only",
		    idns->id_rescap.rc_excl_r, NULL, NULL);
		nvme_print_bit(6, "Write Exclusive - All Registrants",
		    idns->id_rescap.rc_wr_excl_a, NULL, NULL);
		nvme_print_bit(6, "Exclusive Access - All Registrants",
		    idns->id_rescap.rc_excl_a, NULL, NULL);

		nvme_print(4, "IEEE Extended Unique Identifier", -1,
		    "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X",
		    idns->id_eui64[0], idns->id_eui64[1],
		    idns->id_eui64[2], idns->id_eui64[3],
		    idns->id_eui64[4], idns->id_eui64[5],
		    idns->id_eui64[6], idns->id_eui64[7]);
	}

	for (i = 0; i <= idns->id_nlbaf; i++) {
		if (verbose == 0 && idns->id_lbaf[i].lbaf_ms != 0)
			continue;

		nvme_print(4, "LBA Format", i, NULL);
		nvme_print_uint64(6, "Metadata Size",
		    idns->id_lbaf[i].lbaf_ms, NULL, " bytes");
		nvme_print_uint64(6, "LBA Data Size",
		    1 << idns->id_lbaf[i].lbaf_lbads, NULL, " bytes");
		nvme_print_str(6, "Relative Performance", -1,
		    lbaf_relative_performance[idns->id_lbaf[i].lbaf_rp], 0);
	}
}

/*
 * nvme_print_error_log
 *
 * This function pretty-prints all non-zero error log entries, or all entries
 * if verbose is set.
 */
void
nvme_print_error_log(int nlog, nvme_error_log_entry_t *elog)
{
	int i;

	nvme_print(0, "Error Log", -1, NULL);
	for (i = 0; i != nlog; i++)
		if (elog[i].el_count == 0)
			break;
	nvme_print_uint64(2, "Number of Error Log Entries", i, NULL, NULL);

	for (i = 0; i != nlog; i++) {
		int sc = elog[i].el_sf.sf_sc;
		const char *sc_str = "";

		if (elog[i].el_count == 0 && verbose == 0)
			break;

		switch (elog[i].el_sf.sf_sct) {
		case 0: /* Generic Command Status */
			if (sc < ARRAYSIZE(generic_status_codes))
				sc_str = generic_status_codes[sc];
			else if (sc >= 0x80 &&
			    sc - 0x80 < ARRAYSIZE(generic_nvm_status_codes))
				sc_str = generic_nvm_status_codes[sc - 0x80];
			break;
		case 1: /* Specific Command Status */
			if (sc < ARRAYSIZE(specific_status_codes))
				sc_str = specific_status_codes[sc];
			else if (sc >= 0x80 &&
			    sc - 0x80 < ARRAYSIZE(specific_nvm_status_codes))
				sc_str = specific_nvm_status_codes[sc - 0x80];
			break;
		case 2: /* Media Errors */
			if (sc >= 0x80 &&
			    sc - 0x80 < ARRAYSIZE(media_nvm_status_codes))
				sc_str = media_nvm_status_codes[sc - 0x80];
			break;
		case 7: /* Vendor Specific */
			sc_str = "Unknown Vendor Specific";
			break;
		default:
			sc_str = "Reserved";
			break;
		}

		nvme_print(2, "Entry", i, NULL);
		nvme_print_uint64(4, "Error Count",
		    elog[i].el_count, NULL, NULL);
		nvme_print_uint64(4, "Submission Queue ID",
		    elog[i].el_sqid, NULL, NULL);
		nvme_print_uint64(4, "Command ID",
		    elog[i].el_cid, NULL, NULL);
		nvme_print(4, "Status Field", -1, NULL);
		nvme_print_uint64(6, "Phase Tag",
		    elog[i].el_sf.sf_p, NULL, NULL);
		nvme_print(6, "Status Code", -1, "0x%0.2x (%s)",
		    sc, sc_str);
		nvme_print(6, "Status Code Type", -1, "0x%x (%s)",
		    elog[i].el_sf.sf_sct,
		    status_code_types[elog[i].el_sf.sf_sct]);
		nvme_print_bit(6, "More",
		    elog[i].el_sf.sf_m, "yes", "no");
		nvme_print_bit(6, "Do Not Retry",
		    elog[i].el_sf.sf_m, "yes", "no");
		nvme_print_uint64(4, "Parameter Error Location byte",
		    elog[i].el_byte, "0x%0.2"PRIx64, NULL);
		nvme_print_uint64(4, "Parameter Error Location bit",
		    elog[i].el_bit, NULL, NULL);
		nvme_print_uint64(4, "Logical Block Address",
		    elog[i].el_lba, NULL, NULL);
		nvme_print(4, "Namespace ID", -1, "%d",
		    elog[i].el_nsid == 0xffffffff ?
		    0 : elog[i].el_nsid);
		nvme_print_uint64(4,
		    "Vendor Specifc Information Available",
		    elog[i].el_vendor, NULL, NULL);
	}
}

/*
 * nvme_print_health_log
 *
 * This function pretty-prints a summary of the SMART/Health log, or all
 * of the log if verbose is set.
 */
void
nvme_print_health_log(nvme_health_log_t *hlog, nvme_identify_ctrl_t *idctl)
{
	nvme_print(0, "SMART/Health Information", -1, NULL);
	nvme_print(2, "Critical Warnings", -1, NULL);
	nvme_print_bit(4, "Available Space",
	    hlog->hl_crit_warn.cw_avail, "low", "OK");
	nvme_print_bit(4, "Temperature",
	    hlog->hl_crit_warn.cw_temp, "too high", "OK");
	nvme_print_bit(4, "Device Reliability",
	    hlog->hl_crit_warn.cw_reliab, "degraded", "OK");
	nvme_print_bit(4, "Media",
	    hlog->hl_crit_warn.cw_readonly, "read-only", "OK");
	if (idctl->id_vwc.vwc_present != 0)
		nvme_print_bit(4, "Volatile Memory Backup",
		    hlog->hl_crit_warn.cw_volatile, "failed", "OK");

	nvme_print_uint64(2, "Temperature",
	    hlog->hl_temp - 273, NULL, "C");
	nvme_print_uint64(2, "Available Spare Capacity",
	    hlog->hl_avail_spare, NULL, "%");

	if (verbose != 0)
		nvme_print_uint64(2, "Available Spare Threshold",
		    hlog->hl_avail_spare_thr, NULL, "%");

	nvme_print_uint64(2, "Device Life Used",
	    hlog->hl_used, NULL, "%");

	if (verbose == 0)
		return;

	/*
	 * The following two fields are in 1000 512 byte units. Convert that to
	 * GB by doing binary shifts (9 left and 30 right) and muliply by 10^3.
	 */
	nvme_print_uint128(2, "Data Read",
	    hlog->hl_data_read, "GB", 30 - 9, 3);
	nvme_print_uint128(2, "Data Written",
	    hlog->hl_data_write, "GB", 30 - 9, 3);

	nvme_print_uint128(2, "Read Commands",
	    hlog->hl_host_read, NULL, 0, 0);
	nvme_print_uint128(2, "Write Commands",
	    hlog->hl_host_write, NULL, 0, 0);
	nvme_print_uint128(2, "Controller Busy",
	    hlog->hl_ctrl_busy, "min", 0, 0);
	nvme_print_uint128(2, "Power Cycles",
	    hlog->hl_power_cycles, NULL, 0, 0);
	nvme_print_uint128(2, "Power On",
	    hlog->hl_power_on_hours, "h", 0, 0);
	nvme_print_uint128(2, "Unsafe Shutdowns",
	    hlog->hl_unsafe_shutdn, NULL, 0, 0);
	nvme_print_uint128(2, "Uncorrectable Media Errors",
	    hlog->hl_media_errors, NULL, 0, 0);
	nvme_print_uint128(2, "Errors Logged",
	    hlog->hl_errors_logged, NULL, 0, 0);
}

/*
 * nvme_print_fwslot_log
 *
 * This function pretty-prints the firmware slot information.
 */
void
nvme_print_fwslot_log(nvme_fwslot_log_t *fwlog)
{
	int i;

	nvme_print(0, "Firmware Slot Information", -1, NULL);
	nvme_print_uint64(2, "Active Firmware Slot", fwlog->fw_afi, NULL, NULL);

	for (i = 0; i != ARRAYSIZE(fwlog->fw_frs); i++) {
		if (fwlog->fw_frs[i][0] == '\0')
			break;
		nvme_print_str(2, "Firmware Revision for Slot", i + 1,
		    fwlog->fw_frs[i], sizeof (fwlog->fw_frs[i]));
	}
}

/*
 * nvme_print_feat_*
 *
 * These functions pretty-print the data structures returned by GET FEATURES.
 */
void
nvme_print_feat_arbitration(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_arbitration_t arb;

	arb.r = (uint32_t)res;
	if (arb.b.arb_ab != 7)
		nvme_print_uint64(4, "Arbitration Burst",
		    1 << arb.b.arb_ab, NULL, NULL);
	else
		nvme_print_str(4, "Arbitration Burst", 0,
		    "no limit", 0);
	nvme_print_uint64(4, "Low Priority Weight",
	    (uint16_t)arb.b.arb_lpw + 1, NULL, NULL);
	nvme_print_uint64(4, "Medium Priority Weight",
	    (uint16_t)arb.b.arb_mpw + 1, NULL, NULL);
	nvme_print_uint64(4, "High Priority Weight",
	    (uint16_t)arb.b.arb_hpw + 1, NULL, NULL);
}

void
nvme_print_feat_power_mgmt(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_power_mgmt_t pm;

	pm.r = (uint32_t)res;
	nvme_print_uint64(4, "Power State", (uint8_t)pm.b.pm_ps,
	    NULL, NULL);
}

void
nvme_print_feat_lba_range(uint64_t res, void *buf, size_t bufsize,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(id));

	nvme_lba_range_type_t lrt;
	nvme_lba_range_t *lr;
	size_t n_lr;
	int i;

	if (buf == NULL)
		return;

	lrt.r = res;
	lr = buf;

	n_lr = bufsize / sizeof (nvme_lba_range_t);
	if (n_lr > lrt.b.lr_num + 1)
		n_lr = lrt.b.lr_num + 1;

	nvme_print_uint64(4, "Number of LBA Ranges",
	    (uint8_t)lrt.b.lr_num + 1, NULL, NULL);

	for (i = 0; i != n_lr; i++) {
		if (verbose == 0 && lr[i].lr_nlb == 0)
			continue;

		nvme_print(4, "LBA Range", i, NULL);
		if (lr[i].lr_type < ARRAYSIZE(lba_range_types))
			nvme_print_str(6, "Type", -1,
			    lba_range_types[lr[i].lr_type], 0);
		else
			nvme_print_uint64(6, "Type",
			    lr[i].lr_type, NULL, NULL);
		nvme_print(6, "Attributes", -1, NULL);
		nvme_print_bit(8, "Writable",
		    lr[i].lr_attr.lr_write, "yes", "no");
		nvme_print_bit(8, "Hidden",
		    lr[i].lr_attr.lr_hidden, "yes", "no");
		nvme_print_uint64(6, "Starting LBA",
		    lr[i].lr_slba, NULL, NULL);
		nvme_print_uint64(6, "Number of Logical Blocks",
		    lr[i].lr_nlb, NULL, NULL);
		nvme_print(6, "Unique Identifier", -1,
		    "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x"
		    "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x",
		    lr[i].lr_guid[0], lr[i].lr_guid[1],
		    lr[i].lr_guid[2], lr[i].lr_guid[3],
		    lr[i].lr_guid[4], lr[i].lr_guid[5],
		    lr[i].lr_guid[6], lr[i].lr_guid[7],
		    lr[i].lr_guid[8], lr[i].lr_guid[9],
		    lr[i].lr_guid[10], lr[i].lr_guid[11],
		    lr[i].lr_guid[12], lr[i].lr_guid[13],
		    lr[i].lr_guid[14], lr[i].lr_guid[15]);
	}
}

void
nvme_print_feat_temperature(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_temp_threshold_t tt;

	tt.r = (uint32_t)res;
	nvme_print_uint64(4, "Temperature Threshold", tt.b.tt_tmpth - 273,
	    NULL, "C");
}

void
nvme_print_feat_error(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_error_recovery_t er;

	er.r = (uint32_t)res;
	if (er.b.er_tler > 0)
		nvme_print_uint64(4, "Time Limited Error Recovery",
		    (uint32_t)er.b.er_tler * 100, NULL, "ms");
	else
		nvme_print_str(4, "Time Limited Error Recovery", -1,
		    "no time limit", 0);
}

void
nvme_print_feat_write_cache(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_write_cache_t wc;

	wc.r = (uint32_t)res;
	nvme_print_bit(4, "Volatile Write Cache",
	    wc.b.wc_wce, "enabled", "disabled");
}

void
nvme_print_feat_nqueues(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_nqueues_t nq;

	nq.r = (uint32_t)res;
	nvme_print_uint64(4, "Number of Submission Queues",
	    nq.b.nq_nsq + 1, NULL, NULL);
	nvme_print_uint64(4, "Number of Completion Queues",
	    nq.b.nq_ncq + 1, NULL, NULL);
}

void
nvme_print_feat_intr_coal(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_intr_coal_t ic;

	ic.r = (uint32_t)res;
	nvme_print_uint64(4, "Aggregation Threshold",
	    ic.b.ic_thr + 1, NULL, NULL);
	nvme_print_uint64(4, "Aggregation Time",
	    (uint16_t)ic.b.ic_time * 100, NULL, "us");
}
void
nvme_print_feat_intr_vect(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_intr_vect_t iv;
	char *tmp;

	iv.r = (uint32_t)res;
	if (asprintf(&tmp, "Vector %d Coalescing Disable", iv.b.iv_iv) < 0)
		err(-1, "nvme_print_feat_common()");

	nvme_print_bit(4, tmp, iv.b.iv_cd, "yes", "no");
}

void
nvme_print_feat_write_atom(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_write_atomicity_t wa;

	wa.r = (uint32_t)res;
	nvme_print_bit(4, "Disable Normal", wa.b.wa_dn, "yes", "no");
}

void
nvme_print_feat_async_event(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *idctl)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	nvme_async_event_conf_t aec;

	aec.r = (uint32_t)res;
	nvme_print_bit(4, "Available Space below threshold",
	    aec.b.aec_avail, "enabled", "disabled");
	nvme_print_bit(4, "Temperature above threshold",
	    aec.b.aec_temp, "enabled", "disabled");
	nvme_print_bit(4, "Device Reliability compromised",
	    aec.b.aec_reliab, "enabled", "disabled");
	nvme_print_bit(4, "Media read-only",
	    aec.b.aec_readonly, "enabled", "disabled");
	if (idctl->id_vwc.vwc_present != 0)
		nvme_print_bit(4, "Volatile Memory Backup failed",
		    aec.b.aec_volatile, "enabled", "disabled");
}

void
nvme_print_feat_auto_pst(uint64_t res, void *buf, size_t bufsize,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(id));

	nvme_auto_power_state_trans_t apst;
	nvme_auto_power_state_t *aps;
	int i;
	int cnt = bufsize / sizeof (nvme_auto_power_state_t);

	if (buf == NULL)
		return;

	apst.r = res;
	aps = buf;

	nvme_print_bit(4, "Autonomous Power State Transition",
	    apst.b.apst_apste, "enabled", "disabled");
	for (i = 0; i != cnt; i++) {
		if (aps[i].apst_itps == 0 && aps[i].apst_itpt == 0)
			break;

		nvme_print(4, "Power State", i, NULL);
		nvme_print_uint64(6, "Idle Transition Power State",
		    (uint16_t)aps[i].apst_itps, NULL, NULL);
		nvme_print_uint64(6, "Idle Time Prior to Transition",
		    aps[i].apst_itpt, NULL, "ms");
	}
}

void
nvme_print_feat_progress(uint64_t res, void *b, size_t s,
    nvme_identify_ctrl_t *id)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_software_progress_marker_t spm;

	spm.r = (uint32_t)res;
	nvme_print_uint64(4, "Pre-Boot Software Load Count",
	    spm.b.spm_pbslc, NULL, NULL);
}
