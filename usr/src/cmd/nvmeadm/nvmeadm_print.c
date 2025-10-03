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
 * Copyright 2025 Oxide Computer Company
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * functions for printing of NVMe data structures and their members
 */

#include <sys/sysmacros.h>
#include <sys/byteorder.h>
#include <sys/types.h>
#include <sys/hexdump.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stdarg.h>
#include <err.h>
#include <assert.h>
#include <libcmdutils.h>
#include <ctype.h>

#include "nvmeadm.h"

static void nvme_print_str(int, const char *, int, const char *, int);
static void nvme_print_double(int, const char *, double, int, const char *);
static void nvme_print_int64(int, const char *, uint64_t, const char *,
    const char *);
static void nvme_print_uint64(int, const char *, uint64_t, const char *,
    const char *);
static void nvme_print_uint128(int, const char *, nvme_uint128_t, const char *,
    int, int);
static void nvme_print_bit(int, const char *, boolean_t, uint_t, const char *,
    const char *);
static void nvme_print_hexbuf(int, const char *, const uint8_t *, size_t);
static void nvme_print_eui64(int, const char *, const uint8_t *);
static void nvme_print_guid(int, const char *, const uint8_t *);
static void nvme_print_uuid(int, const char *, const uint8_t *);

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
	/* NVMe 1.1 -- 0xd */
	"Invalid SGL Segment Descriptor",
	"Invalid Number of SGL Descriptors",
	"Data SGL Length Invalid",
	"Metadata SGL Length Invalid",
	"SGL Descriptor Type Invalid",
	/* NVMe 1.2  -- 0x12 */
	"Invalid Use of Controller Memory Buffer",
	"PRP Offset Invalid",
	"Atomic Write Unit Exceeded",
	/* NVMe 1.3 -- 0x15 */
	"Operation Denied",
	"SGL Offset Invalid",
	"Reserved",
	"Host Identifier Inconsistent Format",
	"Keep Alive Timeout Expired",
	"Keep Alive Timeout Invalid",
	"Command Aborted due to Preempt and Abort",
	"Sanitize Failed",
	"Sanitize in Progress",
	"SGL Data Block Granularity Invalid",
	"Command Not Supported for Queue in CMB",
	/* NVMe 1.4 -- 0x20 */
	"Namespace is Write Protected",
	"Command Interrupted",
	"Transient Transport Error"
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
	/* NVMe 1.1 -- 0xd */
	"Feature Identifier Not Saveable",
	"Feature Not Changeable",
	"Feature Not Namespace Specific",
	"Firmware Activation Requires NVM Subsystem Reset",
	/* NVMe 1.2 -- 0x12 */
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
	"Controller List Invalid",
	/* NVMe 1.3 -- 0x1e */
	"Boot Partition Write Prohibited",
	"Invalid Controller Identifier",
	"Invalid Secondary Controller State",
	"Invalid Number of Controller Resources",
	"Invalid Resource Identifier",
	/* NVMe 1.4 -- 0x23 */
	"Sanitize Prohibited While Persistent Memory Region is Enabled",
	"ANA Group Identifier Invalid",
	"ANA Attach Failed"
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
	/* NVMe 1.2 -- 0x87 (0x7) */
	"Deallocated or Unwritten Logical Block"
};

static const char *path_status_codes[] = {
	/* NVMe 1.4 -- 0x00 */
	"Internal Path Error",
	"Asymmetric Access Persistent Loss",
	"Asymmetric Access Inaccessible",
	"Asymmetric Access Transition"
};

static const char *path_controller_codes[] = {
	/* NVMe 1.4 -- 0x60 */
	"Controller Pathing Error"
};

static const char *path_host_codes[] = {
	/* NVMe 1.4 -- 0x70 */
	"Host Pathing Error",
	"Command Aborted by Host"
};

static const char *status_code_types[] = {
	"Generic Command Status",
	"Command Specific Status",
	"Media and Data Integrity Errors",
	"Path Related Status",
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

static const char *ns_identifier_type[] = {
	"Reserved", "IEEE Extended Unique Identifier", "Namespace GUID", "UUID"
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
nvme_print(int indent, const char *name, int index, const char *fmt, ...)
{
	int align = NVME_PRINT_ALIGN - (indent + 1);
	va_list ap;

	if (name != NULL)
		align -= strlen(name);

	if (index >= 0)
		align -= snprintf(NULL, 0, " %d", index);

	if (align < 0)
		align = 0;

	va_start(ap, fmt);

	(void) printf("%*s%s", indent, "", name != NULL ? name : "");

	if (index >= 0)
		(void) printf(" %d", index);

	if (fmt != NULL) {
		if (name != NULL || index >= 0)
			(void) printf(": ");
		else
			(void) printf("  ");
		(void) printf("%*s", align, "");
		(void) vprintf(fmt, ap);
	}

	(void) printf("\n");
	va_end(ap);
}

/*
 * nvme_strlen -- return length of string without trailing whitespace
 */
int
nvme_strlen(const char *str, int len)
{
	if (len <= 0)
		return (0);

	while (str[--len] == ' ')
		;

	return (++len);
}

/*
 * nvme_print_str -- print a string up to the specified length
 */
static void
nvme_print_str(int indent, const char *name, int index, const char *value,
    int len)
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
nvme_print_double(int indent, const char *name, double value, int places,
    const char *unit)
{
	if (unit == NULL)
		unit = "";

	nvme_print(indent, name, -1, "%.*g%s", places, value, unit);
}

/*
 * nvme_print_int64 -- print int64_t with optional unit in decimal or another
 * format specified
 */
static void
nvme_print_int64(int indent, const char *name, uint64_t value, const char *fmt,
    const char *unit)
{
	char *tmp_fmt;

	if (unit == NULL)
		unit = "";

	if (fmt == NULL)
		fmt = "%"PRId64;

	if (asprintf(&tmp_fmt, "%s%%s", fmt) < 0)
		err(-1, "nvme_print_int64()");

	nvme_print(indent, name, -1, tmp_fmt, value, unit);

	free(tmp_fmt);
}

/*
 * nvme_print_temp -- The NVMe specification passes most temperature values as
 * uint16_t values that are encoded in kelvin. This converts them in one place
 * to Celsius.
 */
static void
nvme_print_temp(int indent, const char *name, uint16_t value)
{
	int64_t temp = (int64_t)value;
	temp -= 273;
	nvme_print_int64(indent, name, temp, NULL, "C");
}

/*
 * nvme_print_uint64 -- print uint64_t with optional unit in decimal or another
 * format specified
 */
static void
nvme_print_uint64(int indent, const char *name, uint64_t value, const char *fmt,
    const char *unit)
{
	char *tmp_fmt;

	if (unit == NULL)
		unit = "";

	if (fmt == NULL)
		fmt = "%"PRIu64;

	if (asprintf(&tmp_fmt, "%s%%s", fmt) < 0)
		err(-1, "nvme_print_uint64()");

	nvme_print(indent, name, -1, tmp_fmt, value, unit);

	free(tmp_fmt);
}

/*
 * nvme_snprint_uint128 -- format a 128bit uint with optional unit, after
 * applying binary and/or decimal shifting
 */
int
nvme_snprint_uint128(char *buf, size_t buflen, nvme_uint128_t value,
    int scale_bits, int scale_tens)
{
	const char hex[] = "0123456789abcdef";
	uint8_t o[(128 + scale_bits) / 3];
	char p[sizeof (o) * 2];
	char *pp = &p[0];
	int i, x;
	uint64_t rem = 0;

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
		return (snprintf(buf, buflen, "%"PRId64, rem));
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
	 * For negative decimal scaling, use the snprintf precision specifier to
	 * truncate the results according to the requested decimal scaling. For
	 * positive decimal scaling we print the remainder padded with 0.
	 */
	return (snprintf(buf, buflen, "%.*s%0.*"PRId64,
	    strlen(p) + scale_tens, p,
	    scale_tens > 0 ? scale_tens : 0, rem));
}

/*
 * nvme_print_uint128 -- print a 128bit uint with optional unit, after applying
 * binary and/or decimal shifting
 */
static void
nvme_print_uint128(int indent, const char *name, nvme_uint128_t value,
    const char *unit, int scale_bits, int scale_tens)
{
	char buf[64];

	if (unit == NULL)
		unit = "";

	(void) nvme_snprint_uint128(buf, sizeof (buf), value, scale_bits,
	    scale_tens);

	nvme_print(indent, name, -1, "%s%s", buf, unit);
}

/*
 * nvme_print_bit -- print a bit with optional names for both states
 */
static void
nvme_print_bit(int indent, const char *name, boolean_t valid_vers, uint_t value,
    const char *s_true, const char *s_false)
{
	if (s_true == NULL)
		s_true = "supported";
	if (s_false == NULL)
		s_false = "unsupported";

	if (!valid_vers)
		value = 0;

	nvme_print(indent, name, -1, "%s", value ? s_true : s_false);
}

/*
 * nvme_print_hexbuf -- print a buffer of bytes as a hex dump
 */
static void
nvme_print_hexbuf(int indent, const char *name, const uint8_t *buf, size_t len)
{
	/*
	 * The format string is kept in this variable so it can be cut
	 * short to print the remainder after the loop.
	 */
	char fmt[] = { "%02x %02x %02x %02x %02x %02x %02x %02x" };
	size_t lines = len / 8;
	size_t rem = len % 8;
	size_t i;

	for (i = 0; i < lines; i++) {
		nvme_print(indent, name, -1, fmt,
		    buf[i*8 + 0], buf[i*8 + 1], buf[i*8 + 2], buf[i*8 + 3],
		    buf[i*8 + 4], buf[i*8 + 5], buf[i*8 + 6], buf[i*8 + 7]);
		name = NULL;
	}

	if (rem > 0) {
		fmt[rem * 5] = '\0';

		nvme_print(indent, name, -1, fmt,
		    buf[i*8 + 0], buf[i*8 + 1], buf[i*8 + 2], buf[i*8 + 3],
		    buf[i*8 + 4], buf[i*8 + 5], buf[i*8 + 6], buf[i*8 + 7]);
	}
}

/*
 * nvme_print_uuid -- print a UUID in canonical form
 */
static void
nvme_print_uuid(int indent, const char *name, const uint8_t *uuid)
{
	nvme_print(indent, name, -1,
	    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
	    "%02x%02x%02x%02x%02x%02x",
	    uuid[0], uuid[1], uuid[2], uuid[3],
	    uuid[4], uuid[5], uuid[6], uuid[7],
	    uuid[8], uuid[9], uuid[10], uuid[11],
	    uuid[12], uuid[13], uuid[14], uuid[15]);
}

/*
 * nvme_print_guid -- print a namespace GUID
 */
static void
nvme_print_guid(int indent, const char *name, const uint8_t *guid)
{
	nvme_print(indent, name, -1,
	    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	    guid[0], guid[1], guid[2], guid[3],
	    guid[4], guid[5], guid[6], guid[7],
	    guid[8], guid[9], guid[10], guid[11],
	    guid[12], guid[13], guid[14], guid[15]);
}

/*
 * nvme_print_eui64 -- print a namespace EUI64
 */
static void
nvme_print_eui64(int indent, const char *name, const uint8_t *eui64)
{
	nvme_print(indent, name, -1,
	    "%02X%02X%02X%02X%02X%02X%02X%02X",
	    eui64[0], eui64[1], eui64[2], eui64[3],
	    eui64[4], eui64[5], eui64[6], eui64[7]);
}

/*
 * nvme_print_version -- print a uint32_t encoded nvme version
 */
static void
nvme_print_version(int indent, const char *name, uint32_t value)
{
	nvme_reg_vs_t vers;

	vers.r = value;
	nvme_print(indent, name, -1, "%u.%u", vers.b.vs_mjr, vers.b.vs_mnr);
}

/*
 * nvme_print_ctrl_summary -- print a 1-line summary of the IDENTIFY CONTROLLER
 * data structure
 */
void
nvme_print_ctrl_summary(nvme_ctrl_info_t *info)
{
	nvme_uint128_t u128;
	char buf[64];

	const nvme_version_t *version = nvme_ctrl_info_version(info);

	(void) printf("model: %s, serial: %s, FW rev: %s, NVMe v%u.%u",
	    nvme_ctrl_info_model(info), nvme_ctrl_info_serial(info),
	    nvme_ctrl_info_fwrev(info), version->v_major, version->v_minor);

	/*
	 * This can fail because a device isn't at NVMe version 1.2 or it
	 * doesn't support namespace management.
	 */
	if (nvme_ctrl_info_cap(info, &u128)) {
		(void) nvme_snprint_uint128(buf, sizeof (buf), u128, 20, 0);
		(void) printf(", Capacity = %s MB", buf);
	}

	if (nvme_ctrl_info_unalloc_cap(info, &u128) && (u128.lo != 0 ||
	    u128.hi != 0)) {
		(void) nvme_snprint_uint128(buf, sizeof (buf), u128, 20, 0);
		(void) printf(", Unallocated = %s MB", buf);
	}

	(void) printf("\n");
}

/*
 * nvme_print_nsid_summary -- print a 1-line summary of the IDENTIFY NAMESPACE
 * data structure
 */
void
nvme_print_nsid_summary(nvme_ns_info_t *ns)
{
	const nvme_nvm_lba_fmt_t *fmt = NULL;
	const char *comma = "";
	uint64_t val;
	char numbuf[40];

	(void) nvme_ns_info_curformat(ns, &fmt);

	if (nvme_ns_info_size(ns, &val) && fmt != NULL) {
		nicenum_scale(val, nvme_nvm_lba_fmt_data_size(fmt), numbuf,
		    sizeof (numbuf), NN_UNIT_SPACE);
		(void) printf("Size = %sB", numbuf);
		comma = ", ";
	}

	if (nvme_ns_info_cap(ns, &val) && fmt != NULL) {
		nicenum_scale(val, nvme_nvm_lba_fmt_data_size(fmt), numbuf,
		    sizeof (numbuf), NN_UNIT_SPACE);
		(void) printf("%sCapacity = %sB", comma,  numbuf);
		comma = ", ";
	}

	if (nvme_ns_info_use(ns, &val) && fmt != NULL) {
		nicenum_scale(val, nvme_nvm_lba_fmt_data_size(fmt), numbuf,
		    sizeof (numbuf), NN_UNIT_SPACE);
		(void) printf("%sUsed = %sB", comma, numbuf);
	}
	(void) printf("\n");
}

/*
 * nvme_print_identify_ctrl
 *
 * This function pretty-prints the structure returned by the IDENTIFY CONTROLLER
 * command.
 */
void
nvme_print_identify_ctrl(const nvme_identify_ctrl_t *idctl, uint32_t mpsmin,
    const nvme_version_t *version)
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
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_mic.m_multi_pci, NULL, NULL);
	nvme_print_bit(6, "Multiple Controller Support",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_mic.m_multi_ctrl, NULL, NULL);
	nvme_print_bit(6, "Controller is an SR-IOV Virtual Function",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_mic.m_sr_iov, NULL, NULL);
	nvme_print_bit(6, "Asymmetric Namespace Access Reporting",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    idctl->id_mic.m_anar_sup, NULL, NULL);

	if (idctl->id_mdts > 0)
		nvme_print_uint64(4, "Maximum Data Transfer Size",
		    (1 << idctl->id_mdts) * mpsmin / 1024, NULL, "kB");
	else
		nvme_print_str(4, "Maximum Data Transfer Size", -1,
		    "unlimited", 0);

	if (nvme_vers_atleast(version, &nvme_vers_1v1)) {
		nvme_print_uint64(4, "Unique Controller Identifier",
		    idctl->id_cntlid, NULL, NULL);
	}

	if (nvme_vers_atleast(version, &nvme_vers_1v2)) {
		nvme_print_version(4, "NVMe Version",
		    idctl->id_ver);

		if (idctl->id_rtd3r != 0) {
			nvme_print_uint64(4, "RTD3 Resume Latency",
			    idctl->id_rtd3r, NULL, "us");
		}

		if (idctl->id_rtd3e != 0) {
			nvme_print_uint64(4, "RTD3 Entry Latency",
			    idctl->id_rtd3e, NULL, "us");
		}
	}

	if (verbose) {
		nvme_print(4, "Optional Asynchronous Events Supported", -1,
		    NULL);
		nvme_print_bit(6, "Namespace Attribute Notices",
		    nvme_vers_atleast(version, &nvme_vers_1v2),
		    idctl->id_oaes.oaes_nsan, NULL, NULL);
		nvme_print_bit(6, "Firmware Activation Notices",
		    nvme_vers_atleast(version, &nvme_vers_1v2),
		    idctl->id_oaes.oaes_fwact, NULL, NULL);
		nvme_print_bit(6, "Asynchronous Namespace Access Change "
		    "Notices",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_oaes.oaes_ansacn, NULL, NULL);
		nvme_print_bit(6, "Predictable Latency Event Aggregation",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_oaes.oaes_plat, NULL, NULL);
		nvme_print_bit(6, "LBA Status Information Notices",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_oaes.oaes_lbasi, NULL, NULL);
		nvme_print_bit(6, "Endurance Group Event Aggregate Log Page "
		    "Change Notices",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_oaes.oaes_egeal, NULL, NULL);

		nvme_print(4, "Controller Attributes", -1,
		    NULL);
		nvme_print_bit(6, "128-bit Host Identifier",
		    nvme_vers_atleast(version, &nvme_vers_1v2),
		    idctl->id_ctratt.ctrat_hid, NULL, NULL);
		nvme_print_bit(6, "Non-Operational Power State Permissive Mode",
		    nvme_vers_atleast(version, &nvme_vers_1v3),
		    idctl->id_ctratt.ctrat_nops, NULL, NULL);
		nvme_print_bit(6, "NVM Sets",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_ctratt.ctrat_nvmset, NULL, NULL);
		nvme_print_bit(6, "Read Recovery Levels",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_ctratt.ctrat_rrl, NULL, NULL);
		nvme_print_bit(6, "Endurance Groups",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_ctratt.ctrat_engrp, NULL, NULL);
		nvme_print_bit(6, "Predictable Latency Mode",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_ctratt.ctrat_plm, NULL, NULL);
		nvme_print_bit(6, "Traffic Based Keep Alive",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_ctratt.ctrat_tbkas, NULL, NULL);
		nvme_print_bit(6, "Namespace Granularity",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_ctratt.ctrat_nsg, NULL, NULL);
		nvme_print_bit(6, "SQ Associations",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_ctratt.ctrat_sqass, NULL, NULL);
		nvme_print_bit(6, "UUID List",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_ctratt.ctrat_uuid, NULL, NULL);

		nvme_print(4, "Read Recovery Levels", -1,
		    NULL);
		nvme_print_bit(6, "Read Recovery Level 0",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 0), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 1",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 1), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 2",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 2), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 3",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 3), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 4 - Default",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 4), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 5",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 5), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 6",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 6), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 7",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 7), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 8",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 8), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 9",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 9), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 10",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 10), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 11",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 11), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 12",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 12), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 13",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 13), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 14",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 14), NULL, NULL);
		nvme_print_bit(6, "Read Recovery Level 15 - Fast Fail",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_rrls & (1 << 15), NULL, NULL);
	}

	if (nvme_vers_atleast(version, &nvme_vers_1v4)) {
		switch (idctl->id_cntrltype) {
		case NVME_CNTRLTYPE_RSVD:
			nvme_print_str(4, "Controller Type", -1,
			    "not reported", 0);
			break;
		case NVME_CNTRLTYPE_IO:
			nvme_print_str(4, "Controller Type", -1, "I/O", 0);
			break;
		case NVME_CNTRLTYPE_DISC:
			nvme_print_str(4, "Controller Type", -1, "discovery",
			    0);
			break;
		case NVME_CNTRLTYPE_ADMIN:
			nvme_print_str(4, "Controller Type", -1,
			    "administrative", 0);
			break;
		default:
			nvme_print(4, "Controller Type", -1,
			    "unknown reserved value: %u", idctl->id_cntrltype);
			break;
		}
	} else {
		nvme_print_str(4, "Controller Type", -1, "not reported", 0);
	}

	if (nvme_vers_atleast(version, &nvme_vers_1v3)) {
		uint8_t zguid[16] = { 0 };

		if (memcmp(zguid, idctl->id_frguid, sizeof (zguid)) != 0) {
			nvme_print_guid(4, "FRU GUID", idctl->id_frguid);
		} else {
			nvme_print_str(4, "FRU GUID", -1, "unsupported", 0);
		}
	} else {
		nvme_print_str(4, "FRU GUID", -1, "unsupported", 0);
	}

	if (nvme_vers_atleast(version, &nvme_vers_1v4)) {
		nvme_print_uint64(4, "Command Retry Delay Time 1",
		    idctl->id_crdt1 * 100, NULL, "ms");
		nvme_print_uint64(4, "Command Retry Delay Time 2",
		    idctl->id_crdt2 * 100, NULL, "ms");
		nvme_print_uint64(4, "Command Retry Delay Time 3",
		    idctl->id_crdt3 * 100, NULL, "ms");
	} else {
		nvme_print_str(4, "Command Retry Delay Time 1", -1,
		    "unsupported", 0);
		nvme_print_str(4, "Command Retry Delay Time 2", -1,
		    "unsupported", 0);
		nvme_print_str(4, "Command Retry Delay Time 3", -1,
		    "unsupported", 0);
	}

	/*
	 * The NVMe-MI spec claimed a portion of the identify controller data;
	 * however, there's no way to actually figure out if this data is valid
	 * or not. We basically have to rely on the NVMe spec's initialized to
	 * zero behavior for this region. Unfortunately, there's no way to get
	 * the NVMe-MI version to know when fields were added here so we
	 * basically treat the minimum version required as that of when the
	 * NVMe-MI region was reserved in the NVMe spec, which is 1.2. Note,
	 * these bytes go in reverse order because they're allocating them in
	 * reverse order.
	 */
	if (verbose) {
		nvme_print(2, "NVMe Management Interface", -1, NULL);
		nvme_print(4, "Management Endpoint Capabilities", -1, NULL);
		nvme_print_bit(6, "SMBus/I2C Port Management Endpoint",
		    nvme_vers_atleast(version, &nvme_vers_1v2),
		    idctl->id_mec.mec_smbusme, NULL, NULL);
		nvme_print_bit(6, "PCIe Port Management Endpoint",
		    nvme_vers_atleast(version, &nvme_vers_1v2),
		    idctl->id_mec.mec_pcieme, NULL, NULL);

		if (idctl->id_vpdwc.vwci_valid != 0) {
			nvme_print_uint64(4, "VPD Write Cycles Remaining",
			    idctl->id_vpdwc.vwci_crem, NULL, NULL);
		} else {
			nvme_print_str(4, "VPD Write Cycles Remaining", -1,
			    "invalid or unsupported", 0);
		}

		if (idctl->id_nvmsr.nvmsr_nvmesd == 0 &&
		    idctl->id_nvmsr.nvmsr_nvmee == 0 &&
		    idctl->id_nvmsr.nvmsr_rsvd == 0) {
			nvme_print_str(4, "NVM Subsystem Report", -1,
			    "unsupported", 0);
		} else {
			nvme_print(4, "NVM Subsystem Report", -1, NULL);
			nvme_print_bit(6, "NVMe Storage Device",
			    nvme_vers_atleast(version, &nvme_vers_1v2),
			    idctl->id_nvmsr.nvmsr_nvmesd, NULL, NULL);
			nvme_print_bit(6, "NVMe Enclosure",
			    nvme_vers_atleast(version, &nvme_vers_1v2),
			    idctl->id_nvmsr.nvmsr_nvmee, NULL, NULL);
		}
	}

	nvme_print(2, "Admin Command Set Attributes", -1, NULL);
	nvme_print(4, "Optional Admin Command Support", -1, NULL);
	nvme_print_bit(6, "Security Send & Receive",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_oacs.oa_security, NULL, NULL);
	nvme_print_bit(6, "Format NVM",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_oacs.oa_format, NULL, NULL);
	nvme_print_bit(6, "Firmware Activate & Download",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_oacs.oa_firmware, NULL, NULL);
	nvme_print_bit(6, "Namespace Management",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idctl->id_oacs.oa_nsmgmt, NULL, NULL);
	nvme_print_bit(6, "Device Self-test",
	    nvme_vers_atleast(version, &nvme_vers_1v3),
	    idctl->id_oacs.oa_selftest, NULL, NULL);
	nvme_print_bit(6, "Directives",
	    nvme_vers_atleast(version, &nvme_vers_1v3),
	    idctl->id_oacs.oa_direct, NULL, NULL);
	nvme_print_bit(6, "NVME-MI Send and Receive",
	    nvme_vers_atleast(version, &nvme_vers_1v3),
	    idctl->id_oacs.oa_nvmemi, NULL, NULL);
	nvme_print_bit(6, "Virtualization Management",
	    nvme_vers_atleast(version, &nvme_vers_1v3),
	    idctl->id_oacs.oa_virtmgmt, NULL, NULL);
	nvme_print_bit(6, "Doorbell Buffer Config",
	    nvme_vers_atleast(version, &nvme_vers_1v3),
	    idctl->id_oacs.oa_doorbell, NULL, NULL);
	nvme_print_bit(6, "Get LBA Status",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    idctl->id_oacs.oa_lbastat, NULL, NULL);
	if (verbose) {
		nvme_print_uint64(4, "Abort Command Limit",
		    (uint16_t)idctl->id_acl + 1, NULL, NULL);
		nvme_print_uint64(4, "Asynchronous Event Request Limit",
		    (uint16_t)idctl->id_aerl + 1, NULL, NULL);
	}
	nvme_print(4, "Firmware Updates", -1, NULL);
	nvme_print_bit(6, "Firmware Slot 1",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_frmw.fw_readonly, "read-only", "writable");
	nvme_print_uint64(6, "No. of Firmware Slots",
	    idctl->id_frmw.fw_nslot, NULL, NULL);
	nvme_print_bit(6, "Activate Without Reset",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idctl->id_frmw.fw_norst, NULL, NULL);

	nvme_print(2, "Log Page Attributes", -1, NULL);
	nvme_print_bit(6, "Per Namespace SMART/Health info",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_lpa.lp_smart, NULL, NULL);
	nvme_print_bit(6, "Commands Supported and Effects",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idctl->id_lpa.lp_cmdeff, NULL, NULL);
	nvme_print_bit(6, "Get Log Page Extended Data",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idctl->id_lpa.lp_extsup, NULL, NULL);
	nvme_print_bit(6, "Telemetry Log Pages",
	    nvme_vers_atleast(version, &nvme_vers_1v3),
	    idctl->id_lpa.lp_telemetry, NULL, NULL);
	nvme_print_bit(6, "Persistent Event Log",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    idctl->id_lpa.lp_persist, NULL, NULL);

	nvme_print_uint64(4, "Error Log Page Entries",
	    (uint16_t)idctl->id_elpe + 1, NULL, NULL);
	nvme_print_uint64(4, "Number of Power States",
	    (uint16_t)idctl->id_npss + 1, NULL, NULL);
	if (verbose) {
		nvme_print_bit(4, "Admin Vendor-specific Command Format",
		    nvme_vers_atleast(version, &nvme_vers_1v0),
		    idctl->id_avscc.av_spec, "standard", "vendor-specific");
	}

	nvme_print_bit(4, "Autonomous Power State Transitions",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idctl->id_apsta.ap_sup, NULL, NULL);

	if (nvme_vers_atleast(version, &nvme_vers_1v2)) {
		nvme_print_temp(4, "Warning Composite Temperature Threshold",
		    idctl->ap_wctemp);
		nvme_print_temp(4, "Critical Composite Temperature Threshold",
		    idctl->ap_cctemp);
	} else {
		nvme_print_str(4, "Warning Composite Temperature Threshold",
		    -1, "unspecified", 0);
		nvme_print_str(4, "Critical Composite Temperature Threshold",
		    -1, "unspecified", 0);
	}

	if (verbose) {
		if (idctl->ap_mtfa != 0) {
			nvme_print_uint64(4, "Maximum Firmware Activation Time",
			    idctl->ap_mtfa * 100, NULL, "ms");
		} else {
			nvme_print_str(4, "Maximum Firmware Activation Time",
			    -1, "unknown", 0);
		}

		if (idctl->ap_hmpre != 0) {
			nvme_print_uint64(4, "Host Memory Buffer Preferred "
			    "Size", idctl->ap_hmpre * 4, NULL, "KiB");
		} else {
			nvme_print_str(4, "Host Memory Buffer Preferred "
			    "Size", -1, "unsupported", 0);
		}

		if (idctl->ap_hmmin != 0) {
			nvme_print_uint64(4, "Host Memory Buffer Minimum Size",
			    idctl->ap_hmmin * 4, NULL, "KiB");
		} else {
			nvme_print_str(4, "Host Memory Buffer Minimum Size",
			    -1, "unsupported", 0);
		}
	}

	if (idctl->id_oacs.oa_nsmgmt != 0) {
		nvme_print_uint128(4, "Total NVM Capacity",
		    idctl->ap_tnvmcap, "B", 0, 0);
		nvme_print_uint128(4, "Unallocated NVM Capacity",
		    idctl->ap_unvmcap, "B", 0, 0);
	} else if (verbose) {
		nvme_print_str(4, "Total NVM Capacity", -1,
		    "unsupported", 0);
		nvme_print_str(4, "Unallocated NVM Capacity", -1,
		    "unsupported", 0);
	}

	if (verbose) {
		if (idctl->ap_rpmbs.rpmbs_units != 0) {
			nvme_print(4, "Replay Protected Memory Block", -1,
			    NULL);
			nvme_print_uint64(6, "Number of RPMB Units",
			    idctl->ap_rpmbs.rpmbs_units, NULL, NULL);
			switch (idctl->ap_rpmbs.rpmbs_auth) {
			case NVME_RPMBS_AUTH_HMAC_SHA256:
				nvme_print_str(6, "Authentication Method", -1,
				    "HMAC SHA-256", 0);
				break;
			default:
				nvme_print(6, "Authentication Method", -1,
				    "unknown reserved value: %u",
				    idctl->ap_rpmbs.rpmbs_auth);
				break;
			}
			nvme_print_uint64(6, "Total Size",
			    (idctl->ap_rpmbs.rpmbs_tot + 1) * 128, NULL, "KiB");
			nvme_print_uint64(6, "Access Size",
			    (idctl->ap_rpmbs.rpmbs_acc + 1) * 512, NULL, "KiB");
		} else {
			nvme_print_str(4, "Replay Protected Memory Block", -1,
			    "unsupported", 0);
		}

		if (idctl->id_oacs.oa_selftest != 0) {
			nvme_print_uint64(4, "Extended Device Self-test Time",
			    idctl->ap_edstt, NULL, "min");
			nvme_print(4, "Device Self-test Options", -1, NULL);
			nvme_print_bit(6, "Self-test operation granularity",
			    nvme_vers_atleast(version, &nvme_vers_1v3),
			    idctl->ap_dsto.dsto_sub, "subsystem", "controller");
		} else {
			nvme_print_str(4, "Extended Device Self-test Time", -1,
			    "unsupported", 0);
			nvme_print_str(4, "Device Self-test Options", -1,
			    "unsupported", 0);
		}
	}

	switch (idctl->ap_fwug) {
	case 0x00:
		nvme_print_str(4, "Firmware Update Granularity", -1, "unknown",
		    0);
		break;
	case 0xff:
		nvme_print_str(4, "Firmware Update Granularity", -1,
		    "unrestricted", 0);
		break;
	default:
		nvme_print_uint64(4, "Firmware Update Granularity",
		    idctl->ap_fwug * 4, NULL, "KiB");
		break;
	}

	if (verbose) {
		if (idctl->ap_kas != 0) {
			nvme_print_uint64(4, "Keep Alive Support",
			    idctl->ap_kas * 100, NULL, "ms");
		} else {
			nvme_print_str(4, "Keep Alive Support", -1,
			    "unsupported", 0);
		}

		nvme_print(4, "Host Controlled Thermal Management Attributes",
		    -1, NULL);
		nvme_print_bit(6, "Host Controlled Thermal Management",
		    nvme_vers_atleast(version, &nvme_vers_1v3),
		    idctl->ap_hctma.hctma_hctm, NULL, NULL);
		if (idctl->ap_mntmt != 0 && nvme_vers_atleast(version,
		    &nvme_vers_1v3)) {
			nvme_print_temp(6, "Minimum Thermal Management "
			    "Temperature", idctl->ap_mntmt);
		} else {
			nvme_print_str(6, "Minimum Thermal Management "
			    "Temperature", -1, "unsupported", -1);
		}

		if (idctl->ap_mxtmt != 0 && nvme_vers_atleast(version,
		    &nvme_vers_1v3)) {
			nvme_print_temp(6, "Maximum Thermal Management "
			    "Temperature", idctl->ap_mxtmt);
		} else {
			nvme_print_str(6, "Maximum Thermal Management "
			    "Temperature", -1, "unsupported", -1);
		}

		nvme_print(4, "Sanitize Capabilities", -1, NULL);
		nvme_print_bit(6, "Crypto Erase Support",
		    nvme_vers_atleast(version, &nvme_vers_1v3),
		    idctl->ap_sanitize.san_ces, NULL, NULL);
		nvme_print_bit(6, "Block Erase Support",
		    nvme_vers_atleast(version, &nvme_vers_1v3),
		    idctl->ap_sanitize.san_bes, NULL, NULL);
		nvme_print_bit(6, "Overwrite Support",
		    nvme_vers_atleast(version, &nvme_vers_1v3),
		    idctl->ap_sanitize.san_ows, NULL, NULL);
		nvme_print_bit(6, "No-Deallocate Inhibited",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->ap_sanitize.san_ndi, NULL, NULL);
		if (nvme_vers_atleast(version, &nvme_vers_1v4)) {
			uint_t val = idctl->ap_sanitize.san_nodmmas;
			switch (val) {
			case NVME_NODMMAS_UNDEF:
				nvme_print_str(6, "No-Deallocate Modifies "
				    "Media after Sanitize", -1,
				    "undefined", 0);
				break;
			case NVME_NODMMAS_NOMOD:
				nvme_print_str(6, "No-Deallocate Modifies "
				    "Media after Sanitize", -1,
				    "no modification", 0);
				break;
			case NVME_NODMMAS_DOMOD:
				nvme_print_str(6, "No-Deallocate Modifies "
				    "Media after Sanitize", -1,
				    "modification required", 0);
				break;
			default:
				nvme_print(6, "No-Deallocate Modifies "
				    "Media after Sanitize", -1,
				    "unknown reserved value: %u", val);
				break;
			}
		} else {
			nvme_print_str(6, "No-Deallocate Modifies Media after "
			    "Sanitize", -1, "undefined", 0);
		}

		if (idctl->ap_hmminds != 0) {
			nvme_print_uint64(4, "Host Memory Buffer Minimum "
			    "Descriptor Entry Size", idctl->ap_hmminds * 4,
			    NULL, "KiB");
		} else {
			nvme_print_str(4, "Host Memory Buffer Minimum "
			    "Descriptor Entry Size", -1, "unsupported", 0);
		}

		if (idctl->ap_hmmaxd != 0) {
			nvme_print_uint64(4, "Host Memory Buffer Maximum "
			    "Descriptor Entries", idctl->ap_hmmaxd,
			    NULL, NULL);
		} else {
			nvme_print_str(4, "Host Memory Buffer Maximum "
			    "Descriptor Entries", -1, "unsupported", 0);
		}

		if (idctl->id_ctratt.ctrat_engrp != 0) {
			nvme_print_uint64(4, "Max Endurance Group Identifier",
			    idctl->ap_engidmax, NULL, NULL);
		} else {
			nvme_print_str(4, "Max Endurance Group Identifier",
			    -1, "unsupported", 0);
		}

		if (idctl->id_mic.m_anar_sup != 0) {
			nvme_print_uint64(4, "ANA Transition Time",
			    idctl->ap_anatt, NULL, "secs");
		} else {
			nvme_print_str(4, "ANA Transition Time", -1,
			    "unsupported", 0);
		}

		nvme_print(4, "Asymmetric Namespace Access Capabilities",
		    -1, NULL);
		nvme_print_bit(6, "ANA Optimized state",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->ap_anacap.anacap_opt, NULL, NULL);
		nvme_print_bit(6, "ANA Non-Optimized state",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->ap_anacap.anacap_unopt, NULL, NULL);
		nvme_print_bit(6, "ANA Inaccessible state",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->ap_anacap.anacap_inacc, NULL, NULL);
		nvme_print_bit(6, "ANA Persistent Loss state",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->ap_anacap.anacap_ploss, NULL, NULL);
		nvme_print_bit(6, "ANA Persistent Change state",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->ap_anacap.anacap_chg, NULL, NULL);
		nvme_print_bit(6, "ANAGRPID doesn't change with attached NS",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->ap_anacap.anacap_grpns, "yes", "no");
		nvme_print_bit(6, "Non-zero ANAGRPID in Namespace Management",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->ap_anacap.anacap_grpid, NULL, NULL);

		if (idctl->id_mic.m_anar_sup != 0) {
			nvme_print_uint64(4, "Max ANA Group Identifier",
			    idctl->ap_anagrpmax, NULL, NULL);
			nvme_print_uint64(4, "Number of ANA Group Identifiers",
			    idctl->ap_nanagrpid, NULL, NULL);
		} else {
			nvme_print_str(4, "Max ANA Group Identifier",
			    -1, "unsupported", 0);
			nvme_print_str(4, "Number of ANA Group Identifiers",
			    -1, "unsupported", 0);
		}

		if (idctl->id_lpa.lp_persist != 0) {
			nvme_print_uint64(4, "Persistent Event Log Size",
			    idctl->ap_pels * 64, NULL, "KiB");
		} else {
			nvme_print_str(4, "Persistent Event Log Size",
			    -1, "unsupported", 0);
		}
	}


	nvme_print(2, "NVM Command Set Attributes", -1, NULL);
	if (verbose) {
		nvme_print(4, "Submission Queue Entry Size", -1,
		    "min %d, max %d",
		    1 << idctl->id_sqes.qes_min, 1 << idctl->id_sqes.qes_max);
		nvme_print(4, "Completion Queue Entry Size", -1,
		    "min %d, max %d",
		    1 << idctl->id_cqes.qes_min, 1 << idctl->id_cqes.qes_max);

		if (nvme_vers_atleast(version, &nvme_vers_1v2)) {
			nvme_print_uint64(4, "Maximum Outstanding Commands",
			    idctl->id_maxcmd, NULL, NULL);
		} else {
			nvme_print_str(4, "Maximum Outstanding Commands",
			    -1, "unknown", 0);
		}
	}
	nvme_print_uint64(4, "Number of Namespaces",
	    idctl->id_nn, NULL, NULL);
	nvme_print(4, "Optional NVM Command Support", -1, NULL);
	nvme_print_bit(6, "Compare",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_oncs.on_compare, NULL, NULL);
	nvme_print_bit(6, "Write Uncorrectable",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_oncs.on_wr_unc, NULL, NULL);
	nvme_print_bit(6, "Dataset Management",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_oncs.on_dset_mgmt, NULL, NULL);
	nvme_print_bit(6, "Write Zeros",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idctl->id_oncs.on_wr_zero, NULL, NULL);
	nvme_print_bit(6, "Save/Select in Get/Set Features",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idctl->id_oncs.on_save, NULL, NULL);
	nvme_print_bit(6, "Reservations",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idctl->id_oncs.on_reserve, NULL, NULL);
	nvme_print_bit(6, "Timestamp Feature",
	    nvme_vers_atleast(version, &nvme_vers_1v3),
	    idctl->id_oncs.on_ts, NULL, NULL);
	nvme_print_bit(6, "Verify",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    idctl->id_oncs.on_verify, NULL, NULL);

	nvme_print(4, "Fused Operation Support", -1, NULL);
	nvme_print_bit(6, "Compare and Write",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_fuses.f_cmp_wr, NULL, NULL);
	nvme_print(4, "Format NVM Attributes", -1, NULL);
	nvme_print_bit(6, "Per Namespace Format",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_fna.fn_format == 0, NULL, NULL);
	nvme_print_bit(6, "Per Namespace Secure Erase",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_fna.fn_sec_erase == 0, NULL, NULL);
	nvme_print_bit(6, "Cryptographic Erase",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_fna.fn_crypt_erase, NULL, NULL);
	nvme_print(4, "Volatile Write Cache", -1, NULL);
	nvme_print_bit(6, "Present",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idctl->id_vwc.vwc_present, "yes", "no");
	if (verbose) {
		switch (idctl->id_vwc.vwc_nsflush) {
		case NVME_VWCNS_UNKNOWN:
			nvme_print_str(6, "Flush with NSID 0xFFFFFFFF",
			    -1, "unknown", 0);
			break;
		case NVME_VWCNS_UNSUP:
			nvme_print_str(6, "Flush with NSID 0xFFFFFFFF",
			    -1, "unsupported", 0);
			break;
		case NVME_VWCNS_SUP:
			nvme_print_str(6, "Flush with NSID 0xFFFFFFFF",
			    -1, "supported", 0);
			break;
		default:
			nvme_print(6, "Flush with NSID 0xFFFFFFFF",
			    -1, "unknown reserved value: %u",
			    idctl->id_vwc.vwc_nsflush);
			break;
		}
	}
	nvme_print_uint64(4, "Atomic Write Unit Normal",
	    (uint32_t)idctl->id_awun + 1, NULL,
	    idctl->id_awun == 0 ? " block" : " blocks");
	nvme_print_uint64(4, "Atomic Write Unit Power Fail",
	    (uint32_t)idctl->id_awupf + 1, NULL,
	    idctl->id_awupf == 0 ? " block" : " blocks");

	if (verbose != 0) {
		nvme_print_bit(4, "NVM Vendor-specific Command Format",
		    nvme_vers_atleast(version, &nvme_vers_1v0),
		    idctl->id_nvscc.nv_spec, "standard", "vendor-specific");

		nvme_print(4, "Namespace Write Protection Capabilities",
		    -1, NULL);
		nvme_print_bit(6, "Core Support",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_nwpc.nwpc_base, NULL, NULL);
		nvme_print_bit(6, "Write Protect Until Power Cycle",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_nwpc.nwpc_wpupc, NULL, NULL);
		nvme_print_bit(6, "Permanent Write Protect",
		    nvme_vers_atleast(version, &nvme_vers_1v4),
		    idctl->id_nwpc.nwpc_permwp, NULL, NULL);
	}

	if (idctl->id_fuses.f_cmp_wr && nvme_vers_atleast(version,
	    &nvme_vers_1v1)) {
		nvme_print_uint64(4, "Atomic Compare & Write Size",
		    (uint32_t)idctl->id_acwu + 1, NULL,
		    idctl->id_acwu == 0 ? " block" : " blocks");
	} else {
		nvme_print_str(4, "Atomic Compare & Write Size", -1,
		    "unsupported", 0);
	}

	nvme_print(4, "SGL Support", -1, NULL);
	switch (idctl->id_sgls.sgl_sup) {
	case NVME_SGL_UNSUP:
		nvme_print_str(6, "Command Set", -1, "unsupported", 0);
		break;
	case NVME_SGL_SUP_UNALIGN:
		nvme_print_str(6, "Command Set", -1, "supported, "
		    "no restrictions", 0);
		break;
	case NVME_SGL_SUP_ALIGN:
		nvme_print_str(6, "Command Set", -1, "supported, "
		    "alignment restrictions", 0);
		break;
	default:
		nvme_print(6, "Command Set", -1, "unknown reserved value: %u",
		    idctl->id_sgls.sgl_sup);
		break;
	}
	nvme_print_bit(6, "Keyed SGL Block Descriptor",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idctl->id_sgls.sgl_keyed, NULL, NULL);
	nvme_print_bit(6, "SGL Bit Bucket Descriptor",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idctl->id_sgls.sgl_bucket, NULL, NULL);
	nvme_print_bit(6, "Byte Aligned Contiguous Metadata",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idctl->id_sgls.sgl_balign, NULL, NULL);
	nvme_print_bit(6, "SGL Longer than Data Transferred",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idctl->id_sgls.sgl_sglgtd, NULL, NULL);
	nvme_print_bit(6, "MPTR with SGL",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idctl->id_sgls.sgl_mptr, NULL, NULL);
	nvme_print_bit(6, "SGL Address as Offset",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idctl->id_sgls.sgl_offset, NULL, NULL);
	nvme_print_bit(6, "Transport SGL Data Block",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    idctl->id_sgls.sgl_tport, NULL, NULL);
	if (verbose) {
		if (idctl->id_mnan != 0) {
			nvme_print_uint64(4, "Maximum Number of Allowed "
			    "Namespaces", idctl->id_mnan, NULL, NULL);
		} else {
			nvme_print(4, "Maximum Number of Allowed "
			    "Namespaces", -1, "at most %u", idctl->id_nn);
		}
	}

	if (nvme_vers_atleast(version, &nvme_vers_1v2) &&
	    idctl->id_subnqn[0] != '\0') {
		nvme_print_str(4, "NVMe Subsystem Qualified Name", -1,
		    (char *)idctl->id_subnqn, sizeof (idctl->id_subnqn));
	} else {
		nvme_print_str(4, "NVMe Subsystem Qualified Name", -1,
		    "unknown", 0);
	}

	for (i = 0; i != idctl->id_npss + 1; i++) {
		double scale = 0.01;
		double power = 0;
		int places = 2;
		char *unit = "W";

		if (nvme_vers_atleast(version, &nvme_vers_1v1) &&
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
		    nvme_vers_atleast(version, &nvme_vers_1v1),
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
nvme_print_identify_nsid(const nvme_identify_nsid_t *idns,
    const nvme_version_t *version)
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
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_nsfeat.f_thin, NULL, NULL);
	nvme_print_bit(6, "Namespace-specific Atomic Units",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idns->id_nsfeat.f_nsabp, NULL, NULL);
	nvme_print_bit(6, "Deallocate errors",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idns->id_nsfeat.f_dae, NULL, NULL);
	nvme_print_bit(6, "Namespace GUID Reuse",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    idns->id_nsfeat.f_uidreuse, "impossible", "possible");
	nvme_print_bit(6, "Namespace-specific I/O Optimized Sizes",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    idns->id_nsfeat.f_optperf, NULL, NULL);

	nvme_print_uint64(4, "Number of LBA Formats",
	    (uint16_t)idns->id_nlbaf + 1, NULL, NULL);
	nvme_print(4, "Formatted LBA Size", -1, NULL);
	nvme_print_uint64(6, "LBA Format",
	    (uint16_t)idns->id_flbas.lba_format, NULL, NULL);
	nvme_print_bit(6, "Extended Data LBA",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_flbas.lba_extlba, "yes", "no");

	nvme_print(4, "Metadata Capabilities", -1, NULL);
	nvme_print_bit(6, "Extended Data LBA",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_mc.mc_extlba, NULL, NULL);
	nvme_print_bit(6, "Separate Metadata",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_mc.mc_separate, NULL, NULL);

	nvme_print(4, "End-to-End Data Protection Capabilities", -1, NULL);
	nvme_print_bit(6, "Protection Information Type 1",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_dpc.dp_type1, NULL, NULL);
	nvme_print_bit(6, "Protection Information Type 2",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_dpc.dp_type2, NULL, NULL);
	nvme_print_bit(6, "Protection Information Type 3",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_dpc.dp_type3, NULL, NULL);
	nvme_print_bit(6, "Protection Information first",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_dpc.dp_first, NULL, NULL);
	nvme_print_bit(6, "Protection Information last",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_dpc.dp_last, NULL, NULL);
	nvme_print(4, "End-to-End Data Protection Settings", -1, NULL);
	if (idns->id_dps.dp_pinfo == 0) {
		nvme_print_str(6, "Protection Information", -1,
		    "disabled", 0);
	} else {
		nvme_print_uint64(6, "Protection Information Type",
		    idns->id_dps.dp_pinfo, NULL, NULL);
	}
	nvme_print_bit(6, "Protection Information in Metadata",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    idns->id_dps.dp_first, "first 8 bytes", "last 8 bytes");

	nvme_print(4, "Namespace Multi-Path I/O and Namespace Sharing "
	    "Capabilities", -1, NULL);

	nvme_print_bit(6, "Namespace is shared",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idns->id_nmic.nm_shared, "yes", "no");
	nvme_print(2, "Reservation Capabilities", -1, NULL);
	nvme_print_bit(6, "Persist Through Power Loss",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idns->id_rescap.rc_persist, NULL, NULL);
	nvme_print_bit(6, "Write Exclusive",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idns->id_rescap.rc_wr_excl, NULL, NULL);
	nvme_print_bit(6, "Exclusive Access",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idns->id_rescap.rc_excl, NULL, NULL);
	nvme_print_bit(6, "Write Exclusive - Registrants Only",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idns->id_rescap.rc_wr_excl_r, NULL, NULL);
	nvme_print_bit(6, "Exclusive Access - Registrants Only",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idns->id_rescap.rc_excl_r, NULL, NULL);
	nvme_print_bit(6, "Write Exclusive - All Registrants",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idns->id_rescap.rc_wr_excl_a, NULL, NULL);
	nvme_print_bit(6, "Exclusive Access - All Registrants",
	    nvme_vers_atleast(version, &nvme_vers_1v1),
	    idns->id_rescap.rc_excl_a, NULL, NULL);
	nvme_print_bit(6, "Ignore Existing Key Behavior",
	    nvme_vers_atleast(version, &nvme_vers_1v3),
	    idns->id_rescap.rc_ign_ekey, "NVMe 1.3 behavior", "pre-NVMe 1.3");

	if (idns->id_fpi.fpi_sup != 0) {
		nvme_print_uint64(4, "NVM Format Remaining",
		    idns->id_fpi.fpi_remp, NULL, "%");
	} else {
		nvme_print_str(4, "NVM Format Remaining", -1, "unsupported", 0);
	}

	if (verbose) {
		if (idns->id_nawun != 0) {
			nvme_print_uint64(4, "Namespace Atomic Write Unit "
			    "Normal", idns->id_nawun + 1, NULL, " blocks");
		} else {
			nvme_print_str(4, "Namespace Atomic Write Unit "
			    "Normal", -1, "unspecified", 0);
		}

		if (idns->id_nawupf != 0) {
			nvme_print_uint64(4, "Namespace Atomic Write Unit "
			    "Power Fail", idns->id_nawupf + 1, NULL, " blocks");
		} else {
			nvme_print_str(4, "Namespace Atomic Write Unit "
			    "Power Fail", -1, "unspecified", 0);
		}

		if (idns->id_nacwu != 0) {
			nvme_print_uint64(4, "Namespace Atomic Compare & Write "
			    "Unit", idns->id_nacwu + 1, NULL, " blocks");
		} else {
			nvme_print_str(4, "Namespace Atomic Compare & Write "
			    "Unit", -1, "unspecified", 0);
		}

		if (idns->id_nabsn != 0) {
			nvme_print_uint64(4, "Namespace Atomic Boundary Size "
			    "Normal", idns->id_nabsn + 1, NULL, " blocks");
		} else {
			nvme_print_str(4, "Namespace Atomic Boundary Size "
			    "Normal", -1, "unspecified", 0);
		}

		if (idns->id_nbao != 0) {
			nvme_print(4, "Namespace Atomic Boundary Offset", -1,
			    "LBA %u", idns->id_nbao);
		} else {
			nvme_print_str(4, "Namespace Atomic Boundary Offset",
			    -1, "unspecified", 0);
		}

		if (idns->id_nabspf != 0) {
			nvme_print_uint64(4, "Namespace Atomic Boundary Size "
			    "Power Fail", idns->id_nabspf + 1, NULL,
			    idns->id_nabspf == 0 ? " block" : " blocks");
		} else {
			nvme_print_str(4, "Namespace Atomic Boundary Size "
			    "Power Fail", -1, "unspecified", 0);
		}

		if (idns->id_noiob != 0) {
			nvme_print_uint64(4, "Namespace Optional I/O Boundary",
			    idns->id_noiob, NULL,
			    idns->id_noiob == 1 ? " block" : " blocks");
		} else {
			nvme_print_str(4, "Namespace Optimal I/O Boundary",
			    -1, "unspecified", 0);
		}
	}

	if (idns->id_nvmcap.lo != 0 || idns->id_nvmcap.hi != 0) {
		nvme_print_uint128(4, "NVM Capacity", idns->id_nvmcap,
		    "B", 0, 0);
	} else {
		nvme_print_str(4, "NVM Capacity", -1, "unknown", 0);
	}

	if (verbose) {
		if (idns->id_npwg != 0) {
			nvme_print_uint64(4, "Namespace Preferred Write "
			    "Granularity", idns->id_npwg + 1, NULL, " blocks");
		} else {
			nvme_print_str(4, "Namespace Preferred Write "
			    "Granularity", -1, "unspecified", 0);
		}

		if (idns->id_npwa != 0) {
			nvme_print_uint64(4, "Namespace Preferred Write "
			    "Alignment", idns->id_npwa + 1, NULL, " blocks");
		} else {
			nvme_print_str(4, "Namespace Preferred Write "
			    "Alignment", -1, "unspecified", 0);
		}

		if (idns->id_npdg != 0) {
			nvme_print_uint64(4, "Namespace Preferred Deallocate "
			    "Granularity", idns->id_npdg + 1, NULL, " blocks");
		} else {
			nvme_print_str(4, "Namespace Preferred Deallocate "
			    "Granularity", -1, "unspecified", 0);
		}

		if (idns->id_npda != 0) {
			nvme_print_uint64(4, "Namespace Preferred Deallocate "
			    "Alignment", idns->id_npda + 1, NULL, " blocks");
		} else {
			nvme_print_str(4, "Namespace Preferred Deallocate "
			    "Alignment", -1, "unspecified", 0);
		}

		if (idns->id_nows != 0) {
			nvme_print_uint64(4, "Namespace Optimal Write Size",
			    idns->id_nows + 1, NULL, " blocks");
		} else {
			nvme_print_str(4, "Namespace Optimal Write Size",
			    -1, "unspecified", 0);
		}

		if (idns->id_anagrpid != 0) {
			nvme_print_uint64(4, "Namespace ANA Group Identifier",
			    idns->id_anagrpid, NULL, NULL);
		} else {
			nvme_print_str(4, "Namespace ANA Group Identifier",
			    -1, "unsupported", 0);
		}
	}

	nvme_print(4, "Namespace Attributes", -1, NULL);
	nvme_print_bit(6, "Write Protected",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    idns->id_nsattr.nsa_wprot, "yes", "no");

	if (verbose) {
		if (idns->id_nvmsetid != 0) {
			nvme_print_uint64(4, "Namespace Set Identifier",
			    idns->id_nvmsetid, NULL, NULL);
		} else {
			nvme_print_str(4, "Namespace Set Identifier",
			    -1, "unsupported", 0);
		}

		if (idns->id_endgid != 0) {
			nvme_print_uint64(4, "Namespace Endurance Group "
			    "Identifier", idns->id_endgid, NULL, NULL);
		} else {
			nvme_print_str(4, "Namespace Endurance Group "
			    "Identifier", -1, "unsupported", 0);
		}
	}

	if (nvme_vers_atleast(version, &nvme_vers_1v2)) {
		uint8_t guid[16] = { 0 };
		if (memcmp(guid, idns->id_nguid, sizeof (guid) != 0)) {
			nvme_print_guid(4, "Namespace GUID", idns->id_nguid);
		} else {
			nvme_print_str(4, "Namespace GUID",
			    -1, "unsupported", 0);
		}
	} else {
		nvme_print_str(4, "Namespace GUID", -1, "unsupported", 0);
	}


	if (nvme_vers_atleast(version, &nvme_vers_1v1)) {
		uint8_t oui[8] = { 0 };
		if (memcmp(oui, idns->id_eui64, sizeof (oui)) != 0) {
			nvme_print_eui64(4, "IEEE Extended Unique Identifier",
			    idns->id_eui64);
		} else {
			nvme_print_str(4, "IEEE Extended Unique Identifier",
			    -1, "unsupported", 0);
		}
	} else {
		nvme_print_str(4, "IEEE Extended Unique Identifier", -1,
		    "unsupported", 0);
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
 * nvme_print_identify_nsid_list
 *
 * Print a NVMe Namespace List.
 */
void
nvme_print_identify_nsid_list(const char *header,
    const nvme_identify_nsid_list_t *nslist)
{
	uint32_t i;

	nvme_print(0, header, -1, NULL);

	/*
	 * The namespace ID list is ordered, unused entries are 0.
	 */
	for (i = 0;
	    i < ARRAY_SIZE(nslist->nl_nsid) && nslist->nl_nsid[i] != 0;
	    i++) {
		nvme_print_uint64(2, "Namespace Identifier", nslist->nl_nsid[i],
		    NULL, NULL);
	}
}

/*
 * nvme_print_identify_nsid_desc
 *
 * Print a NVMe Namespace Identifier Descriptor list.
 */
void
nvme_print_identify_nsid_desc(void *nsdesc)
{
	const nvme_identify_nsid_desc_t *desc = nsdesc;
	int i = 0;
	uintptr_t ptr, end;

	nvme_print(0, "Namespace Identification Descriptors", -1, NULL);

	for (ptr = (uintptr_t)desc, end = ptr + NVME_IDENTIFY_BUFSIZE;
	    desc->nd_nidl != 0 && ptr + desc->nd_nidl + 4 <= end;
	    desc = (nvme_identify_nsid_desc_t *)(ptr += desc->nd_nidl + 4)) {
		const char *nidt;

		if (desc->nd_nidt >= ARRAY_SIZE(ns_identifier_type))
			nidt = "Reserved";
		else
			nidt = ns_identifier_type[desc->nd_nidt];

		nvme_print(2, "Namespace Identifier Descriptor", i++, NULL);
		nvme_print_str(4, "Namespace Identifier Type", -1, nidt, 0);
		nvme_print_uint64(4, "Namespace Identifier Length",
		    desc->nd_nidl, NULL, NULL);

		if (desc->nd_nidt == NVME_NSID_DESC_EUI64 &&
		    desc->nd_nidl == NVME_NSID_DESC_LEN_EUI64) {
			nvme_print_eui64(4, "IEEE Extended Unique Identifier",
			    desc->nd_nid);
		} else if (desc->nd_nidt == NVME_NSID_DESC_NGUID &&
		    desc->nd_nidl == NVME_NSID_DESC_LEN_NGUID) {
			nvme_print_guid(4, "Namespace GUID", desc->nd_nid);
		} else if (desc->nd_nidt == NVME_NSID_DESC_NUUID &&
		    desc->nd_nidl == NVME_NSID_DESC_LEN_NUUID) {
			nvme_print_uuid(4, "Namespace UUID", desc->nd_nid);
		} else if (desc->nd_nidt < NVME_NSID_DESC_MIN ||
		    desc->nd_nidt > NVME_NSID_DESC_MAX) {
			nvme_print_hexbuf(4, "Raw Bytes", desc->nd_nid,
			    desc->nd_nidl);
		} else {
			nvme_print_hexbuf(4,
			    "Raw Bytes (Invalid Descriptor Length)",
			    desc->nd_nid, desc->nd_nidl);
		}
	}
}

/*
 * nvme_print_identify_ctrl_list
 *
 * Print a NVMe Controller List.
 */
void
nvme_print_identify_ctrl_list(const char *header,
    const nvme_identify_ctrl_list_t *ctlist)
{
	int i;

	nvme_print(0, header, -1, NULL);
	for (i = 0; i != ctlist->cl_nid; i++) {
		nvme_print_uint64(2, "Controller Identifier",
		    ctlist->cl_ctlid[i], NULL, NULL);
	}
}

/*
 * nvme_print_error_log
 *
 * This function pretty-prints all non-zero error log entries, or all entries
 * if verbose is set.
 */
void
nvme_print_error_log(int nlog, const nvme_error_log_entry_t *elog,
    const nvme_version_t *version)
{
	int i;

	nvme_print(0, "Error Log", -1, NULL);
	for (i = 0; i != nlog; i++)
		if (elog[i].el_count == 0)
			break;
	nvme_print_uint64(2, "Number of Error Log Entries", i, NULL, NULL);

	for (i = 0; i != nlog; i++) {
		int sc = elog[i].el_sf.sf_sc;
		const char *sc_str = "Unknown";

		if (elog[i].el_count == 0 && verbose == 0)
			break;

		switch (elog[i].el_sf.sf_sct) {
		case 0: /* Generic Command Status */
			if (sc < ARRAY_SIZE(generic_status_codes)) {
				sc_str = generic_status_codes[sc];
			} else if (sc >= 0x80 &&
			    sc - 0x80 < ARRAY_SIZE(generic_nvm_status_codes)) {
				sc_str = generic_nvm_status_codes[sc - 0x80];
			}
			break;
		case 1: /* Specific Command Status */
			if (sc < ARRAY_SIZE(specific_status_codes)) {
				sc_str = specific_status_codes[sc];
			} else if (sc >= 0x80 &&
			    sc - 0x80 < ARRAY_SIZE(specific_nvm_status_codes)) {
				sc_str = specific_nvm_status_codes[sc - 0x80];
			}
			break;
		case 2: /* Media Errors */
			if (sc >= 0x80 &&
			    sc - 0x80 < ARRAY_SIZE(media_nvm_status_codes)) {
				sc_str = media_nvm_status_codes[sc - 0x80];
			}
			break;
		case 3:	/* Path Related Status */
			if (sc < ARRAY_SIZE(path_status_codes)) {
				sc_str = path_status_codes[sc];
			} else if (sc >= 0x60 &&
			    sc - 0x60 < ARRAY_SIZE(path_controller_codes)) {
				sc_str = path_controller_codes[sc - 0x60];
			} else if (sc >= 0x70 &&
			    sc - 0x70 < ARRAY_SIZE(path_host_codes)) {
				sc_str = path_host_codes[sc - 0x70];
			}
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
		    nvme_vers_atleast(version, &nvme_vers_1v0),
		    elog[i].el_sf.sf_m, "yes", "no");
		nvme_print_bit(6, "Do Not Retry",
		    nvme_vers_atleast(version, &nvme_vers_1v0),
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
		    "Vendor Specific Information Available",
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
nvme_print_health_log(const nvme_health_log_t *hlog,
    const nvme_identify_ctrl_t *idctl, const nvme_version_t *version)
{
	nvme_print(0, "SMART/Health Information", -1, NULL);
	nvme_print(2, "Critical Warnings", -1, NULL);
	nvme_print_bit(4, "Available Space",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    hlog->hl_crit_warn.cw_avail, "low", "OK");
	nvme_print_bit(4, "Temperature",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    hlog->hl_crit_warn.cw_temp, "too high", "OK");
	nvme_print_bit(4, "Device Reliability",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    hlog->hl_crit_warn.cw_reliab, "degraded", "OK");
	nvme_print_bit(4, "Media",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    hlog->hl_crit_warn.cw_readonly, "read-only", "OK");
	if (idctl->id_vwc.vwc_present != 0)
		nvme_print_bit(4, "Volatile Memory Backup",
		    nvme_vers_atleast(version, &nvme_vers_1v0),
		    hlog->hl_crit_warn.cw_volatile, "failed", "OK");

	nvme_print_temp(2, "Temperature", hlog->hl_temp);
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
	 * GB by doing binary shifts (9 left and 30 right) and multiply by 10^3.
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

	if (!nvme_vers_atleast(version, &nvme_vers_1v2)) {
		return;
	}

	if (idctl->ap_wctemp != 0) {
		nvme_print_uint64(2, "Warning Composite Temperature Time",
		    hlog->hl_warn_temp_time, NULL, "min");
	}

	if (idctl->ap_cctemp != 0) {
		nvme_print_uint64(2, "Critical Composite Temperature Time",
		    hlog->hl_crit_temp_time, NULL, "min");
	}

	if (hlog->hl_temp_sensor_1 != 0) {
		nvme_print_temp(2, "Temperature Sensor 1",
		    hlog->hl_temp_sensor_1);
	}

	if (hlog->hl_temp_sensor_2 != 0) {
		nvme_print_temp(2, "Temperature Sensor 2",
		    hlog->hl_temp_sensor_2);
	}

	if (hlog->hl_temp_sensor_3 != 0) {
		nvme_print_temp(2, "Temperature Sensor 3",
		    hlog->hl_temp_sensor_3);
	}

	if (hlog->hl_temp_sensor_4 != 0) {
		nvme_print_temp(2, "Temperature Sensor 4",
		    hlog->hl_temp_sensor_4);
	}

	if (hlog->hl_temp_sensor_5 != 0) {
		nvme_print_temp(2, "Temperature Sensor 5",
		    hlog->hl_temp_sensor_5);
	}

	if (hlog->hl_temp_sensor_6 != 0) {
		nvme_print_temp(2, "Temperature Sensor 6",
		    hlog->hl_temp_sensor_6);
	}

	if (hlog->hl_temp_sensor_7 != 0) {
		nvme_print_temp(2, "Temperature Sensor 7",
		    hlog->hl_temp_sensor_7);
	}

	if (hlog->hl_temp_sensor_8 != 0) {
		nvme_print_temp(2, "Temperature Sensor 8",
		    hlog->hl_temp_sensor_8);
	}

	if (!nvme_vers_atleast(version, &nvme_vers_1v3)) {
		return;
	}

	nvme_print_uint64(2, "Thermal Management Temp 1 Transition Count",
	    hlog->hl_tmtemp_1_tc, NULL, NULL);

	nvme_print_uint64(2, "Thermal Management Temp 2 Transition Count",
	    hlog->hl_tmtemp_2_tc, NULL, NULL);

	nvme_print_uint64(2, "Time for Thermal Management Temp 1",
	    hlog->hl_tmtemp_1_time, NULL, "sec");

	nvme_print_uint64(2, "Time for Thermal Management Temp 2",
	    hlog->hl_tmtemp_2_time, NULL, "sec");
}

/*
 * nvme_print_fwslot_log
 *
 * This function pretty-prints the firmware slot information.
 */
void
nvme_print_fwslot_log(const nvme_fwslot_log_t *fwlog,
    const nvme_identify_ctrl_t *idctl)
{
	int i;

	char str[NVME_FWVER_SZ + sizeof (" (read-only)")];

	nvme_print(0, "Firmware Slot Information", -1, NULL);
	nvme_print_uint64(2, "Active Firmware Slot", fwlog->fw_afi, NULL, NULL);
	if (fwlog->fw_next != 0)
		nvme_print_uint64(2, "Next Firmware Slot", fwlog->fw_next,
		    NULL, NULL);


	(void) snprintf(str, sizeof (str), "%.*s%s",
	    nvme_strlen(fwlog->fw_frs[0], sizeof (fwlog->fw_frs[0])),
	    fwlog->fw_frs[0], idctl->id_frmw.fw_readonly ? " (read-only)" : "");
	nvme_print_str(2, "Firmware Revision for Slot", 1, str, sizeof (str));

	for (i = 1; i < idctl->id_frmw.fw_nslot; i++) {
		nvme_print_str(2, "Firmware Revision for Slot", i + 1,
		    fwlog->fw_frs[i][0] == '\0' ? "<Unused>" :
		    fwlog->fw_frs[i], sizeof (fwlog->fw_frs[i]));
	}
}

/*
 * nvme_print_feat_*
 *
 * These functions pretty-print the data structures returned by GET FEATURES.
 */
void
nvme_print_feat_unknown(nvme_feat_output_t output, uint32_t cdw0, void *b,
    size_t s)
{
	if ((output & NVME_FEAT_OUTPUT_CDW0) != 0) {
		nvme_print_uint64(4, "cdw0", cdw0, "0x%"PRIx64, NULL);
	}

	if ((output & NVME_FEAT_OUTPUT_DATA) != 0) {
		nvme_print_hexbuf(4, "data", b, s);
	}
}

void
nvme_print_feat_arbitration(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_arbitration_t arb;

	arb.r = cdw0;
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
nvme_print_feat_power_mgmt(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_power_mgmt_t pm;

	pm.r = cdw0;
	nvme_print_uint64(4, "Power State", (uint8_t)pm.b.pm_ps,
	    NULL, NULL);
}

void
nvme_print_feat_lba_range(uint32_t cdw0, void *buf, size_t bufsize,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(id));

	nvme_lba_range_type_t lrt;
	nvme_lba_range_t *lr;
	size_t n_lr;
	int i;

	if (buf == NULL)
		return;

	lrt.r = cdw0;
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
		if (lr[i].lr_type < ARRAY_SIZE(lba_range_types))
			nvme_print_str(6, "Type", -1,
			    lba_range_types[lr[i].lr_type], 0);
		else
			nvme_print_uint64(6, "Type",
			    lr[i].lr_type, NULL, NULL);
		nvme_print(6, "Attributes", -1, NULL);
		nvme_print_bit(8, "Writable",
		    nvme_vers_atleast(version, &nvme_vers_1v0),
		    lr[i].lr_attr.lr_write, "yes", "no");
		nvme_print_bit(8, "Hidden",
		    nvme_vers_atleast(version, &nvme_vers_1v0),
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
nvme_print_feat_temperature(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_temp_threshold_t tt;
	char *label = b;

	tt.r = cdw0;
	nvme_print_temp(4, label, tt.b.tt_tmpth);
}

void
nvme_print_feat_error(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_error_recovery_t er;

	er.r = cdw0;
	if (er.b.er_tler > 0)
		nvme_print_uint64(4, "Time Limited Error Recovery",
		    (uint32_t)er.b.er_tler * 100, NULL, "ms");
	else
		nvme_print_str(4, "Time Limited Error Recovery", -1,
		    "no time limit", 0);
}

void
nvme_print_feat_write_cache(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_write_cache_t wc;

	wc.r = cdw0;
	nvme_print_bit(4, "Volatile Write Cache",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    wc.b.wc_wce, "enabled", "disabled");
}

void
nvme_print_feat_nqueues(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_nqueues_t nq;

	nq.r = cdw0;
	nvme_print_uint64(4, "Number of Submission Queues",
	    nq.b.nq_nsq + 1, NULL, NULL);
	nvme_print_uint64(4, "Number of Completion Queues",
	    nq.b.nq_ncq + 1, NULL, NULL);
}

void
nvme_print_feat_intr_coal(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_intr_coal_t ic;

	ic.r = cdw0;
	nvme_print_uint64(4, "Aggregation Threshold",
	    ic.b.ic_thr + 1, NULL, NULL);
	nvme_print_uint64(4, "Aggregation Time",
	    (uint16_t)ic.b.ic_time * 100, NULL, "us");
}
void
nvme_print_feat_intr_vect(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_intr_vect_t iv;
	char *tmp;

	iv.r = cdw0;
	if (asprintf(&tmp, "Vector %d Coalescing Disable", iv.b.iv_iv) < 0)
		err(-1, "nvme_print_feat_common()");

	nvme_print_bit(4, tmp, iv.b.iv_cd,
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    "yes", "no");
}

void
nvme_print_feat_write_atom(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_write_atomicity_t wa;

	wa.r = cdw0;
	nvme_print_bit(4, "Disable Normal", wa.b.wa_dn,
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    "yes", "no");
}

void
nvme_print_feat_async_event(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *idctl, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	nvme_async_event_conf_t aec;

	aec.r = cdw0;
	nvme_print_bit(4, "Available Space below threshold",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    aec.b.aec_avail, "enabled", "disabled");
	nvme_print_bit(4, "Temperature above threshold",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    aec.b.aec_temp, "enabled", "disabled");
	nvme_print_bit(4, "Device Reliability compromised",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    aec.b.aec_reliab, "enabled", "disabled");
	nvme_print_bit(4, "Media read-only",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
	    aec.b.aec_readonly, "enabled", "disabled");
	if (idctl->id_vwc.vwc_present != 0) {
		nvme_print_bit(4, "Volatile Memory Backup failed",
		    nvme_vers_atleast(version, &nvme_vers_1v0),
		    aec.b.aec_volatile, "enabled", "disabled");
	}

	/* NVMe 1.2 */
	nvme_print_bit(4, "Namespace attribute notices",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    aec.b.aec_nsan, "enabled", "disabled");
	nvme_print_bit(4, "Firmware activation notices",
	    nvme_vers_atleast(version, &nvme_vers_1v2),
	    aec.b.aec_fwact, "enabled", "disabled");

	/* NVMe 1.3 */
	nvme_print_bit(4, "Telemetry log notices",
	    nvme_vers_atleast(version, &nvme_vers_1v3),
	    aec.b.aec_telln, "enabled", "disabled");

	/* NVMe 1.4 */
	nvme_print_bit(4, "ANA change notices",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    aec.b.aec_ansacn, "enabled", "disabled");
	nvme_print_bit(4,
	    "Predictable latency event aggr. LCNs",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    aec.b.aec_plat, "enabled", "disabled");
	nvme_print_bit(4, "LBA status information notices",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    aec.b.aec_lbasi, "enabled", "disabled");
	nvme_print_bit(4, "Endurance group event aggregate LCNs",
	    nvme_vers_atleast(version, &nvme_vers_1v4),
	    aec.b.aec_egeal, "enabled", "disabled");
}

void
nvme_print_feat_auto_pst(uint32_t cdw0, void *buf, size_t bufsize,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(id));

	nvme_auto_power_state_trans_t apst;
	nvme_auto_power_state_t *aps;
	int i;
	int cnt = bufsize / sizeof (nvme_auto_power_state_t);

	if (buf == NULL)
		return;

	apst.r = cdw0;
	aps = buf;

	nvme_print_bit(4, "Autonomous Power State Transition",
	    nvme_vers_atleast(version, &nvme_vers_1v0),
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
nvme_print_feat_progress(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	_NOTE(ARGUNUSED(b));
	_NOTE(ARGUNUSED(s));
	_NOTE(ARGUNUSED(id));
	nvme_software_progress_marker_t spm;

	spm.r = cdw0;
	nvme_print_uint64(4, "Pre-Boot Software Load Count",
	    spm.b.spm_pbslc, NULL, NULL);
}

void
nvme_print_feat_host_behavior(uint32_t cdw0, void *b, size_t s,
    const nvme_identify_ctrl_t *id, const nvme_version_t *version)
{
	const nvme_host_behavior_t *hb = b;

	nvme_print_bit(4, "Advanced Command Retry",
	    nvme_vers_atleast(version, &nvme_vers_1v4), hb->nhb_acre,
	    "enabled", "disabled");
	nvme_print_bit(4, "Extended Telemetry Data Area 4",
	    nvme_vers_atleast(version, &nvme_vers_2v0), hb->nhb_etdas,
	    "enabled", "disabled");
	nvme_print_bit(4, "LBA Format Extension",
	    nvme_vers_atleast(version, &nvme_vers_2v0), hb->nhb_lbafee,
	    "enabled", "disabled");
	nvme_print_bit(4, "Host Dispersed Namespace Support",
	    nvme_vers_atleast(version, &nvme_vers_2v1), hb->nhb_lbafee,
	    "enabled", "disabled");
	nvme_print(4, "Copy Descriptor Formats", -1, NULL);
	nvme_print_bit(6, "Copy Descriptor 2",
	    nvme_vers_atleast(version, &nvme_vers_2v1), hb->nhb_cdfe & (1 << 2),
	    "enabled", "disabled");
	nvme_print_bit(6, "Copy Descriptor 3",
	    nvme_vers_atleast(version, &nvme_vers_2v1), hb->nhb_cdfe & (1 << 3),
	    "enabled", "disabled");
	nvme_print_bit(6, "Copy Descriptor 4",
	    nvme_vers_atleast(version, &nvme_vers_2v1), hb->nhb_cdfe & (1 << 4),
	    "enabled", "disabled");
}

/*
 * This is designed to print out a large buffer as decipherable hexadecimal.
 * This is intended for log pages or command output where there is unknown
 * printing. For an inline hex buffer, see nvme_print_hexbuf().
 */
void
nvmeadm_dump_hex(const uint8_t *buf, size_t len)
{
	(void) hexdump_file(buf, len, HDF_DEFAULT, stdout);
}
