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
 * Deal with Micron-specific logs.
 */

#include <err.h>
#include <string.h>
#include <sys/stddef.h>
#include <sys/sysmacros.h>
#include <sys/nvme/micron.h>

#include "nvmeadm.h"

/*
 * Synthetic identifiers for these logs to deal with the changes that we have
 * found in here over time. See micron_vul_ext_smart_getvers() for more.
 */
#define	MICRON_GEN_73XX	1
#define	MICRON_GEN_74XX	2

#define	MICRON_F_SMART(f)	\
	.nf_off = offsetof(micron_vul_ext_smart_t, mes_##f), \
	.nf_len = sizeof (((micron_vul_ext_smart_t *)NULL)->mes_##f)

static const nvmeadm_field_bit_t micron_vul_ext_smart_wpr_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "dramue",
	.nfb_desc = "DRAM Double Bit Error",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "did not occur", "occurred" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "spare",
	.nfb_desc = "Low Remaining Spare Block Count",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "did not occur", "occurred" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "cap",
	.nfb_desc = "Power Holdup Capacitor Failure",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "did not occur", "occurred" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "nvram",
	.nfb_desc = "NVRAM Checksum Failure",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "did not occur", "occurred" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "daor",
	.nfb_desc = "DRAM Address Out of Range",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "did not occur", "occurred" }
}, {
	.nfb_lowbit = 5, .nfb_hibit = 5,
	.nfb_short = "temp",
	.nfb_desc = "Overtemp Shutdown",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "did not occur", "occurred" }
} };

static const nvmeadm_field_t micron_vul_ext_smart_fields[] = { {
	MICRON_F_SMART(gbb),
	.nf_short = "gbb",
	.nf_desc = "Grown Bad Block Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(max_erase),
	.nf_short = "mec",
	.nf_desc = "Per-Block Max Erase Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(power_on),
	.nf_short = "pon",
	.nf_desc = "Power-on",
	.nf_type = NVMEADM_FT_UNIT,
	.nf_addend = { .nfa_unit = "min" }
}, {
	MICRON_F_SMART(wp_reason),
	.nf_short = "wpr",
	.nf_desc = "Write Protect Reason",
	NVMEADM_F_BITS(micron_vul_ext_smart_wpr_bits)
}, {
	MICRON_F_SMART(cap),
	.nf_short = "cap",
	.nf_desc = "Device Capacity",
	.nf_type = NVMEADM_FT_BYTES
}, {
	MICRON_F_SMART(erase_count),
	.nf_short = "tec",
	.nf_desc = "Total Erase Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(use_rate),
	.nf_short = "use",
	.nf_desc = "Lifetime Use Rate",
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(erase_fail),
	.nf_short = "efc",
	.nf_desc = "Erase Fail Count",
	.nf_rev = MICRON_GEN_74XX,
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(uecc),
	.nf_short = "uecc",
	.nf_desc = "Reported Uncorrectable ECC Errors",
	.nf_rev = MICRON_GEN_74XX,
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(prog_fail),
	.nf_short = "pfc",
	.nf_desc = "Program Fail Count",
	.nf_rev = MICRON_GEN_74XX,
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(read_bytes),
	.nf_short = "read",
	.nf_desc = "Total Bytes Read",
	.nf_rev = MICRON_GEN_74XX,
	.nf_type = NVMEADM_FT_BYTES
}, {
	MICRON_F_SMART(write_bytes),
	.nf_short = "write",
	.nf_desc = "Total Bytes Written",
	.nf_rev = MICRON_GEN_74XX,
	.nf_type = NVMEADM_FT_BYTES
}, {
	MICRON_F_SMART(trans_size),
	.nf_short = "tus",
	.nf_desc = "Translation Unit Size",
	.nf_type = NVMEADM_FT_BYTES
}, {
	MICRON_F_SMART(bs_total),
	.nf_short = "tbs",
	.nf_desc = "Total Block Stripe Count for User Data",
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(bs_free),
	.nf_short = "fbs",
	.nf_desc = "Free Block Stripe Count for User Data",
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(bs_cap),
	.nf_short = "bss",
	.nf_desc = "Block Stripe Size",
	.nf_type = NVMEADM_FT_BYTES
}, {
	MICRON_F_SMART(user_erase_min),
	.nf_short = "ubemin",
	.nf_desc = "Minimum User Block Erase Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(user_erase_avg),
	.nf_short = "ubeavg",
	.nf_desc = "Average User Block Erase Count",
	.nf_type = NVMEADM_FT_HEX
}, {
	MICRON_F_SMART(user_erase_max),
	.nf_short = "ubemax",
	.nf_desc = "Maximum User Block Erase Count",
	.nf_type = NVMEADM_FT_HEX
} };

/*
 * The 73xx series and 74xx series have some different entries in these log
 * pages. There is no good way to determine this in the log. Instead we use a
 * crude but reasonable heuristic. The 74xx series added a pair of counters for
 * total bytes read and written. If these are zero, then we know we're on the
 * 73xx assuming it's playing by its reserved rules. We've also seen some cases
 * where the 73xx parts will return all 1s for the reserved fields, so we check
 * that too.
 */
static uint32_t
micron_vul_ext_smart_getvers(const void *data, size_t len)
{
	const uint8_t zero[16] = { 0 };
	uint8_t ones[16];

	if (len < sizeof (micron_vul_ext_smart_t)) {
		errx(-1, "cannot parse revision information, found 0x%zx "
		    "bytes, need at least 0x%zx", len,
		    sizeof (micron_vul_ext_smart_t));
	}

	(void) memset(ones, 0xff, sizeof (ones));
	const micron_vul_ext_smart_t *log = data;
	if (memcmp(zero, log->mes_read_bytes, sizeof (zero)) == 0 &&
	    memcmp(zero, log->mes_write_bytes, sizeof (zero)) == 0) {
		return (MICRON_GEN_73XX);
	}

	if (memcmp(ones, log->mes_read_bytes, sizeof (ones)) == 0 &&
	    memcmp(ones, log->mes_write_bytes, sizeof (ones)) == 0) {
		return (MICRON_GEN_73XX);
	}

	return (MICRON_GEN_74XX);
}

const nvmeadm_log_field_info_t micron_vul_extsmart_field_info = {
	.nlfi_log = "micron/extsmart",
	.nlfi_fields = micron_vul_ext_smart_fields,
	.nlfi_nfields = ARRAY_SIZE(micron_vul_ext_smart_fields),
	.nlfi_min = sizeof (micron_vul_ext_smart_t),
	.nlfi_getrev = micron_vul_ext_smart_getvers
};
