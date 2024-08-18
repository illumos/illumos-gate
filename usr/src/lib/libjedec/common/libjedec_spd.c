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
 * This is the common file or parsing out SPD data of different generations. Our
 * general goal is to create a single nvlist_t that has a few different sections
 * present in it:
 *
 *   o Metadata (e.g. DRAM type, Revision, overlay type, etc.)
 *   o Manufacturing Information
 *   o Common parameters: these are ultimately specific to a DDR type.
 *   o Overlay parameters: these are specific to both the DDR type and the
 *     module type.
 *
 * We try to only fail top-level parsing if we really can't understand anything
 * or don't have enough information. We assume that we'll get relatively
 * complete data. Errors are listed as keys for a given entry and will be
 * skipped otherwise. For an overview of the actual fields and structures, see
 * libjedec.h.
 *
 * Currently we support all of DDR4, DDD5, and LPDDR5/x based SPD information
 * with the exception of some NVDIMM properties.
 */

#include <string.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <stdbool.h>

#include "libjedec_spd.h"

void
spd_nvl_err(spd_info_t *si, const char *key, spd_error_kind_t err,
    const char *fmt, ...)
{
	int ret;
	nvlist_t *nvl;
	char msg[1024];
	va_list ap;

	if (si->si_error != LIBJEDEC_SPD_OK)
		return;

	ret = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}

	ret = nvlist_add_uint32(nvl, SPD_KEY_ERRS_CODE, err);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		nvlist_free(nvl);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}

	/*
	 * We cast this snprintf to void so we can try to get someone something
	 * at least in the face of it somehow being too large.
	 */
	va_start(ap, fmt);
	(void) vsnprintf(msg, sizeof (msg), fmt, ap);
	va_end(ap);

	ret = nvlist_add_string(nvl, SPD_KEY_ERRS_MSG, msg);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		nvlist_free(nvl);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}

	ret = nvlist_add_nvlist(si->si_errs, key, nvl);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		nvlist_free(nvl);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}

	nvlist_free(nvl);
}

void
spd_nvl_insert_str(spd_info_t *si, const char *key, const char *data)
{
	int ret;

	if (si->si_error != LIBJEDEC_SPD_OK)
		return;

	ret = nvlist_add_string(si->si_nvl, key, data);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}
}

void
spd_nvl_insert_u32(spd_info_t *si, const char *key, uint32_t data)
{
	int ret;

	if (si->si_error != LIBJEDEC_SPD_OK)
		return;

	ret = nvlist_add_uint32(si->si_nvl, key, data);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}
}

void
spd_nvl_insert_u64(spd_info_t *si, const char *key, uint64_t data)
{
	int ret;

	if (si->si_error != LIBJEDEC_SPD_OK)
		return;

	ret = nvlist_add_uint64(si->si_nvl, key, data);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}
}

void
spd_nvl_insert_u8_array(spd_info_t *si, const char *key,
    uint8_t *data, uint_t nent)
{
	int ret;

	if (si->si_error != LIBJEDEC_SPD_OK)
		return;

	ret = nvlist_add_uint8_array(si->si_nvl, key, data, nent);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}
}

void
spd_nvl_insert_u32_array(spd_info_t *si, const char *key,
    uint32_t *data, uint_t nent)
{
	int ret;

	if (si->si_error != LIBJEDEC_SPD_OK)
		return;

	ret = nvlist_add_uint32_array(si->si_nvl, key, data, nent);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}
}

void
spd_nvl_insert_u64_array(spd_info_t *si, const char *key,
    uint64_t *data, uint_t nent)
{
	int ret;

	if (si->si_error != LIBJEDEC_SPD_OK)
		return;

	ret = nvlist_add_uint64_array(si->si_nvl, key, data, nent);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}
}

void
spd_nvl_insert_boolean_array(spd_info_t *si, const char *key,
    boolean_t *data, uint_t nent)
{
	int ret;

	if (si->si_error != LIBJEDEC_SPD_OK)
		return;

	ret = nvlist_add_boolean_array(si->si_nvl, key, data, nent);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}
}

void
spd_nvl_insert_key(spd_info_t *si, const char *key)
{
	int ret;

	if (si->si_error != LIBJEDEC_SPD_OK)
		return;

	ret = nvlist_add_boolean(si->si_nvl, key);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}
}

void
spd_insert_map(spd_info_t *si, const char *key, uint8_t spd_val,
    const spd_value_map_t *maps, size_t nmaps)
{
	for (size_t i = 0; i < nmaps; i++) {
		if (maps[i].svm_spd != spd_val)
			continue;
		if (maps[i].svm_skip)
			return;

		spd_nvl_insert_u32(si, key, maps[i].svm_use);
		return;
	}

	spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "encountered unknown "
	    "value: 0x%x", spd_val);
}

void
spd_insert_map64(spd_info_t *si, const char *key, uint8_t spd_val,
    const spd_value_map64_t *maps, size_t nmaps)
{
	for (size_t i = 0; i < nmaps; i++) {
		if (maps[i].svm_spd != spd_val)
			continue;
		if (maps[i].svm_skip)
			return;

		spd_nvl_insert_u64(si, key, maps[i].svm_use);
		return;
	}

	spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "encountered unknown "
	    "value: 0x%x", spd_val);
}

void
spd_insert_str_map(spd_info_t *si, const char *key, uint8_t spd_val,
    const spd_str_map_t *maps, size_t nmaps)
{
	for (size_t i = 0; i < nmaps; i++) {
		if (maps[i].ssm_spd != spd_val)
			continue;
		if (maps[i].ssm_skip)
			return;

		spd_nvl_insert_str(si, key, maps[i].ssm_str);
		return;
	}

	spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "encountered unknown "
	    "value: 0x%x", spd_val);
}

/*
 * Map an array in its entirety to a corresponding set of values. If any one
 * value cannot be translated, then we fail the whole item.
 */
void
spd_insert_map_array(spd_info_t *si, const char *key, const uint8_t *raw,
    size_t nraw, const spd_value_map_t *maps, size_t nmaps)
{
	uint32_t *trans;

	trans = calloc(nraw, sizeof (uint32_t));
	if (trans == NULL) {
		si->si_error = LIBJEDEC_SPD_NOMEM;
		return;
	}

	for (size_t i = 0; i < nraw; i++) {
		bool found = false;
		for (size_t map = 0; map < nmaps; map++) {
			if (maps[map].svm_spd != raw[i])
				continue;
			ASSERT3U(maps[map].svm_skip, ==, false);
			found = true;
			trans[i] = maps[map].svm_use;
			break;
		}

		if (!found) {
			spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "encountered "
			    "unknown array value: [%zu]=0x%x", i, raw[i]);
			goto done;
		}
	}

	spd_nvl_insert_u32_array(si, key, trans, nraw);
done:
	free(trans);
}

/*
 * We've been given a value which attempts to fit within a range. This range has
 * an optional upper and lower bound. The value can be transformed in one of
 * three ways which are honored in the following order:
 *
 * 1) If there is a multiple, we apply that to the raw value first.
 * 2) There can be a base value which we then add to any adjusted value.
 * 3) The final value can be treated as an exponent resulting in a bit-shift.
 *
 * After this is done we can check against the minimum and maximum values. A
 * specified min or max of zero is ignored.
 */
void
spd_insert_range(spd_info_t *si, const char *key, uint8_t raw_val,
    const spd_value_range_t *range)
{
	uint32_t min = 0, max = UINT32_MAX;
	uint32_t act = raw_val;

	if (range->svr_mult != 0) {
		act *= range->svr_mult;
	}

	act += range->svr_base;

	if (range->svr_exp) {
		act = 1 << act;
	}

	if (range->svr_max != 0) {
		max = range->svr_max;
	}

	if (range->svr_min != 0) {
		min = range->svr_min;
	} else if (range->svr_base != 0) {
		min = range->svr_base;
	}

	if (act > max || act < min) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "found value "
		    "0x%x (raw 0x%x) outside range [0x%x, 0x%x]", act, raw_val,
		    min, max);
	} else {
		spd_nvl_insert_u32(si, key, act);
	}
}

/*
 * Either insert the given flag for a key or OR it in if it already exists.
 */
void
spd_upsert_flag(spd_info_t *si, const char *key, uint32_t flag)
{
	int ret;
	uint32_t val;

	ret = nvlist_lookup_uint32(si->si_nvl, key, &val);
	if (ret != 0) {
		VERIFY3S(ret, ==, ENOENT);
		spd_nvl_insert_u32(si, key, flag);
		return;
	}

	VERIFY0(val & flag);
	val |= flag;
	spd_nvl_insert_u32(si, key, val);
}

void
spd_parse_rev(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t enc = SPD_DDR4_SPD_REV_ENC(data);
	const uint8_t add = SPD_DDR4_SPD_REV_ADD(data);

	spd_nvl_insert_u32(si, SPD_KEY_REV_ENC, enc);
	spd_nvl_insert_u32(si, SPD_KEY_REV_ADD, add);
}

void
spd_parse_jedec_id(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	uint32_t id[2];

	VERIFY3U(len, ==, 2);
	id[0] = SPD_MFG_ID0_CONT(si->si_data[off]);
	id[1] = si->si_data[off + 1];

	spd_nvl_insert_u32_array(si, key, id, ARRAY_SIZE(id));
}

void
spd_parse_jedec_id_str(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	uint8_t cont = SPD_MFG_ID0_CONT(si->si_data[off]);
	const char *str;

	VERIFY3U(len, ==, 2);
	str = libjedec_vendor_string(cont, si->si_data[off + 1]);
	if (str != NULL) {
		spd_nvl_insert_str(si, key, str);
	} else {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE, "no matching "
		    "libjedec vendor string for 0x%x,0x%x", cont,
		    si->si_data[off + 1]);
	}
}

/*
 * Parse a string that is at most len bytes wide and is padded with spaces. If
 * the string contains an unprintable, then we will not pull this off and set an
 * error for the string's key. 128 bytes should be larger than any ascii string
 * that we encounter as that is the size of most regions in SPD data.
 */
void
spd_parse_string(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	uint32_t nbytes = len;
	char buf[128];

	VERIFY3U(sizeof (buf), >, len);
	for (uint32_t i = 0; i < len; i++) {
		if (si->si_data[off + i] == ' ') {
			nbytes = i;
			break;
		}

		if (isascii(si->si_data[off + i]) == 0 ||
		    isprint(si->si_data[off + i]) == 0) {
			spd_nvl_err(si, key, SPD_ERROR_UNPRINT,
			    "byte %u for key %s (off: 0x%x, val: 0x%x) is not "
			    "printable", i, key, off + 1,
			    si->si_data[off + i]);
			return;
		}
	}

	if (nbytes == 0) {
		spd_nvl_err(si, key, SPD_ERROR_NO_DATA, "key %s has "
		    "no valid bytes in the string", key);
		return;
	}

	(void) memcpy(buf, &si->si_data[off], nbytes);
	buf[nbytes] = '\0';
	spd_nvl_insert_str(si, key, buf);
}

/*
 * Turn an array of bytes into a hex string. We need to allocate up to two bytes
 * per length that we have. We always zero pad such strings. We statically size
 * our buffer because the largest such string we have right now is a 4-byte
 * serial number. With the 128 byte buffer below, we could deal with a length up
 * to 63 (far beyond what we expect to ever see).
 */
void
spd_parse_hex_string(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	char buf[128];
	size_t nwrite = 0;

	VERIFY3U(sizeof (buf), >=, len * 2 + 1);

	for (uint32_t i = 0; i < len; i++) {
		int ret = snprintf(buf + nwrite, sizeof (buf) - nwrite,
		    "%02X", si->si_data[off + i]);
		if (ret < 0) {
			spd_nvl_err(si, key, SPD_ERROR_INTERNAL,
			    "snprintf failed unexpectedly for key %s: %s",
			    key, strerror(errno));
			return;
		}

		VERIFY3U(ret, ==, 2);
		nwrite += ret;
	}

	spd_nvl_insert_str(si, key, buf);
}

/*
 * Several SPD keys are explicit BCD major and minor versions in a given nibble.
 * This is most common in DDR5, but otherwise one should probably use
 * spd_parse_hex_string().
 */
void
spd_parse_hex_vers(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t maj = bitx8(data, 7, 4);
	const uint8_t min = bitx8(data, 3, 0);
	char buf[128];

	VERIFY3U(len, ==, 1);

	int ret = snprintf(buf, sizeof (buf), "%X.%X", maj, min);
	if (ret < 0) {
		spd_nvl_err(si, key, SPD_ERROR_INTERNAL,
		    "snprintf failed unexpectedly for key %s: %s",
		    key, strerror(errno));
		return;
	}

	spd_nvl_insert_str(si, key, buf);
}

void
spd_parse_raw_u8(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	VERIFY3U(len, ==, 1);
	spd_nvl_insert_u32(si, key, si->si_data[off]);
}

void
spd_parse_u8_array(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	uint8_t *data = (uint8_t *)si->si_data + off;

	spd_nvl_insert_u8_array(si, key, data, len);
}

void
spd_parse_dram_step(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	VERIFY3U(len, ==, 1);

	if (si->si_data[off] == SPD_DRAM_STEP_NOINFO)
		return;

	spd_parse_hex_string(si, off, len, key);
}

/*
 * Height and thickness have the same meaning across DDR3-DDR5.
 */
static const spd_value_range_t spd_height_range = {
	.svr_base = SPD_DDR5_COM_HEIGHT_BASE
};

static const spd_value_range_t spd_thick_range = {
	.svr_base = SPD_DDR5_COM_THICK_BASE
};

void
spd_parse_height(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t height = SPD_DDR5_COM_HEIGHT_MM(data);
	spd_insert_range(si, key, height, &spd_height_range);
}

void
spd_parse_thickness(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	const uint8_t data = si->si_data[off];
	const uint8_t front = SPD_DDR5_COM_THICK_FRONT(data);
	const uint8_t back = SPD_DDR5_COM_THICK_BACK(data);

	spd_insert_range(si, SPD_KEY_MOD_FRONT_THICK, front, &spd_thick_range);
	spd_insert_range(si, SPD_KEY_MOD_BACK_THICK, back, &spd_thick_range);
}

/*
 * Common timestamp calculation logic for DDR3-4, LPDDR3-5 that assumes 1 ps FT
 * and 125ps MTB. The MTB may either be an 8-bit, 12-bit, or 16-bit value. The
 * FTB value is actually a signed two's complement value that we use to adjust
 * things. We need to check for two illegal values:
 *
 * 1. That the value as a whole after adjustment is non-zero.
 * 2. That the fine adjustment does not cause us to underflow (i.e. unit values
 *    for the MTB of 1 and the FTB of -126).
 */
void
spd_parse_ddr_time(spd_info_t *si, const char *key, uint8_t upper_mtb,
    uint8_t mtb, uint8_t ftb)
{
	uint64_t ps = ((upper_mtb << 8) | mtb) * SPD_DDR4_MTB_PS;
	int8_t adj = (int8_t)ftb * SPD_DDR4_FTB_PS;

	if (ps == 125 && adj <= -125) {
		spd_nvl_err(si, key, SPD_ERROR_BAD_DATA,
		    "MTB (%" PRIu64 "ps) and FTB (%dps) would cause underflow",
		    ps, adj);
		return;
	}

	ps += adj;
	if (ps == 0) {
		spd_nvl_err(si, key, SPD_ERROR_NO_XLATE,
		    "encountered unexpected zero time value");
		return;
	}
	spd_nvl_insert_u64(si, key, ps);
}

/*
 * Combine two values into a picosecond value that is split between the MTB and
 * FTB. The MTB and FTB are split amongst a large number of bytes and are not
 * contiguous. The MTB is at data[off], and the FTB is at data[off + len - 1].
 *
 * This is shared by LPDDR3-5 which all use the same time base parameters. DDR3
 * also uses it for a number of items based on our assumptions.
 */
void
spd_parse_mtb_ftb_time_pair(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	const uint8_t mtb = si->si_data[off];
	const uint8_t ftb = si->si_data[off + len - 1];

	return (spd_parse_ddr_time(si, key, 0, mtb, ftb));
}

/*
 * Parse a pair of values where the MTB is split across two uint8_t's. The LSB
 * is in off and the MSB is in off+1.
 */
void
spd_parse_mtb_pair(spd_info_t *si, uint32_t off, uint32_t len,
    const char *key)
{
	ASSERT3U(len, ==, 2);
	return (spd_parse_ddr_time(si, key, si->si_data[off + 1],
	    si->si_data[off], 0));
}

static const spd_str_map_t spd_ddr_design_map0[32] = {
	{ 0, "A", false },
	{ 1, "B", false },
	{ 2, "C", false },
	{ 3, "D", false },
	{ 4, "E", false },
	{ 5, "F", false },
	{ 6, "G", false },
	{ 7, "H", false },
	{ 8, "J", false },
	{ 9, "K", false },
	{ 10, "L", false },
	{ 11, "M", false },
	{ 12, "N", false },
	{ 13, "P", false },
	{ 14, "R", false },
	{ 15, "T", false },
	{ 16, "U", false },
	{ 17, "V", false },
	{ 18, "W", false },
	{ 19, "Y", false },
	{ 20, "AA", false },
	{ 21, "AB", false },
	{ 22, "AC", false },
	{ 23, "AD", false },
	{ 24, "AE", false },
	{ 25, "AF", false },
	{ 26, "AG", false },
	{ 27, "AH", false },
	{ 28, "AJ", false },
	{ 29, "AK", false },
	{ 30, "AL", false },
	{ 31, "ZZ", false }
};

static const spd_str_map_t spd_ddr_design_map1[32] = {
	{ 0, "AM", false },
	{ 1, "AN", false },
	{ 2, "AP", false },
	{ 3, "AR", false },
	{ 4, "AT", false },
	{ 5, "AU", false },
	{ 6, "AV", false },
	{ 7, "AW", false },
	{ 8, "AY", false },
	{ 9, "BA", false },
	{ 10, "BB", false },
	{ 11, "BC", false },
	{ 12, "BD", false },
	{ 13, "BE", false },
	{ 14, "BF", false },
	{ 15, "BG", false },
	{ 16, "BH", false },
	{ 17, "BJ", false },
	{ 18, "BK", false },
	{ 19, "BL", false },
	{ 20, "BM", false },
	{ 21, "BN", false },
	{ 22, "BP", false },
	{ 23, "BR", false },
	{ 24, "BT", false },
	{ 25, "BU", false },
	{ 26, "BV", false },
	{ 27, "BW", false },
	{ 28, "BY", false },
	{ 29, "CA", false },
	{ 30, "CB", false },
	{ 31, "ZZ", false }
};

/*
 * In DDR3/4 and LPDDR3-5 the design information contains both a reference raw
 * card and a revision of the card. The card revision is split between two
 * bytes, the design and the height field. This is common logic that'll check
 * both. We use the DDR4 constants for the fields, but they are the same across
 * all versions.
 */
void
spd_parse_design(spd_info_t *si, uint32_t design, uint32_t height)
{
	const uint8_t data = si->si_data[design];
	const uint8_t rev = SPD_DDR4_RDIMM_REF_REV(data);
	const uint8_t card = SPD_DDR4_RDIMM_REF_CARD(data);

	if (SPD_DDR4_RDIMM_REF_EXT(data) != 0) {
		spd_insert_str_map(si, SPD_KEY_MOD_REF_DESIGN, card,
		    spd_ddr_design_map1, ARRAY_SIZE(spd_ddr_design_map1));
	} else {
		spd_insert_str_map(si, SPD_KEY_MOD_REF_DESIGN, card,
		    spd_ddr_design_map0, ARRAY_SIZE(spd_ddr_design_map0));
	}

	/*
	 * The design rev is split between here and the height field. If we
	 * have the value of three, then we must also add in the height's value
	 * to this.
	 */
	if (rev == SPD_DDR4_RDIMM_REV_USE_HEIGHT) {
		const uint8_t hdata = si->si_data[height];
		const uint8_t hrev = SPD_DDR4_RDIMM_HEIGHT_REV(hdata);
		spd_nvl_insert_u32(si, SPD_KEY_MOD_DESIGN_REV, rev + hrev);
	} else {
		spd_nvl_insert_u32(si, SPD_KEY_MOD_DESIGN_REV, rev);
	}
}

/*
 * Calculate the DRAM CRC16. The crc calculation covers [ off, off + len ). The
 * expected CRC is in expect. The JEDEC specs describe the algorithm (e.g. 21-C
 * Annex L, 8.1.53).
 */
void
spd_parse_crc_expect(spd_info_t *si, uint32_t off, uint32_t len,
    uint16_t expect, const char *key)
{
	uint32_t crc = 0;

	for (uint32_t i = 0; i < len; i++) {
		crc = crc ^ (uint32_t)si->si_data[off + i] << 8;
		for (uint32_t c = 0; c < 8; c++) {
			if (crc & 0x8000) {
				crc = crc << 1 ^ 0x1021;
			} else {
				crc = crc << 1;
			}
		}
	}

	crc &= 0xffff;
	if (crc == expect) {
		spd_nvl_insert_u32(si, key, crc);
	} else {
		spd_nvl_err(si, key, SPD_ERROR_BAD_DATA, "crc mismatch: "
		    "expected 0x%x, found 0x%x", expect, crc);
	}
}

/*
 * Calculate the DRAM CRC16. The crc ranges over [ off, off + len - 2). The crc
 * lsb is at off + len - 2, and the msb is at off + len - 1.
 */
void
spd_parse_crc(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	const uint16_t expect = si->si_data[off + len - 2] |
	    (si->si_data[off + len - 1] << 8);

	spd_parse_crc_expect(si, off, len - 2, expect, key);
}

void
spd_parse(spd_info_t *sip, const spd_parse_t *parse, size_t nparse)
{
	for (size_t i = 0; i < nparse; i++) {
		uint32_t len;

		if (parse[i].sp_len != 0) {
			len = parse[i].sp_len;
		} else {
			len = 1;
		}

		if (len + parse[i].sp_off >= sip->si_nbytes) {
			if ((sip->si_flags & SPD_INFO_F_INCOMPLETE) != 0)
				continue;
			sip->si_flags |= SPD_INFO_F_INCOMPLETE;
			ASSERT3U(parse[i].sp_off, <, UINT32_MAX);
			spd_nvl_insert_u32(sip, SPD_KEY_INCOMPLETE,
			    (uint32_t)parse[i].sp_off);
		} else {
			parse[i].sp_parse(sip, parse[i].sp_off, len,
			    parse[i].sp_key);
		}

		if (sip->si_error != LIBJEDEC_SPD_OK) {
			return;
		}
	}
}

static spd_error_t
spd_init_info(spd_info_t *sip)
{
	int ret;

	if ((ret = nvlist_alloc(&sip->si_nvl, NV_UNIQUE_NAME, 0)) != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		return (LIBJEDEC_SPD_NOMEM);
	}

	if ((ret = nvlist_alloc(&sip->si_errs, NV_UNIQUE_NAME, 0)) != 0) {
		VERIFY3S(ret, ==, ENOMEM);
		return (LIBJEDEC_SPD_NOMEM);
	}

	return (LIBJEDEC_SPD_OK);
}

static void
spd_fini_info(spd_info_t *sip)
{
	nvlist_free(sip->si_nvl);
	nvlist_free(sip->si_errs);
}

nvlist_t *
libjedec_spd(const uint8_t *buf, size_t nbytes, spd_error_t *err)
{
	int ret;
	spd_error_t set;
	spd_info_t si;

	if (err == NULL) {
		err = &set;
	}

	(void) memset(&si, 0, sizeof (spd_info_t));
	si.si_data = buf;
	si.si_nbytes = nbytes;

	*err = spd_init_info(&si);
	if (si.si_error != LIBJEDEC_SPD_OK) {
		goto fatal;
	}

	/*
	 * To begin parsing the SPD, we must first look at byte 2, which appears
	 * to almost always be the Key Byte / Host Bus Command Protocol Type
	 * which then tells us how the rest of the data is formatted.
	 */
	if (si.si_nbytes <= SPD_DRAM_TYPE) {
		*err = LIBJEDEC_SPD_TOOSHORT;
		goto fatal;
	}

	si.si_error = LIBJEDEC_SPD_OK;
	si.si_dram = buf[SPD_DRAM_TYPE];
	switch (si.si_dram) {
	case SPD_DT_DDR3_SDRAM:
		spd_parse_ddr3(&si);
		break;
	case SPD_DT_DDR4_SDRAM:
		spd_parse_ddr4(&si);
		break;
	case SPD_DT_LPDDR3_SDRAM:
	case SPD_DT_LPDDR4_SDRAM:
	case SPD_DT_LPDDR4X_SDRAM:
		spd_parse_lp4(&si);
		break;
	case SPD_DT_DDR5_SDRAM:
		spd_parse_ddr5(&si);
		break;
	case SPD_DT_LPDDR5_SDRAM:
	case SPD_DT_LPDDR5X_SDRAM:
		spd_parse_lp5(&si);
		break;
	default:
		*err = LIBJEDEC_SPD_UNSUP_TYPE;
		goto fatal;
	}

	/*
	 * We got everything, at this point add the error nvlist here.
	 */
	if (si.si_error == LIBJEDEC_SPD_OK) {
		if (!nvlist_empty(si.si_errs) &&
		    (ret = nvlist_add_nvlist(si.si_nvl, "errors",
		    si.si_errs)) != 0) {
			VERIFY3S(ret, ==, ENOMEM);
			*err = LIBJEDEC_SPD_NOMEM;
			goto fatal;
		}
		nvlist_free(si.si_errs);
		return (si.si_nvl);
	}

	*err = si.si_error;
fatal:
	spd_fini_info(&si);
	return (NULL);
}
