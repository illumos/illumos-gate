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
 * Copyright 2023 Oxide Computer Company
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
 * Currently we support all of DDR4 and DDD5 based SPD information with the
 * exception of some NVDIMM properties.
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

void
spd_insert_range(spd_info_t *si, const char *key, uint8_t raw_val,
    const spd_value_range_t *range)
{
	/*
	 * Apply any base or multiple to the value. If the min or max are zero,
	 * then we ignore them. We apply the base before a multiple.
	 */
	uint32_t min = 0, max = UINT32_MAX;
	uint32_t act = raw_val + range->svr_base;

	if (range->svr_mult != 0) {
		act *= range->svr_mult;
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
	const uint8_t add = SPD_DDR4_SPD_REV_ENC(data);

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
	uint32_t nbytes = 0;
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

	int ret = snprintf(buf, sizeof (buf), "%x.%x", maj, min);
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
	const uint8_t back = SPD_DDR5_COM_THICK_FRONT(data);

	spd_insert_range(si, SPD_KEY_MOD_FRONT_THICK, front, &spd_thick_range);
	spd_insert_range(si, SPD_KEY_MOD_BACK_THICK, back, &spd_thick_range);
}

/*
 * Calculate the DRAM CRC16. The crc ranges over [ off, off + len - 2). The crc
 * lsb is at off + len - 2, and the msb is at off + len - 1. The JEDEC specs
 * describe the algorithm (e.g. 21-C Annex L, 8.1.53).
 */
void
spd_parse_crc(spd_info_t *si, uint32_t off, uint32_t len, const char *key)
{
	uint32_t crc = 0;
	const uint16_t expect = si->si_data[off + len - 2] |
	    (si->si_data[off + len - 1] << 8);

	for (uint32_t i = 0; i < len - 2; i++) {
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
	case SPD_DT_DDR4_SDRAM:
		spd_parse_ddr4(&si);
		break;
	case SPD_DT_DDR5_SDRAM:
		spd_parse_ddr5(&si);
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
