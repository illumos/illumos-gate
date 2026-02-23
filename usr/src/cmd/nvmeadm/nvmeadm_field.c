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
 * Logic to slice, dice, and print structured data from log pages and related
 * NVMe structures.
 */

#include <err.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <sys/bitext.h>
#include <libcmdutils.h>
#include <sys/ilstr.h>
#include <ctype.h>

#include "nvmeadm.h"

static const nvmeadm_log_field_info_t *field_log_map[] = {
	&suplog_field_info,
	&supcmd_field_info,
	&supmicmd_field_info,
	&supfeat_field_info,
	&phyeye_field_info,
	&ocp_vul_smart_field_info,
	&ocp_vul_errrec_field_info,
	&ocp_vul_devcap_field_info,
	&ocp_vul_unsup_field_info,
	&ocp_vul_telstr_field_info,
};

typedef struct {
	const char *fo_base;
	const char *fo_short;
	const char *fo_desc;
	char fo_val[256];
	char fo_hval[256];
	uint32_t fo_off;
	uint32_t fo_bitoff;
	uint32_t fo_len;
	uint32_t fo_bitlen;
} field_ofmt_t;

typedef enum {
	NVMEADM_FIELD_OT_SHORT,
	NVMEADM_FIELD_OT_DESC,
	NVMEADM_FIELD_OT_VALUE,
	NVMEADM_FIELD_OT_HUMAN,
	NVMEADM_FIELD_OT_BYTEOFF,
	NVMEADM_FIELD_OT_BITOFF,
	NVMEADM_FIELD_OT_BYTELEN,
	NVMEADM_FIELD_OT_BITLEN
} phyeye_otype_t;

static boolean_t
nvmeadm_field_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	size_t ret;
	field_ofmt_t *fo = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case NVMEADM_FIELD_OT_SHORT:
		if (fo->fo_base == NULL) {
			ret = strlcat(buf, fo->fo_short, buflen);
		} else {
			ret = snprintf(buf, buflen, "%s.%s", fo->fo_base,
			    fo->fo_short);
		}
		break;
	case NVMEADM_FIELD_OT_DESC:
		ret = strlcat(buf, fo->fo_desc, buflen);
		break;
	case NVMEADM_FIELD_OT_VALUE:
		if (fo->fo_val[0] == '\0')
			return (B_FALSE);

		ret = strlcat(buf, fo->fo_val, buflen);
		break;
	case NVMEADM_FIELD_OT_HUMAN:
		if (fo->fo_hval[0] != '\0') {
			ret = strlcat(buf, fo->fo_hval, buflen);
		} else {
			ret = strlcat(buf, fo->fo_val, buflen);
		}
		break;
	case NVMEADM_FIELD_OT_BYTEOFF:
		ret = snprintf(buf, buflen, "%u", fo->fo_off);
		break;
	case NVMEADM_FIELD_OT_BITOFF:
		ret = snprintf(buf, buflen, "%u", fo->fo_bitoff);
		break;
	case NVMEADM_FIELD_OT_BYTELEN:
		ret = snprintf(buf, buflen, "%u", fo->fo_len);
		break;
	case NVMEADM_FIELD_OT_BITLEN:
		ret = snprintf(buf, buflen, "%u", fo->fo_bitlen);
		break;
	default:
		abort();
	}

	return (ret < buflen);
}

const ofmt_field_t nvmeadm_field_ofmt[] = {
	{ "SHORT", 30, NVMEADM_FIELD_OT_SHORT, nvmeadm_field_ofmt_cb },
	{ "DESC", 30, NVMEADM_FIELD_OT_DESC, nvmeadm_field_ofmt_cb },
	{ "VALUE", 20, NVMEADM_FIELD_OT_VALUE, nvmeadm_field_ofmt_cb },
	{ "HUMAN", 20, NVMEADM_FIELD_OT_HUMAN, nvmeadm_field_ofmt_cb },
	{ "OFFSET", 8, NVMEADM_FIELD_OT_BYTEOFF, nvmeadm_field_ofmt_cb },
	{ "BITOFF", 8, NVMEADM_FIELD_OT_BITOFF, nvmeadm_field_ofmt_cb },
	{ "LENGTH", 8, NVMEADM_FIELD_OT_BYTELEN, nvmeadm_field_ofmt_cb },
	{ "BITLEN", 8, NVMEADM_FIELD_OT_BITLEN, nvmeadm_field_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

/*
 * We've been asked to apply a filter that matches on a field which may be a
 * top-level field or a nested one. For example, consider eom.odp.pefp. When
 * we're in parsable mode we only ever allow for absolute matches. This ensures
 * that if we add more fields to something that it doesn't end up changing the
 * output the user gets. However, if we're in a non-parsable mode then we'll
 * allow partial matches with a section. That is, 'eom' will match anything
 * starting with 'eom'. 'eom.odp' will match all fields with 'eom.odp'. Partial
 * matches within a field will not work, e.g. 'eom.o' would not match 'eom.odp'.
 *
 * However, a more specific match should match its parent. So, we want
 * 'eom.odp.pefp' to match 'eom' and 'eom.odp'. Even if we match those, we don't
 * count them as a use of the filter. Only exact matches count. This ensures
 * that if someone makes a typo or uses a non-existent field, say 'eom.foobar',
 * which does match 'eom', it still will generate an error.
 */
bool
nvmeadm_field_filter(nvmeadm_field_print_t *print, const char *base,
    const char *shrt)
{
	char buf[PATH_MAX];
	const char *check;
	bool match = false;

	if (print->fp_nfilts == 0) {
		return (true);
	}

	if (base != NULL && shrt != NULL) {
		(void) snprintf(buf, sizeof (buf), "%s.%s", base, shrt);
		check = buf;
	} else if (base == NULL) {
		VERIFY3P(shrt, !=, NULL);
		check = shrt;
	} else if (shrt == NULL) {
		VERIFY3P(base, !=, NULL);
		check = base;
	} else {
		abort();
	}

	/*
	 * Always check all filters so that way a user specifying the same thing
	 * multiple times doesn't end up in trouble.
	 */
	for (int i = 0; i < print->fp_nfilts; i++) {
		nvmeadm_field_filt_t *f = &print->fp_filts[i];

		if (strcmp(check, f->nff_str) == 0) {
			f->nff_used = true;
			match = true;
			continue;
		}

		if (print->fp_ofmt != NULL) {
			continue;
		}

		size_t len = strlen(check);
		if (len >= f->nff_len) {
			if (strncmp(check, f->nff_str, f->nff_len) == 0 &&
			    check[f->nff_len] == '.') {
				match = true;
				continue;
			}
		} else {
			if (strncmp(check, f->nff_str, len) == 0 &&
			    f->nff_str[len] == '.') {
				match = true;
				continue;
			}
		}
	}

	return (match);
}

static void
field_print_one_bit(nvmeadm_field_print_t *print, field_ofmt_t *ofarg,
    nvmeadm_field_type_t type, uint32_t level)
{
	uint32_t indent;

	if (!nvmeadm_field_filter(print, ofarg->fo_base, ofarg->fo_short)) {
		return;
	}

	if (print->fp_ofmt != NULL) {
		ofmt_print(print->fp_ofmt, ofarg);
		return;
	}

	indent = 4 + print->fp_indent * 2;
	if (level > 1) {
		indent += (level - 1) * 7;
	}

	(void) printf("%*s|--> %s: ", indent, "", ofarg->fo_desc);
	switch (type) {
	case NVMEADM_FT_STRMAP:
		(void) printf("%s (%s)\n", ofarg->fo_hval,
		    ofarg->fo_val);
		break;
	case NVMEADM_FT_BITS:
		(void) printf("%s\n", ofarg->fo_val);
		break;
	case NVMEADM_FT_HEX:
	case NVMEADM_FT_PERCENT:
		(void) printf("%s\n", ofarg->fo_hval);
		break;
	default:
		abort();
	}
}

/*
 * Extract what should be a series of printable ASCII bytes, but don't assume
 * that they are. Similarly, assume we need to trim any trailing spaces in the
 * field. If anything in here is not ASCII, we'll escape it.
 */
static void
field_extract_ascii(const void *data, nvmeadm_field_type_t type, size_t len,
    size_t off, field_ofmt_t *ofarg)
{
	bool zpad = type == NVMEADM_FT_ASCIIZ;
	const uint8_t *u8p = data + off;

	while (len > 0) {
		if ((zpad && u8p[len - 1] == '\0') ||
		    (!zpad && u8p[len - 1] == ' ')) {
			len--;
		} else {
			break;
		}
	}

	if (len == 0)
		return;

	ilstr_t ilstr;
	ilstr_init_prealloc(&ilstr, ofarg->fo_val, sizeof (ofarg->fo_val));

	for (size_t i = 0; i < len; i++) {
		if (isascii(u8p[i]) && isprint(u8p[i])) {
			ilstr_append_char(&ilstr, u8p[i]);
		} else {
			ilstr_aprintf(&ilstr, "\\x%02x", u8p[i]);
		}
	}

	if (ilstr_errno(&ilstr) != ILSTR_ERROR_OK) {
		errx(-1, "failed to construct internal string for field %s: "
		    "0x%x", ofarg->fo_desc, ilstr_errno(&ilstr));
	}

	(void) memcpy(ofarg->fo_hval, ofarg->fo_val, ilstr_len(&ilstr) + 1);
	ilstr_fini(&ilstr);
}

static uint64_t
nvmeadm_apply_addend(uint64_t val, const nvmeadm_field_addend_t *add)
{
	if (add->nfa_shift > 0) {
		val <<= add->nfa_shift;
	}

	val += add->nfa_addend;
	return (val);
}

static void
nvmeadm_field_bit_extract(const nvmeadm_field_bit_t *bit, uint64_t fval,
    field_ofmt_t *ofarg, uint64_t *bp)
{
	VERIFY3U(bit->nfb_hibit, <, 64);
	uint64_t bval = bitx64(fval, bit->nfb_hibit, bit->nfb_lowbit);
	if (bp != NULL)
		*bp = bval;

	(void) snprintf(ofarg->fo_val, sizeof (ofarg->fo_val), "0x%" PRIx64,
	    bval);
	switch (bit->nfb_type) {
	case NVMEADM_FT_HEX:
		/*
		 * The "human" string is the version with the addend applied.
		 */
		bval = nvmeadm_apply_addend(bval, &bit->nfb_addend);
		(void) snprintf(ofarg->fo_hval, sizeof (ofarg->fo_hval),
		    "0x%" PRIx64, bval);
		break;
	case NVMEADM_FT_UNIT:
		bval = nvmeadm_apply_addend(bval, &bit->nfb_addend);
		(void) snprintf(ofarg->fo_hval, sizeof (ofarg->fo_hval),
		    "%" PRIu64 " %s", bval, bit->nfb_addend.nfa_unit);
		break;
	case NVMEADM_FT_BITS:
		/* No human string for this. */
		break;
	case NVMEADM_FT_STRMAP:
		if (bval < ARRAY_SIZE(bit->nfb_strs) &&
		    bit->nfb_strs[bval] != NULL) {
			(void) strlcpy(ofarg->fo_hval, bit->nfb_strs[bval],
			    sizeof (ofarg->fo_hval));
		} else {
			(void) strlcpy(ofarg->fo_hval, "reserved",
			    sizeof (ofarg->fo_hval));
		}
		break;
	case NVMEADM_FT_PERCENT:
		(void) snprintf(ofarg->fo_hval, sizeof (ofarg->fo_hval), "%u%%",
		    bval);
		break;
	case NVMEADM_FT_BYTES:
		bval = nvmeadm_apply_addend(bval, &bit->nfb_addend);
		nicenum(bval, ofarg->fo_hval, sizeof (ofarg->fo_hval));
		break;
	case NVMEADM_FT_GUID:
		/* GUIDs don't fit inside the 8 byte limit we have */
		abort();
	case NVMEADM_FT_ASCII:
	case NVMEADM_FT_ASCIIZ:
		/* We should handle this once it shows up here */
		abort();
	case NVMEADM_FT_CONTAINER:
		/* Containers are only used at the field level right now. */
		abort();
	}
}

static void
field_print_bits(nvmeadm_field_print_t *print, const nvmeadm_field_bit_t *bits,
    size_t nbits, uint64_t val, const char *base, size_t off, size_t bitoff,
    uint32_t level)
{
	for (size_t i = 0; i < nbits; i++) {
		uint8_t blen = bits[i].nfb_hibit - bits[i].nfb_lowbit + 1;
		field_ofmt_t ofarg = { 0 };

		/*
		 * See if this field is one that is meaningful to this revision
		 * of the log page or controller. If the version is NULL or the
		 * revision is 0 in the field, then there is nothing to check.
		 * While most fields add something in a new revision, a few also
		 * change things, so we also check for a max revision as well.
		 */
		if (bits[i].nfb_rev != 0 && bits[i].nfb_rev > print->fp_rev) {
			continue;
		}

		if (bits[i].nfb_maxrev != 0 && print->fp_rev >
		    bits[i].nfb_maxrev) {
			continue;
		}

		if (bits[i].nfb_vers != NULL && print->fp_vers != NULL &&
		    !nvme_vers_atleast(print->fp_vers, bits[i].nfb_vers)) {
			continue;
		}

		ofarg.fo_base = base;
		ofarg.fo_short = bits[i].nfb_short;
		ofarg.fo_desc = bits[i].nfb_desc;
		ofarg.fo_off = off + (bitoff + bits[i].nfb_lowbit) / NBBY;
		ofarg.fo_bitoff = (bitoff + bits[i].nfb_lowbit) % NBBY;
		ofarg.fo_len = blen / NBBY;
		ofarg.fo_bitlen = blen % NBBY;

		uint64_t bit_val;
		nvmeadm_field_bit_extract(&bits[i], val, &ofarg, &bit_val);

		field_print_one_bit(print, &ofarg, bits[i].nfb_type, level);

		if (bits[i].nfb_type == NVMEADM_FT_BITS) {
			char buf[256];

			(void) snprintf(buf, sizeof (buf), "%s.%s", base,
			    bits[i].nfb_short);
			field_print_bits(print, bits[i].nfb_bits,
			    bits[i].nfb_nbits, bit_val, buf, ofarg.fo_off,
			    ofarg.fo_bitoff, level + 1);
		}
	}
}

static void
field_print_one(nvmeadm_field_print_t *print, field_ofmt_t *ofarg,
    nvmeadm_field_type_t type)
{
	if (!nvmeadm_field_filter(print, ofarg->fo_base, ofarg->fo_short)) {
		return;
	}

	if (print->fp_ofmt != NULL) {
		if (type == NVMEADM_FT_CONTAINER)
			return;
		ofmt_print(print->fp_ofmt, ofarg);
		return;
	}

	uint_t indent = 2 + print->fp_indent * 2;
	(void) printf("%*s%s:", indent, "", ofarg->fo_desc);
	switch (type) {
	case NVMEADM_FT_BITS:
		(void) printf(" %s\n", ofarg->fo_val);
		break;
	case NVMEADM_FT_STRMAP:
		(void) printf(" %s (%s)\n", ofarg->fo_hval, ofarg->fo_val);
		break;
	case NVMEADM_FT_HEX:
	case NVMEADM_FT_UNIT:
	case NVMEADM_FT_BYTES:
	case NVMEADM_FT_PERCENT:
	case NVMEADM_FT_GUID:
	case NVMEADM_FT_ASCII:
	case NVMEADM_FT_ASCIIZ:
		(void) printf(" %s\n", ofarg->fo_hval);
		break;
	case NVMEADM_FT_CONTAINER:
		(void) printf("\n");
		break;
	}
}

/*
 * Extract the u128 from where we are right now.
 */
static void
nvmeadm_field_extract_u128(const nvmeadm_field_t *field, const void *data,
    field_ofmt_t *ofarg)
{
	nvme_uint128_t u128;
	const uint8_t *u8p;

	(void) memcpy(&u128, data + field->nf_off, sizeof (u128));

	if (u128.hi == 0) {
		(void) snprintf(ofarg->fo_val, sizeof (ofarg->fo_val), "0x%x",
		    u128.lo);
	} else {
		(void) snprintf(ofarg->fo_val, sizeof (ofarg->fo_val),
		    "0x%x%016x", u128.hi, u128.lo);
	}

	switch (field->nf_type) {
	case NVMEADM_FT_BYTES:
		/*
		 * Right now we a 64-bit byte value is 16 EiB. If we have more
		 * than that, error so we do something more clever, but
		 * otherwise punt for the time being.
		 */
		if (u128.hi != 0) {
			warnx("encountered 128-bit size with upper bits set "
			    "for field %s, cannot accurately convert",
			    field->nf_desc);
			u128.lo = UINT64_MAX;
		}

		if (field->nf_addend.nfa_shift != 0 ||
		    field->nf_addend.nfa_addend != 0) {
			warnx("encountered 128-bit size with addend request "
			    "for field %s, but conversion not implemented",
			    field->nf_desc);
		}

		nicenum(u128.lo, ofarg->fo_hval, sizeof (ofarg->fo_hval));
		break;
	case NVMEADM_FT_GUID:
		u8p = data + field->nf_off;
		(void) snprintf(ofarg->fo_hval, sizeof (ofarg->fo_hval),
		    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		    "%02x%02x%02x%02x%02x%02x",
		    u8p[15], u8p[14], u8p[13], u8p[12],
		    u8p[11], u8p[10], u8p[9], u8p[8],
		    u8p[7], u8p[6], u8p[5], u8p[4],
		    u8p[3], u8p[2], u8p[1], u8p[0]);
		break;
	case NVMEADM_FT_HEX:
		if (field->nf_addend.nfa_shift != 0 ||
		    field->nf_addend.nfa_addend != 0) {
			warnx("encountered 128-bit field with addend, but "
			    "cannot apply it");
		}
		(void) memcpy(ofarg->fo_hval, ofarg->fo_val,
		    sizeof (ofarg->fo_hval));
		break;
	default:
		break;
	}
}

static void
nvmeadm_field_extract(const nvmeadm_field_t *field, const void *data,
    field_ofmt_t *ofarg, uint64_t *bp)
{
	uint64_t val;

	/*
	 * Don't touch containers. There is nothing to extract.
	 */
	if (field->nf_type == NVMEADM_FT_CONTAINER)
		return;

	/*
	 * If this is an ASCII field, then we just handle this immediately.
	 */
	if (field->nf_type == NVMEADM_FT_ASCII ||
	    field->nf_type == NVMEADM_FT_ASCIIZ) {
		field_extract_ascii(data, field->nf_type, field->nf_len,
		    field->nf_off, ofarg);
		return;
	}

	/*
	 * Next look at the type and size and see if this is something that we
	 * can deal with simply. Items that are less than a u64 are easy. If we
	 * had better C23 support and therefore could deal with a u128, then
	 * this would be simpler too. Until then, we split this based on things
	 * larger than a u64 and those not.
	 */
	if (field->nf_len > sizeof (uint64_t)) {
		switch (field->nf_type) {
		case NVMEADM_FT_HEX:
		case NVMEADM_FT_BYTES:
		case NVMEADM_FT_GUID:
			VERIFY3U(field->nf_len, ==, 16);
			nvmeadm_field_extract_u128(field, data, ofarg);
			break;
		default:
			abort();
		}
		return;
	}

	/*
	 * NVMe integers are defined as being encoded in little endian.
	 */
	val = 0;
	const uint8_t *u8p = data + field->nf_off;
	for (size_t i = 0; i < field->nf_len; i++) {
		uint8_t shift = i * NBBY;
		val |= (uint64_t)u8p[i] << shift;
	}

	if (bp != NULL)
		*bp = val;
	(void) snprintf(ofarg->fo_val, sizeof (ofarg->fo_val), "0x%" PRIx64,
	    val);

	switch (field->nf_type) {
	case NVMEADM_FT_HEX:
		/*
		 * The "human" string is the version with the addend applied.
		 */
		val = nvmeadm_apply_addend(val, &field->nf_addend);
		(void) snprintf(ofarg->fo_hval, sizeof (ofarg->fo_hval),
		    "0x%" PRIx64, val);
		break;
	case NVMEADM_FT_UNIT:
		val = nvmeadm_apply_addend(val, &field->nf_addend);
		(void) snprintf(ofarg->fo_hval, sizeof (ofarg->fo_hval),
		    "%" PRIu64 " %s", val, field->nf_addend.nfa_unit);
		break;
	case NVMEADM_FT_BITS:
		/* No human string for these */
		break;
	case NVMEADM_FT_STRMAP:
		if (val < ARRAY_SIZE(field->nf_strs) &&
		    field->nf_strs[val] != NULL) {
			(void) strlcpy(ofarg->fo_hval, field->nf_strs[val],
			    sizeof (ofarg->fo_hval));
		} else {
			(void) strlcpy(ofarg->fo_hval, "reserved",
			    sizeof (ofarg->fo_hval));
		}
		break;
	case NVMEADM_FT_BYTES:
		val = nvmeadm_apply_addend(val, &field->nf_addend);
		nicenum(val, ofarg->fo_hval, sizeof (ofarg->fo_hval));
		break;
	case NVMEADM_FT_PERCENT:
		(void) snprintf(ofarg->fo_hval, sizeof (ofarg->fo_hval), "%u%%",
		    val);
		break;
	case NVMEADM_FT_GUID:
		/*
		 * GUIDs are larger than 8 bytes and so we should never hit
		 * this.
		 */
		abort();
	case NVMEADM_FT_ASCII:
	case NVMEADM_FT_ASCIIZ:
	case NVMEADM_FT_CONTAINER:
		/* Should already be handled above */
		abort();
	}
}

void
nvmeadm_field_print(nvmeadm_field_print_t *print)
{
	if (print->fp_ofmt == NULL && print->fp_header != NULL &&
	    nvmeadm_field_filter(print, print->fp_base, NULL)) {
		(void) printf("%s\n", print->fp_header);
	}

	for (size_t i = 0; i < print->fp_nfields; i++) {
		const nvmeadm_field_t *field = &print->fp_fields[i];
		field_ofmt_t ofarg = { 0 };

		/*
		 * See if this field is one that is meaningful to this revision
		 * of the log page or controller. If the version is NULL or the
		 * revision is 0 in the field, then there is nothing to check.
		 */
		if (field->nf_rev != 0 && field->nf_rev > print->fp_rev) {
			continue;
		}

		if (field->nf_maxrev != 0 && print->fp_rev > field->nf_maxrev) {
			continue;
		}

		if (field->nf_vers != NULL && print->fp_vers != NULL &&
		    !nvme_vers_atleast(print->fp_vers, field->nf_vers)) {
			continue;
		}

		ofarg.fo_base = print->fp_base;
		ofarg.fo_short = field->nf_short;
		ofarg.fo_desc = field->nf_desc;
		ofarg.fo_off = print->fp_off + field->nf_off;
		ofarg.fo_bitoff = 0;
		ofarg.fo_len = field->nf_len;
		ofarg.fo_bitlen = 0;

		/*
		 * Extract the value from the field and perform any conversions
		 * to a human value where appropriate.
		 */
		uint64_t bit_val;
		nvmeadm_field_extract(field, print->fp_data, &ofarg, &bit_val);

		field_print_one(print, &ofarg, field->nf_type);

		/*
		 * Now that we've dealt with this, handle anything that's
		 * somewhat recursive in nature.
		 */
		if (field->nf_type == NVMEADM_FT_CONTAINER) {
			char buf[256];
			nvmeadm_field_print_t copy = *print;

			if (print->fp_base == NULL) {
				(void) strlcpy(buf, field->nf_short,
				    sizeof (buf));
			} else {
				(void) snprintf(buf, sizeof (buf), "%s.%s",
				    print->fp_base, field->nf_short);
			}

			copy.fp_header = NULL;
			copy.fp_base = buf;
			copy.fp_fields = field->nf_fields;
			copy.fp_nfields = field->nf_nfields;
			copy.fp_data += field->nf_off;
			copy.fp_dlen = field->nf_len;
			copy.fp_off += field->nf_off;
			copy.fp_indent++;

			nvmeadm_field_print(&copy);
		} else if (field->nf_type == NVMEADM_FT_BITS) {
			char buf[256];

			if (print->fp_base == NULL) {
				(void) strlcpy(buf, field->nf_short,
				    sizeof (buf));
			} else {
				(void) snprintf(buf, sizeof (buf), "%s.%s",
				    print->fp_base, field->nf_short);
			}

			field_print_bits(print, field->nf_bits, field->nf_nbits,
			    bit_val, buf, ofarg.fo_off, 0, 1);
		}
	}
}

bool
nvmeadm_log_page_fields(const nvme_process_arg_t *npa, const char *name,
    const void *data, size_t len, nvmeadm_field_filt_t *filts, size_t nfilts,
    nvmeadm_log_field_flag_t flags)
{
	bool ret = true, found = false;
	VERIFY0(flags & ~NVMEADM_LFF_CHECK_NAME);

	/*
	 * If we don't have a log page name, that's an indication that we're
	 * being asked to just do our hex print.
	 */
	if (name == NULL) {
		nvmeadm_dump_hex(data, len);
		return (ret);
	}

	for (size_t i = 0; i < ARRAY_SIZE(field_log_map); i++) {
		if (strcmp(name, field_log_map[i]->nlfi_log) != 0) {
			continue;
		}

		/*
		 * We've found a match for this log page. Ensure we don't hex
		 * dump it at the end.
		 */
		found = true;

		if (len < field_log_map[i]->nlfi_min) {
			errx(-1, "cannot print log %s: log requires "
			    "0x%zx bytes of data but only have 0x%zx",
			    name, field_log_map[i]->nlfi_min, len);
		}

		nvmeadm_field_print_t print = { 0 };
		if (field_log_map[i]->nlfi_getrev != NULL) {
			print.fp_rev = field_log_map[i]->nlfi_getrev(data,
			    len);
		}

		/*
		 * This may be NULL if we're not getting this fresh from a
		 * controller.
		 */
		print.fp_vers = npa->npa_version;

		print.fp_filts = filts;
		print.fp_nfilts = nfilts;
		print.fp_ofmt = npa->npa_ofmt;

		/*
		 * A registered log page may instead ask to drive the process as
		 * there is variable data or similar present.
		 */
		if (field_log_map[i]->nlfi_drive != NULL) {
			if (!field_log_map[i]->nlfi_drive(&print, data, len)) {
				ret = false;
			}
		} else {
			print.fp_fields = field_log_map[i]->nlfi_fields;
			print.fp_nfields = field_log_map[i]->nlfi_nfields;

			/*
			 * We set the base string to NULL for most log pages
			 * that aren't comprised of variable components by
			 * default. Ones that are variable instead will set this
			 * as part of their drive function callback.
			 */
			print.fp_base = NULL;

			print.fp_data = data;
			print.fp_dlen = len;

			nvmeadm_field_print(&print);
			break;
		}
	}

	if (!found) {
		if ((flags & NVMEADM_LFF_CHECK_NAME) != 0) {
			warnx("unable to print log page %s: the log page is "
			    "either unknown or printing information is missing",
			    name);
			ret = false;
		}

		if (npa->npa_ofmt != NULL) {
			errx(-1, "parsable mode requested, but unable to print "
			    "parsable output");
		}

		nvmeadm_dump_hex(data, len);
	}

	for (size_t i = 0; i < nfilts; i++) {
		if (!filts[i].nff_used) {
			warnx("filter '%s' did not match any fields",
			    filts[i].nff_str);
			ret = false;
		}
	}

	return (ret);
}
