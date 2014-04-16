/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <msg.h>
#include <_elfdump.h>
#include <struct_layout.h>
#include <conv.h>


/*
 * Functions for extracting and formatting numeric values from
 * structure data.
 */




/*
 * Extract the integral field into the value union given and
 * perform any necessary byte swapping to make the result readable
 * on the elfdump host.
 */
void
sl_extract_num_field(const char *data, int do_swap, const sl_field_t *fdesc,
    sl_data_t *field_data)
{
	/* Copy the value bytes into our union */
	(void) memcpy(field_data, data + fdesc->slf_offset,
	    fdesc->slf_eltlen);

	/* Do byte swapping as necessary */
	if (do_swap) {
		switch (fdesc->slf_eltlen) {
		case 2:
			field_data->sld_ui16 = BSWAP_HALF(field_data->sld_ui16);
			break;

		case 4:
			field_data->sld_ui32 = BSWAP_WORD(field_data->sld_ui32);
			break;

		case 8:
			field_data->sld_ui64 =
			    BSWAP_LWORD(field_data->sld_ui64);
			break;
		}
	}
}

/*
 * Extract the given integer field, and return its value, cast
 * to Word. Note that this operation must not be used on values
 * that can be negative, or larger than 32-bits, as information
 * can be lost.
 */
Word
sl_extract_as_word(const char *data, int do_swap, const sl_field_t *fdesc)
{
	sl_data_t	v;

	/* Extract the value from the raw data */
	sl_extract_num_field(data, do_swap, fdesc, &v);

	if (fdesc->slf_sign) {
		switch (fdesc->slf_eltlen) {
			case 1:
				return ((Word) v.sld_i8);
			case 2:
				return ((Word) v.sld_i16);
			case 4:
				return ((Word) v.sld_i32);
			case 8:
				return ((Word) v.sld_i64);
		}
	} else {
		switch (fdesc->slf_eltlen) {
			case 1:
				return ((Word) v.sld_ui8);
			case 2:
				return ((Word) v.sld_ui16);
			case 4:
				return ((Word) v.sld_ui32);
			case 8:
				return ((Word) v.sld_ui64);
		}
	}

	/* This should not be reached */
	assert(0);
	return (0);
}


/*
 * Extract the given integer field, and return its value, cast
 * to Lword. Note that this operation must not be used on values
 * that can be negative, as information can be lost.
 */
Lword
sl_extract_as_lword(const char *data, int do_swap, const sl_field_t *fdesc)
{
	sl_data_t	v;

	/* Extract the value from the raw data */
	sl_extract_num_field(data, do_swap, fdesc, &v);

	if (fdesc->slf_sign) {
		switch (fdesc->slf_eltlen) {
			case 1:
				return ((Lword) v.sld_i8);
			case 2:
				return ((Lword) v.sld_i16);
			case 4:
				return ((Lword) v.sld_i32);
			case 8:
				return ((Lword) v.sld_i64);
		}
	} else {
		switch (fdesc->slf_eltlen) {
			case 1:
				return ((Lword) v.sld_ui8);
			case 2:
				return ((Lword) v.sld_ui16);
			case 4:
				return ((Lword) v.sld_ui32);
			case 8:
				return ((Lword) v.sld_ui64);
		}
	}

	/* This should not be reached */
	assert(0);
	return (0);
}


/*
 * Extract the given integer field, and return its value, cast
 * to int32_t. Note that this operation must not be used on unsigned
 * values larger than 31-bits, or on signed values larger than 32-bits,
 * as information can be lost.
 */
Sword
sl_extract_as_sword(const char *data, int do_swap, const sl_field_t *fdesc)
{
	sl_data_t	v;

	/* Extract the value from the raw data */
	sl_extract_num_field(data, do_swap, fdesc, &v);

	if (fdesc->slf_sign) {
		switch (fdesc->slf_eltlen) {
			case 1:
				return ((Sword)v.sld_i8);
			case 2:
				return ((Sword)v.sld_i16);
			case 4:
				return ((Sword)v.sld_i32);
			case 8:
				return ((Sword)v.sld_i64);
		}
	} else {
		switch (fdesc->slf_eltlen) {
			case 1:
				return ((Sword)v.sld_ui8);
			case 2:
				return ((Sword)v.sld_ui16);
			case 4:
				return ((Sword)v.sld_ui32);
			case 8:
				return ((Sword)v.sld_ui64);
		}
	}

	/* This should not be reached */
	assert(0);
	return (0);
}


/*
 * Extract the integral field and format it into the supplied buffer.
 */
const char *
sl_fmt_num(const char *data, int do_swap, const sl_field_t *fdesc,
    sl_fmt_num_t fmt_type, sl_fmtbuf_t buf)
{
	/*
	 * These static arrays are indexed by [fdesc->slf_sign][fmt_type]
	 * to get a format string to use for the specified combination.
	 */
	static const char *fmt_i8[2][3] = {
		{
			MSG_ORIG(MSG_CNOTE_FMT_U),
			MSG_ORIG(MSG_CNOTE_FMT_X),
			MSG_ORIG(MSG_CNOTE_FMT_Z2X)
		},
		{
			MSG_ORIG(MSG_CNOTE_FMT_D),
			MSG_ORIG(MSG_CNOTE_FMT_X),
			MSG_ORIG(MSG_CNOTE_FMT_Z2X)
		}
	};
	static const char *fmt_i16[2][3] = {
		{
			MSG_ORIG(MSG_CNOTE_FMT_U),
			MSG_ORIG(MSG_CNOTE_FMT_X),
			MSG_ORIG(MSG_CNOTE_FMT_Z4X)
		},
		{
			MSG_ORIG(MSG_CNOTE_FMT_D),
			MSG_ORIG(MSG_CNOTE_FMT_X),
			MSG_ORIG(MSG_CNOTE_FMT_Z4X)
		}
	};
	static const char *fmt_i32[2][3] = {
		{
			MSG_ORIG(MSG_CNOTE_FMT_U),
			MSG_ORIG(MSG_CNOTE_FMT_X),
			MSG_ORIG(MSG_CNOTE_FMT_Z8X)
		},
		{
			MSG_ORIG(MSG_CNOTE_FMT_D),
			MSG_ORIG(MSG_CNOTE_FMT_X),
			MSG_ORIG(MSG_CNOTE_FMT_Z8X)
		}
	};
	static const char *fmt_i64[2][3] = {
		{
			MSG_ORIG(MSG_CNOTE_FMT_LLU),
			MSG_ORIG(MSG_CNOTE_FMT_LLX),
			MSG_ORIG(MSG_CNOTE_FMT_Z16LLX)
		},
		{
			MSG_ORIG(MSG_CNOTE_FMT_LLD),
			MSG_ORIG(MSG_CNOTE_FMT_LLX),
			MSG_ORIG(MSG_CNOTE_FMT_Z16LLX)
		}
	};

	sl_data_t	v;

	/* Extract the value from the raw data */
	sl_extract_num_field(data, do_swap, fdesc, &v);

	/*
	 * Format into the buffer. Note that we depend on the signed
	 * and unsigned versions of each width being equivalent as long
	 * as the format specifies the proper formatting.
	 */
	switch (fdesc->slf_eltlen) {
	case 1:
		(void) snprintf(buf, sizeof (sl_fmtbuf_t),
		    fmt_i8[fdesc->slf_sign][fmt_type], (uint32_t)v.sld_ui8);
		break;

	case 2:
		(void) snprintf(buf, sizeof (sl_fmtbuf_t),
		    fmt_i16[fdesc->slf_sign][fmt_type], (uint32_t)v.sld_ui16);
		break;

	case 4:
		(void) snprintf(buf, sizeof (sl_fmtbuf_t),
		    fmt_i32[fdesc->slf_sign][fmt_type], v.sld_ui32);
		break;

	case 8:
		(void) snprintf(buf, sizeof (sl_fmtbuf_t),
		    fmt_i64[fdesc->slf_sign][fmt_type], v.sld_ui64);
		break;
	}

	return (buf);
}

/*
 * Return structure layout definition for the given machine type,
 * or NULL if the specified machine is not supported.
 */
const sl_arch_layout_t	*
sl_mach(Half mach)
{
	switch (mach) {
	case EM_386:
		return (struct_layout_i386());

	case EM_AMD64:
		return (struct_layout_amd64());

	case EM_SPARC:
	case EM_SPARC32PLUS:
		return (struct_layout_sparc());

	case EM_SPARCV9:
		return (struct_layout_sparcv9());
	}

	/* Unsupported architecture */
	return (NULL);
}
