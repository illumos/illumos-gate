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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * String conversion routine for hardware capabilities types.
 */
#include	<strings.h>
#include	<stdio.h>
#include	<elfcap.h>
#include	"cap_msg.h"
#include	"_conv.h"

const conv_ds_t **
conv_cap_tag_strings(Conv_fmt_flags_t fmt_flags)
{
#if	(CA_SUNW_NUM != (CA_SUNW_HW_2 + 1))
#error	"CA_SUNW_NUM has grown"
#endif
	static const Msg	tags_cf[] = {
		MSG_CA_SUNW_NULL_CF,	MSG_CA_SUNW_HW_1_CF,
		MSG_CA_SUNW_SF_1_CF,	MSG_CA_SUNW_HW_2_CF
	};
	static const Msg	tags_nf[] = {
		MSG_CA_SUNW_NULL_NF,	MSG_CA_SUNW_HW_1_NF,
		MSG_CA_SUNW_SF_1_NF,	MSG_CA_SUNW_HW_2_NF,
	};
	static const conv_ds_msg_t ds_tags_cf = {
	    CONV_DS_MSG_INIT(ELFCLASSNONE, tags_cf) };
	static const conv_ds_msg_t ds_tags_nf = {
	    CONV_DS_MSG_INIT(ELFCLASSNONE, tags_nf) };

	static const conv_ds_t *ds_cf[] = { CONV_DS_ADDR(ds_tags_cf), NULL };
	static const conv_ds_t *ds_nf[] = { CONV_DS_ADDR(ds_tags_nf), NULL };


	return ((CONV_TYPE_FMT_ALT(fmt_flags) == CONV_FMT_ALT_NF) ?
	    ds_nf : ds_cf);
}

conv_iter_ret_t
conv_iter_cap_tags(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_ds(ELFOSABI_NONE, EM_NONE,
	    conv_cap_tag_strings(fmt_flags), func, uvalue));
}

/*
 * Given an array of elfcap_desc_t, and a count, call the specified
 * iteration for each value in the array.
 */
static conv_iter_ret_t
conv_iter_elfcap(const elfcap_desc_t *cdp, uint_t cnum,
    Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func, void *uvalue)
{
	const char	*str;

	fmt_flags = CONV_TYPE_FMT_ALT(fmt_flags);

	for (; cnum-- > 0; cdp++) {
		/*
		 * Skip "reserved" bits. These are unassigned bits in the
		 * middle of the assigned range.
		 */
		if (cdp->c_val == 0)
			continue;

		switch (fmt_flags) {
		default:
			str = cdp->c_full.s_str;
			break;
		case CONV_FMT_ALT_CFNP:
			str = cdp->c_uc.s_str;
			break;
		case CONV_FMT_ALT_NF:
			str = cdp->c_lc.s_str;
			break;
		}

		if ((* func)(str, cdp->c_val, uvalue) == CONV_ITER_DONE)
			return (CONV_ITER_DONE);
	}

	return (CONV_ITER_CONT);
}

/*
 * Iterate the strings for CA_SUNW_HW1
 */
conv_iter_ret_t
conv_iter_cap_val_hw1(Half mach, Conv_fmt_flags_t fmt_flags,
    conv_iter_cb_t func, void *uvalue)
{
	if ((mach == EM_386) || (mach == EM_486) ||
	    (mach == EM_AMD64) || (mach == CONV_MACH_ALL))
		if (conv_iter_elfcap(elfcap_getdesc_hw1_386(),
		    ELFCAP_NUM_HW1_386, fmt_flags, func, uvalue) ==
		    CONV_ITER_DONE)
			return (CONV_ITER_DONE);

	if ((mach == EM_SPARC) || (mach == EM_SPARC32PLUS) ||
	    (mach == EM_SPARCV9) || (mach == CONV_MACH_ALL))
		if (conv_iter_elfcap(elfcap_getdesc_hw1_sparc(),
		    ELFCAP_NUM_HW1_SPARC, fmt_flags, func, uvalue) ==
		    CONV_ITER_DONE)
			return (CONV_ITER_DONE);

	return (CONV_ITER_CONT);
}

/*
 * Iterate the strings for CA_SUNW_SF1
 */
conv_iter_ret_t
conv_iter_cap_val_sf1(Conv_fmt_flags_t fmt_flags, conv_iter_cb_t func,
    void *uvalue)
{
	return (conv_iter_elfcap(elfcap_getdesc_sf1(), ELFCAP_NUM_SF1,
	    fmt_flags, func, uvalue));
}
