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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdio.h>
#include	<strings.h>
#include	<_machelf.h>
#include	"_conv.h"
#include	"globals_msg.h"


/*
 * Map an integer into a descriptive string.
 *
 * entry:
 *	inv_buf - A buffer into which this routine can format
 *		a result string, if necessary.
 *	val - The value for which a string is desired.
 *	flags - CONV_FMT_* values to be passed to conv_invalid_val() if
 *		necessary. The caller is reponsible for having examined
 *		the CONV_FMT_ALT_* part of flags and passing the proper
 *		msg array.
 *	num_msg - # of Msg entries in msg.
 *	msg - Array of num_msg Msg items corresponding to the possible
 *		strings corresponding to val.
 *	local_sgs_msg - Message string table from module from which
 *		this function is called.
 *
 * exit:
 *	If val lies in the range [0-(num_msg-1)], then the string
 *	corresponding to it is returned. If val is outside the range,
 *	conv_invalid_val() is called to format an ASCII representation
 *	of it into inv_buf, and that is returned.
 */
/*ARGSUSED5*/
static const char *
map_msg2str(Conv_inv_buf_t *inv_buf, Conv_elfvalue_t val,
    Conv_fmt_flags_t flags, size_t num_msg, const Msg *msg,
    const char *local_sgs_msg)
{
	if ((val < num_msg) && (msg[val] != 0))
		return (MSG_ORIG_STRTAB(msg[val], local_sgs_msg));

	/* If we get here, it's an unknown value */
	return (conv_invalid_val(inv_buf, val, flags));
}

/*
 * Map an integer into a descriptive string from a NULL terminated
 * array of Val_desc or Val_desc2 descriptors.
 *
 * entry:
 *	inv_buf - A buffer into which this routine can format
 *		a result string, if necessary.
 *	osabi,mach (_conv_vd22str only) - The osab/mach under which
 *		val is to be interpreted. Items with a non-0 osabi or machine
 *		that do not match are quietly ignored.
 *	val - The value for which a string is desired.
 *	flags - CONV_FMT_* values to be passed to conv_invalid_val() if
 *		necessary. The caller is reponsible for having examined
 *		the CONV_FMT_ALT_* part of flags and passing the proper
 *		descriptor array.
 *	vdp - Pointer to NULL terminated array of Val_desc descriptors.
 *	local_sgs_msg - Message string table from module from which
 *		this function is called.
 *
 * exit:
 *	If val is found in the vdp array, and in the osabi version of
 *	this function if the osabi matches, then the string corresponding
 *	val is returned. If a string for val is not found, conv_invalid_val()
 *	is called to format an ASCII representation of it into inv_buf, and
 *	that is returned.
 */
/*ARGSUSED4*/
static const char *
map_vd2str(Conv_inv_buf_t *inv_buf, Conv_elfvalue_t val,
    Conv_fmt_flags_t flags, const Val_desc *vdp, const char *local_sgs_msg)
{
	for (; vdp->v_msg; vdp++) {
		if (val == vdp->v_val)
			return (MSG_ORIG_STRTAB(vdp->v_msg, local_sgs_msg));
	}

	/* If we get here, it's an unknown value */
	return (conv_invalid_val(inv_buf, val, flags));
}

/*ARGSUSED6*/
static const char *
map_vd22str(Conv_inv_buf_t *inv_buf, uchar_t osabi, Half mach,
    Conv_elfvalue_t val, Conv_fmt_flags_t flags, const Val_desc2 *vdp,
    const char *local_sgs_msg)
{
	for (; vdp->v_msg; vdp++) {
		if (CONV_VD2_SKIP(osabi, mach, vdp))
			continue;

		if (val == vdp->v_val)
			return (MSG_ORIG_STRTAB(vdp->v_msg, local_sgs_msg));
	}

	/* If we get here, it's an unknown value */
	return (conv_invalid_val(inv_buf, val, flags));
}

/*
 * Process an array of conv_ds_XXX_t structures and call the appropriate
 * map functions for the format of the strings given.
 */
const char *
_conv_map_ds(uchar_t osabi, Half mach, Conv_elfvalue_t value,
    const conv_ds_t **dsp, Conv_fmt_flags_t fmt_flags, Conv_inv_buf_t *inv_buf,
    const char *local_sgs_msg)
{
	const conv_ds_t *ds;

	for (ds = *dsp; ds != NULL; ds = *(++dsp)) {
		if ((value < ds->ds_baseval) || (value > ds->ds_topval))
			continue;

		switch (ds->ds_type) {
		case CONV_DS_MSGARR:
			return (map_msg2str(inv_buf, value - ds->ds_baseval,
			    fmt_flags, ds->ds_topval - ds->ds_baseval + 1,
			    /*LINTED*/
			    ((conv_ds_msg_t *)ds)->ds_msg,
			    local_sgs_msg));

		case CONV_DS_VD:
			return (map_vd2str(inv_buf, value, fmt_flags,
			    /*LINTED*/
			    ((conv_ds_vd_t *)ds)->ds_vd,
			    local_sgs_msg));

		case CONV_DS_VD2:
			return (map_vd22str(inv_buf, osabi, mach, value,
			    fmt_flags,
			    /*LINTED*/
			    ((conv_ds_vd2_t *)ds)->ds_vd2,
			    local_sgs_msg));
		}
	}

	return (conv_invalid_val(inv_buf, value, fmt_flags));
}

/*
 * Iterate over every message string in a given array of Msg codes,
 * calling a user supplied callback for each one.
 *
 * entry:
 *	basevalue - Value corresponding to the first Msg in the array.
 *	local_sgs_msg - Pointer to the __sgs_msg array for the
 *		libconv module making the call.
 *	num_msg - # of items in array referenced by msg
 *	msg - Array of Msg indexes for the strings to iterate over.
 *		The value corresponding to each element of msg must be:
 *			value[i] = basevalue + i
 *	func, uvalue - User supplied function to be called for each
 *		string in msg. uvalue is an arbitrary user supplied pointer
 *		to be passed to func.
 *	local_sgs_msg - Pointer to the __sgs_msg array for the
 *		libconv module making the call.
 *
 * exit:
 *	The callback function is called for every non-zero item in
 *	msg[]. If any callback returns CONV_ITER_DONE, execution stops
 *	with that item and the function returns immediately. Otherwise,
 *	it continues to the end of the array.
 *
 *	The value from the last callback is returned.
 */
/*ARGSUSED5*/
static conv_iter_ret_t
_conv_iter_msgarr(uint32_t basevalue, const Msg *msg, size_t num_msg,
    conv_iter_cb_t func, void *uvalue, const char *local_sgs_msg)
{
	for (; num_msg-- > 0; basevalue++, msg++) {
		if (*msg != 0)
			if ((* func)(MSG_ORIG_STRTAB(*msg, local_sgs_msg),
			    basevalue, uvalue) == CONV_ITER_DONE)
				return (CONV_ITER_DONE);
	}

	return (CONV_ITER_CONT);
}

/*
 * Iterate over every message string in a given array of Val_desc or
 * Val_desc2 descriptors, calling a user supplied callback for each one.
 *
 * entry:
 *	osabi,mach (_conv_iter_vd2 only) - The osabi/mach for which
 *		strings are desired. Strings with a non-0 osabi or machine
 *		that do not match are quietly ignored.
 *	vdp - Pointer to NULL terminated array of Val_desc descriptors.
 *	func, uvalue - User supplied function to be called for each
 *		string in msg. uvalue is an arbitrary user supplied pointer
 *		to be passed to func.
 *	local_sgs_msg - Pointer to the __sgs_msg array for the
 *		libconv module making the call.
 *
 * exit:
 *	The callback function is called for every descriptor referenced by
 *	vdp. In the case of the OSABI-version of this function, strings from
 *	the wrong osabi are not used. If any callback returns CONV_ITER_DONE,
 *	execution stops with that item and the function returns immediately.
 *	Otherwise, it continues to the end of the array.
 *
 *	The value from the last callback is returned.
 */
/*ARGSUSED3*/
conv_iter_ret_t
_conv_iter_vd(const Val_desc *vdp, conv_iter_cb_t func, void *uvalue,
    const char *local_sgs_msg)
{
	for (; vdp->v_msg; vdp++) {
		if ((* func)(MSG_ORIG_STRTAB(vdp->v_msg, local_sgs_msg),
		    vdp->v_val, uvalue) == CONV_ITER_DONE)
			return (CONV_ITER_DONE);
	}

	return (CONV_ITER_CONT);
}

/*ARGSUSED5*/
conv_iter_ret_t
_conv_iter_vd2(conv_iter_osabi_t osabi, Half mach, const Val_desc2 *vdp,
    conv_iter_cb_t func, void *uvalue, const char *local_sgs_msg)
{
	for (; vdp->v_msg; vdp++) {
		if (CONV_ITER_VD2_SKIP(osabi, mach, vdp))
			continue;

		if ((* func)(MSG_ORIG_STRTAB(vdp->v_msg, local_sgs_msg),
		    vdp->v_val, uvalue) == CONV_ITER_DONE)
			return (CONV_ITER_DONE);
	}

	return (CONV_ITER_CONT);
}

/*
 * Process an array of conv_ds_XXX_t structures and call the appropriate
 * iteration functions for the format of the strings given.
 */
conv_iter_ret_t
_conv_iter_ds(conv_iter_osabi_t osabi, Half mach, const conv_ds_t **dsp,
    conv_iter_cb_t func, void *uvalue, const char *local_sgs_msg)
{
	const conv_ds_t *ds;

	for (ds = *dsp; ds != NULL; ds = *(++dsp)) {
		switch (ds->ds_type) {
		case CONV_DS_MSGARR:
			if (_conv_iter_msgarr(ds->ds_baseval,
			    /*LINTED*/
			    ((conv_ds_msg_t *)ds)->ds_msg,
			    ds->ds_topval - ds->ds_baseval + 1, func, uvalue,
			    local_sgs_msg) == CONV_ITER_DONE)
				return (CONV_ITER_DONE);
			break;

		case CONV_DS_VD:
			/*LINTED*/
			if (_conv_iter_vd(((conv_ds_vd_t *)ds)->ds_vd,
			    func, uvalue, local_sgs_msg) == CONV_ITER_DONE)
				return (CONV_ITER_DONE);
			break;

		case CONV_DS_VD2:
			if (_conv_iter_vd2(osabi, mach,
			    /*LINTED*/
			    ((conv_ds_vd2_t *)ds)->ds_vd2,
			    func, uvalue, local_sgs_msg) == CONV_ITER_DONE)
				return (CONV_ITER_DONE);
			break;
		}
	}

	return (CONV_ITER_CONT);
}

/*
 * Initialize the uvalue block prior to use of an interation function
 * employing conv_iter_strtol().
 *
 * entry:
 *	str - String to be matched to a value
 *	uvalue - Pointer to uninitialized uvalue block
 *
 * exit:
 *	Initializes the uvalue block for use. Returns True (1) if a non-empty
 *	string was supplied, and False (0).
 */
int
conv_iter_strtol_init(const char *str, conv_strtol_uvalue_t *uvalue)
{
	const char	*tail;

	while (conv_strproc_isspace(*str))
		str++;
	uvalue->csl_str = str;
	uvalue->csl_found = 0;

	tail = str + strlen(str);
	while ((tail > str) && conv_strproc_isspace(*(tail - 1)))
		tail--;
	uvalue->csl_strlen = tail - str;

	return (uvalue->csl_strlen > 0);
}

/*
 * conv_iter_strtol() is used with iteration functions to map a string
 * to the value of its corresponding ELF constant.
 *
 * entry:
 *	str - String supplied by this iteration
 *	value - Value of ELF constant corresponding to str
 *	uvalue - Pointer to conv_strtol_uvalue_t block previously
 *		initialized by a call to conv_iter_strtol_init().
 */
conv_iter_ret_t
conv_iter_strtol(const char *str, uint32_t value, void *uvalue)
{
	conv_strtol_uvalue_t *state = (conv_strtol_uvalue_t *)uvalue;

	if ((strlen(str) == state->csl_strlen) &&
	    (strncasecmp(str, state->csl_str, state->csl_strlen) == 0)) {
		state->csl_found = 1;
		state->csl_value = value;
		return (CONV_ITER_DONE);	/* Found it. Stop now. */
	}

	return (CONV_ITER_CONT);		/* Keep looking */
}
