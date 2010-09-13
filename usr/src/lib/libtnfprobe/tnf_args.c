/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	  Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include "tnf_trace.h"
#include "tnf_types.h"
#include "tnf_args.h"
#include <string.h>
#include <assert.h>

/*
 * tnf_probe_get_num_args: returns the number of arguments at probe site
 * probe_p.  This includes the first 2 args (tag and time delta) in the return
 * value.
 */
int
tnf_probe_get_num_args(tnf_probe_control_t *probe_p)
{
	int count = 0;
	tnf_tag_data_t ***tag_p;

	tag_p = probe_p->slot_types;
	while (*tag_p) {
		count++;
		tag_p++;
	}
	return (count);
}

/*
 * tnf_probe_get_arg_indexed: returns a pointer into the buffer where
 * argument i is stored.  Returns NULL on error.  Argument numbering is
 * zero based i.e. to get the 3rd argument, the input value should be 2.
 */

/* ALIGN_ROUNDUP: y has to be one less than a power of 2 eg. 3, 7, 15, etc. */
#define	ALIGN_ROUNDUP(x, y) (((x) + (y)) & ~(y))

void *
tnf_probe_get_arg_indexed(tnf_probe_control_t *probe_p, int index, void *buffer)
{
	int count = 0;
	size_t align;
	size_t elem_size = 0;
	tnf_tag_data_t ***tag_ppp;
	tnf_tag_data_t   *tag_p;
	unsigned long offset = 0;

	tag_ppp = probe_p->slot_types;
	if (!tag_ppp)
		return (NULL);

	while (count <= index) {
		/* error checking. REMIND: Do we need it ? */
		if (!(*tag_ppp))
			return (NULL);
		tag_p = **tag_ppp;
		if (!tag_p)
			return (NULL);

		offset = offset + elem_size;
		align = tag_p->tag_align - 1;
		assert(align != 0);
		offset = ALIGN_ROUNDUP(offset, align);
		/* get size of current element */
		elem_size = tag_p->tag_ref_size;
		tag_ppp++;
		count++;
	}

	return ((void *)((char *)buffer + offset));
}

/*
 * tnf_probe_get_type_indexed: returns the type of the ith argument.
 * returns TNF_UNKNOWN on error.  Argument numbering is zero based
 * i.e. to get the 3rd argument, the input value should be 2.
 */

tnf_arg_kind_t
tnf_probe_get_type_indexed(tnf_probe_control_t *probe_p, int index)
{
	tnf_tag_data_t ***tag_ppp;
	tnf_tag_data_t   *tag_p;

	tag_ppp = probe_p->slot_types + index;
	if (!tag_ppp)
		return (TNF_UNKNOWN);
	if (!(*tag_ppp))
		return (TNF_UNKNOWN);
	tag_p = **tag_ppp;
	if (!tag_p)
		return (TNF_UNKNOWN);
	return (tag_p->tag_kind);
}


/*
 * tnf_probe_get_value: returns the start of the value string that is
 * associated with the input attribute.  The number of characters in the
 * value is also returned as the final argument.  The size return value
 * indicates the length of the string that is valid.  Returns NULL on no
 * match or error.
 */

const char *
tnf_probe_get_value(tnf_probe_control_t *probe_p, char *attribute,
ulong_t *size)
{

	const char 	*attr_start, *attr_end, *str_end;
	const char	*val_start;
	int 		separator;
	uint_t		attr_len;
	size_t		input_len;

	input_len = strlen(attribute);
	attr_start = probe_p->attrs;
	assert(attr_start);
	str_end = attr_start + strlen(attr_start);
	separator = ATTR_SEPARATOR;
	while (attr_start < str_end) {
		attr_end = strchr(attr_start, separator);
		if (!attr_end) {
			/* last attribute */
			attr_end = str_end;
		}
		/* LINTED - result <= string length */
		attr_len = attr_end - attr_start;

		/* skip over leading white space */
		while (*attr_start && ((*attr_start == ' ') ||
						(*attr_start == '\t'))) {
			attr_start++;
		}
		/* search for match on attribute */
		if (strncmp(attr_start, attribute, input_len) == 0) {
			/* make sure next char is a space or semicolon */
			val_start = attr_start + input_len;
			if (*val_start == ATTR_SEPARATOR) {
				*size = 0;
				return (val_start);
			} else if (*val_start == VAL_SEPARATOR) {
				/* +1 for val separator */
				*size = attr_len - (input_len + 1);
				return (val_start + 1);
			}
			/* a false match - just continue */
		}
		/* skip to next attribute */
		attr_start = attr_end + 1;
	}

	/* no match */
	return (NULL);
}

/* used by in-process argument reader */
char *
tnf_probe_get_chars(void *slot)
{
	tnf_reference_t	ref;
	char		*str_p;

	ref = *((tnf_reference_t *)slot);
	assert(TNF_REF32_IS_FWD(ref));
	str_p = (char *)slot + TNF_REF32_VALUE(ref);
	str_p += ARRAY_HDR_SIZE;
	return (str_p);
}
