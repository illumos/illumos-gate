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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include "libtnf.h"

/*
 *
 */

static struct ntop {
	char		*name;
	tag_props_t	prop;
} ntop[] = {
{ TNF_N_INLINE,		TAG_PROP_INLINE },
{ TNF_N_TAGGED,		TAG_PROP_TAGGED },
{ TNF_N_SCALAR,		TAG_PROP_SCALAR },
{ TNF_N_DERIVED,	TAG_PROP_DERIVED },
{ TNF_N_ARRAY,		TAG_PROP_ARRAY },
{ TNF_N_STRING,		TAG_PROP_STRING },
{ TNF_N_STRUCT,		TAG_PROP_STRUCT },
{ TNF_N_TYPE,		TAG_PROP_TYPE },
{ NULL,			0}
};

static struct ntok {
	char		*name;
	tnf_kind_t	kind;
} scalar_ntok[] = {
{ TNF_N_CHAR, 		TNF_K_CHAR },
{ TNF_N_INT8,		TNF_K_INT8 },
{ TNF_N_INT16,		TNF_K_INT16 },
{ TNF_N_INT32,		TNF_K_INT32 },
{ TNF_N_UINT8,		TNF_K_UINT8 },
{ TNF_N_UINT16,		TNF_K_UINT16 },
{ TNF_N_UINT32,		TNF_K_UINT32 },
{ TNF_N_INT64,		TNF_K_INT64 },
{ TNF_N_UINT64,		TNF_K_UINT64 },
{ TNF_N_FLOAT32,	TNF_K_FLOAT32 },
{ TNF_N_FLOAT64,	TNF_K_FLOAT64 },
{ NULL,			0 }
};

/*
 * Compute tag props
 */

tag_props_t
_tnf_get_props(TNF *tnf, tnf_ref32_t *tag)
{
	tag_props_t	props;
	struct ntop  	*p;

	props = 0;

	p = ntop;
	/* No need to get base tag for inherited properties */
	while (p->name) {
		if (HAS_PROPERTY(tnf, tag, p->name))
			props |= p->prop;
		p++;
	}

	return (props);
}

/*
 * Data kind depends on implementation properties of base tag
 */

tnf_kind_t
_tnf_get_kind(TNF *tnf, tnf_ref32_t *tag)
{
	tnf_ref32_t	*base_tag;
	char		*base_name;

	base_tag 	= _tnf_get_base_tag(tnf, tag);
	base_name 	= _tnf_get_name(tnf, base_tag);

	if (HAS_PROPERTY(tnf, base_tag, TNF_N_SCALAR)) {
		struct ntok 	*p;

		p = scalar_ntok;
		while (p->name) {
			if (strcmp(p->name, base_name) == 0)
				return (p->kind);
			p++;
		}
		return (TNF_K_SCALAR);

	} else if (HAS_PROPERTY(tnf, base_tag, TNF_N_ARRAY)) {
		if (strcmp(base_name, TNF_N_STRING) == 0)
			return (TNF_K_STRING);
		else
			return (TNF_K_ARRAY);

	} else if (HAS_PROPERTY(tnf, base_tag, TNF_N_TYPE)) {
		return (TNF_K_TYPE);

	} else if (HAS_PROPERTY(tnf, base_tag, TNF_N_STRUCT)) {
		return (TNF_K_STRUCT);

	} else {		/* abstract */
		return (TNF_K_UNKNOWN);
	}
}
