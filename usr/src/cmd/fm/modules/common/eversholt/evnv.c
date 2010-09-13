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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * evnv.c -- eversholt specific nvpair manipulation functions
 *
 * this module provides the simulated fault management exercise.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <libnvpair.h>
#include "evnv.h"
#include "out.h"

#define	min(a, b)	(((a) <= (b)) ? (a) : (b))

extern nv_alloc_t Eft_nv_hdl;

static void
outindent(int depth)
{
	while (depth-- > 0)
		out(O_ALTFP|O_VERB3|O_NONL, "   ");
}

/*
 * evnv_cmpnvl -- compare two asrus in their nvlist form
 */
int
evnv_cmpnvl(nvlist_t *nvl1, nvlist_t *nvl2, int depth)
{
	/*
	 * an assumption here is that each list was constructed in the
	 * same order, which is a safe assumption since we built the
	 * list of ourself (well, libtopo did at any rate)
	 */
	data_type_t t1, t2;
	nvlist_t **la1 = NULL;
	nvlist_t **la2 = NULL;
	nvlist_t *l1 = NULL;
	nvlist_t *l2 = NULL;
	nvpair_t *p1 = NULL;
	nvpair_t *p2 = NULL;
	uint64_t lv1, lv2;
	uint_t m, na1, na2;
	char *s1, *s2;
	int ret, i;

	for (;;) {
		p1 = nvlist_next_nvpair(nvl1, p1);
		p2 = nvlist_next_nvpair(nvl2, p2);
		if (p1 == NULL && p2 == NULL) {
			outindent(depth);
			out(O_ALTFP|O_VERB3, "equal nvls\n");
			return (0);
		}
		if (p1 == NULL)
			return (-1);
		if (p2 == NULL)
			return (1);
		s1 = nvpair_name(p1);
		s2 = nvpair_name(p2);
		outindent(depth);
		out(O_ALTFP|O_VERB3, "cmpnvl: pair %s vs %s", s1, s2);
		if ((ret = strcmp(s1, s2)) != 0)
			return (ret);
		t1 = nvpair_type(p1);
		t2 = nvpair_type(p2);
		if (t1 != t2)
			return (t1 - t2);
		/*
		 * We don't compare all possible types, just the
		 * ones we know are likely to actually be present
		 * in nvlists we've generated.
		 */
		switch (t1) {
		case DATA_TYPE_NVLIST:
			(void) nvpair_value_nvlist(p1, &l1);
			(void) nvpair_value_nvlist(p2, &l2);
			if ((ret = evnv_cmpnvl(l1, l2, depth + 1)) != 0)
				return (ret);
			break;
		case DATA_TYPE_NVLIST_ARRAY:
			(void) nvpair_value_nvlist_array(p1, &la1, &na1);
			(void) nvpair_value_nvlist_array(p2, &la2, &na2);
			m = min(na1, na2);
			for (i = 0; i < m; i++) {
				if ((ret =
				    evnv_cmpnvl(*la1, *la2, depth + 1)) != 0)
					return (ret);
				la1++;
				la2++;
			}
			if (na1 < na2)
				return (-1);
			else if (na2 < na1)
				return (1);
			break;
		case DATA_TYPE_STRING:
			(void) nvpair_value_string(p1, &s1);
			(void) nvpair_value_string(p2, &s2);
			if ((ret = strcmp(s1, s2)) != 0) {
				outindent(depth);
				if (ret < 0)
					out(O_ALTFP|O_VERB3,
					    "cmpnvl: %s < %s", s1, s2);
				else
					out(O_ALTFP|O_VERB3,
					    "cmpnvl: %s > %s", s1, s2);
				return (ret);
			}
			break;
		case DATA_TYPE_UINT64:
			lv1 = lv2 = 0;
			(void) nvpair_value_uint64(p1, &lv1);
			(void) nvpair_value_uint64(p2, &lv2);
			outindent(depth);
			out(O_ALTFP|O_VERB3, "cmpnvl: %llu vs %llu", lv1, lv2);
			if (lv1 > lv2)
				return (1);
			else if (lv2 > lv1)
				return (-1);
			break;
		case DATA_TYPE_INT64:
			lv1 = lv2 = 0;
			(void) nvpair_value_int64(p1, (int64_t *)&lv1);
			(void) nvpair_value_int64(p2, (int64_t *)&lv2);
			outindent(depth);
			out(O_ALTFP|O_VERB3, "cmpnvl: %lld vs %lld", lv1, lv2);
			if (lv1 > lv2)
				return (1);
			else if (lv2 > lv1)
				return (-1);
			break;
		case DATA_TYPE_UINT32:
			lv1 = lv2 = 0;
			(void) nvpair_value_uint32(p1, (uint32_t *)&lv1);
			(void) nvpair_value_uint32(p2, (uint32_t *)&lv2);
			outindent(depth);
			out(O_ALTFP|O_VERB3, "cmpnvl: %u vs %u",
			    *(uint32_t *)&lv1, *(uint32_t *)&lv2);
			if (lv1 > lv2)
				return (1);
			else if (lv2 > lv1)
				return (-1);
			break;
		case DATA_TYPE_INT32:
			lv1 = lv2 = 0;
			(void) nvpair_value_int32(p1, (int32_t *)&lv1);
			(void) nvpair_value_int32(p2, (int32_t *)&lv2);
			outindent(depth);
			out(O_ALTFP|O_VERB3, "cmpnvl: %d vs %d",
			    *(int32_t *)&lv1, *(int32_t *)&lv2);
			if (lv1 > lv2)
				return (1);
			else if (lv2 > lv1)
				return (-1);
			break;
		case DATA_TYPE_UINT16:
			lv1 = lv2 = 0;
			(void) nvpair_value_uint16(p1, (uint16_t *)&lv1);
			(void) nvpair_value_uint16(p2, (uint16_t *)&lv2);
			outindent(depth);
			out(O_ALTFP|O_VERB3, "cmpnvl: %u vs %u",
			    *(uint16_t *)&lv1, *(uint16_t *)&lv2);
			if (lv1 > lv2)
				return (1);
			else if (lv2 > lv1)
				return (-1);
			break;
		case DATA_TYPE_INT16:
			lv1 = lv2 = 0;
			(void) nvpair_value_int16(p1, (int16_t *)&lv1);
			(void) nvpair_value_int16(p2, (int16_t *)&lv2);
			outindent(depth);
			out(O_ALTFP|O_VERB3, "cmpnvl: %d vs %d",
			    *(int16_t *)&lv1, *(int16_t *)&lv2);
			if (lv1 > lv2)
				return (1);
			else if (lv2 > lv1)
				return (-1);
			break;
		case DATA_TYPE_UINT8:
			lv1 = lv2 = 0;
			(void) nvpair_value_uint8(p1, (uint8_t *)&lv1);
			(void) nvpair_value_uint8(p2, (uint8_t *)&lv2);
			outindent(depth);
			out(O_ALTFP|O_VERB3, "cmpnvl: %u vs %u",
			    *(uint8_t *)&lv1, *(uint8_t *)&lv2);
			if (lv1 > lv2)
				return (1);
			else if (lv2 > lv1)
				return (-1);
			break;
		case DATA_TYPE_INT8:
			lv1 = lv2 = 0;
			(void) nvpair_value_int8(p1, (int8_t *)&lv1);
			(void) nvpair_value_int8(p2, (int8_t *)&lv2);
			outindent(depth);
			out(O_ALTFP|O_VERB3, "cmpnvl: %d vs %d",
			    *(int8_t *)&lv1, *(int8_t *)&lv2);
			if (lv1 > lv2)
				return (1);
			else if (lv2 > lv1)
				return (-1);
			break;
		}
	}
}

/*
 * evnv_dupnvl -- duplicate a payload nvlist, keeping only the interesting stuff
 */
nvlist_t *
evnv_dupnvl(nvlist_t *nvp)
{
	nvlist_t *retval = NULL;
	int nvret;

	if (nvp == NULL)
		return (NULL);

	if ((nvret = nvlist_xdup(nvp, &retval, &Eft_nv_hdl)) != 0)
		out(O_DIE, "dupnvl: dup failed: %d", nvret);

	return (retval);
}
