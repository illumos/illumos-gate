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

#include <errno.h>

#include "fru_tag.h"

char *
get_tagtype_str(fru_tagtype_t e)
{
	switch (e) {
		case FRU_A:
			return ("A");
		case FRU_B:
			return ("B");
		case FRU_C:
			return ("C");
		case FRU_D:
			return ("D");
		case FRU_E:
			return ("E");
		case FRU_F:
			return ("F");
		case FRU_G:
			return ("G");
		case FRU_X:
			return ("X");
	}
	return ("?");
}

size_t
get_tag_size(fru_tagtype_t tag)
{
	switch (tag) {
		case FRU_A:
			return (1);
		case FRU_B:
		case FRU_C:
			return (2);
		case FRU_D:
		case FRU_E:
			return (3);
		case FRU_F:
			return (4);
		case FRU_G:
			return (6);
	}
	errno = EINVAL;
	return (-1);
}

int
mk_tag(fru_tagtype_t type, uint32_t dense, size_t pl_len, fru_tag_t *tag)
{
	static fru_tag_t max = { 0xFFFFFFFFFFFFFFFFULL };
	/* make sure the tag is clear. */
	tag->raw_data = 0;

	/* then fill it in with data. */
	switch (type) {
		case FRU_A:
			if ((dense > max.a.dense) || (pl_len > max.a.pl_len)) {
				errno = EINVAL;
				return (-1);
			}
			tag->a.type = FRU_A_ID;
			tag->a.dense = dense;
			tag->a.pl_len = pl_len;
			break;
		case FRU_B:
			if ((dense > max.b.dense) || (pl_len > max.b.pl_len)) {
				errno = EINVAL;
				return (-1);
			}
			tag->b.type = FRU_B_ID;
			tag->b.dense = dense;
			tag->b.pl_len = pl_len;
			break;
		case FRU_C:
			if ((dense > max.c.dense) || (pl_len > max.c.pl_len)) {
				errno = EINVAL;
				return (-1);
			}
			tag->c.type = FRU_C_ID;
			tag->c.dense = dense;
			tag->c.pl_len = pl_len;
			break;
		case FRU_D:
			if ((dense > max.d.dense) || (pl_len > max.d.pl_len)) {
				errno = EINVAL;
				return (-1);
			}
			tag->d.type = FRU_D_ID;
			tag->d.dense = dense;
			tag->d.pl_len = pl_len;
			break;
		case FRU_E:
			if ((dense > max.e.dense) || (pl_len > max.e.pl_len)) {
				errno = EINVAL;
				return (-1);
			}
			tag->e.type = FRU_E_ID;
			tag->e.dense = dense;
			tag->e.pl_len = pl_len;
			break;
		case FRU_F:
			if ((dense > max.f.dense) || (pl_len > max.f.pl_len)) {
				errno = EINVAL;
				return (-1);
			}
			tag->f.type = FRU_F_ID;
			tag->f.dense = dense;
			tag->f.pl_len = pl_len;
			break;
		case FRU_G:
			if ((dense > max.g.dense) || (pl_len > max.g.pl_len)) {
				errno = EINVAL;
				return (-1);
			}
			tag->g.type = FRU_G_ID;
			tag->g.dense = dense;
			tag->g.pl_len = pl_len;
			break;
		default:
			errno = EINVAL;
			return (-1);
	}

	return (get_tag_size(type));
}

#if defined(_LITTLE_ENDIAN)
fru_tagtype_t
get_tag_type(fru_tag_t *tag)
{
	uint64_t tmp64;
	uint32_t tmp32;
	fru_tag_t tmp;

	if (tag->a.type == FRU_A_ID)
		return (FRU_A);

	tmp.raw_data = (tag->byte[0] << 8) | tag->byte[1];
	if (tmp.b.type == FRU_B_ID)
		return (FRU_B);
	if (tmp.c.type == FRU_C_ID)
		return (FRU_C);

	tmp32 = (tag->byte[0] << 16) | (tag->byte[1] << 8) | tag->byte[2];
	tmp.raw_data = tmp32;
	if (tmp.d.type == FRU_D_ID)
		return (FRU_D);
	if (tmp.e.type == FRU_E_ID)
		return (FRU_E);

	tmp32 = (tag->byte[0] << 24) | (tag->byte[1] << 16) |
	    (tag->byte[2] << 8) | tag->byte[3];
	tmp.raw_data = tmp32;
	if (tmp.f.type == FRU_F_ID)
		return (FRU_F);

	tmp64 = ((uint64_t)tag->byte[0] << 40) |
	    ((uint64_t)tag->byte[1] << 32) |
	    ((uint64_t)tag->byte[2] << 24) |
	    ((uint64_t)tag->byte[3] << 16) |
	    ((uint64_t)tag->byte[4] << 8) |
	    (uint64_t)tag->byte[5];
	tmp.raw_data = tmp64;
	if (tmp.g.type == FRU_G_ID)
		return (FRU_G);

	errno = EINVAL;
	return (-1);
}
#else
fru_tagtype_t
get_tag_type(fru_tag_t *tag)
{
	if (tag->a.type == FRU_A_ID)
		return (FRU_A);
	else if (tag->b.type  == FRU_B_ID)
		return (FRU_B);
	else if (tag->c.type == FRU_C_ID)
		return (FRU_C);
	else if (tag->d.type == FRU_D_ID)
		return (FRU_D);
	else if (tag->e.type == FRU_E_ID)
		return (FRU_E);
	else if (tag->f.type == FRU_F_ID)
		return (FRU_F);
	else if (tag->g.type == FRU_G_ID)
		return (FRU_G);

	errno = EINVAL;
	return (-1);
}
#endif  /* _LITTLE_ENDIAN */

#if defined(_LITTLE_ENDIAN)
uint32_t
get_tag_dense(fru_tag_t *tag)
{
	uint64_t tmp64;
	uint32_t tmp32;
	fru_tag_t tmp;

	tmp = *tag;
	switch (get_tag_type(tag)) {
		case FRU_A:
			return (tag->a.dense);
		case FRU_B:
			tmp.raw_data = (tag->byte[0] << 8) | tag->byte[1];
			return (tmp.b.dense);
		case FRU_C:
			tmp.raw_data = (tag->byte[0] << 8) | tag->byte[1];
			return (tmp.c.dense);
		case FRU_D:
			tmp32 = (tag->byte[0] << 16) | (tag->byte[1] << 8) |
			    tag->byte[2];
			tmp.raw_data = tmp32;
			return (tmp.d.dense);
		case FRU_E:
			tmp32 = (tag->byte[0] << 16) | (tag->byte[1] << 8) |
			    tag->byte[2];
			tmp.raw_data = tmp32;
			return (tmp.e.dense);
		case FRU_F:
			tmp32 = (tag->byte[0] << 24) | (tag->byte[1] << 16) |
			    (tag->byte[2] << 8) | tag->byte[3];
			tmp.raw_data = tmp32;
			return (tmp.f.dense);
		case FRU_G:
			tmp64 = ((uint64_t)tag->byte[0] << 40) |
			    ((uint64_t)tag->byte[1] << 32) |
			    ((uint64_t)tag->byte[2] << 24) |
			    ((uint64_t)tag->byte[3] << 16) |
			    ((uint64_t)tag->byte[4] << 8) |
			    (uint64_t)tag->byte[5];
			tmp.raw_data = tmp64;
			return (tmp.g.dense);
		default:
			errno = EINVAL;
			return ((uint32_t)-1);
	}
}
#else
uint32_t
get_tag_dense(fru_tag_t *tag)
{
	switch (get_tag_type(tag)) {
		case FRU_A:
			return (tag->a.dense);
		case FRU_B:
			return (tag->b.dense);
		case FRU_C:
			return (tag->c.dense);
		case FRU_D:
			return (tag->d.dense);
		case FRU_E:
			return (tag->e.dense);
		case FRU_F:
			return (tag->f.dense);
		case FRU_G:
			return (tag->g.dense);
		default:
			errno = EINVAL;
			return ((uint32_t)-1);
	}
}
#endif  /* _LITTLE_ENDIAN */

#if defined(_LITTLE_ENDIAN)
size_t
get_payload_length(fru_tag_t *tag)
{
	uint64_t tmp64;
	uint32_t tmp32;
	fru_tag_t tmp;

	tmp = *tag;
	switch (get_tag_type(tag)) {
		case FRU_A:
			return (tag->a.pl_len);
		case FRU_B:
			tmp.raw_data = (tag->byte[0] << 8) | tag->byte[1];
			return (tmp.b.pl_len);
		case FRU_C:
			tmp.raw_data = (tag->byte[0] << 8) | tag->byte[1];
			return (tmp.c.pl_len);
		case FRU_D:
			tmp32 = (tag->byte[0] << 16) | (tag->byte[1] << 8) |
			    tag->byte[2];
			tmp.raw_data = tmp32;
			return (tmp.d.pl_len);
		case FRU_E:
			tmp32 = (tag->byte[0] << 16) | (tag->byte[1] << 8) |
			    tag->byte[2];
			tmp.raw_data = tmp32;
			return (tmp.e.pl_len);
		case FRU_F:
			tmp32 = (tag->byte[0] << 24) | (tag->byte[1] << 16) |
			    (tag->byte[2] << 8) | tag->byte[3];
			tmp.raw_data = tmp32;
			return (tmp.f.pl_len);
		case FRU_G:
			tmp64 = ((uint64_t)tag->byte[0] << 40) |
			    ((uint64_t)tag->byte[1] << 32) |
			    ((uint64_t)tag->byte[2] << 24) |
			    ((uint64_t)tag->byte[3] << 16) |
			    ((uint64_t)tag->byte[4] << 8) |
			    (uint64_t)tag->byte[5];
			tmp.raw_data = tmp64;
			return (tmp.g.pl_len);
		default:
			errno = EINVAL;
			return ((uint32_t)-1);
	}
}
#else
size_t
get_payload_length(fru_tag_t *tag)
{
	switch (get_tag_type(tag)) {
		case FRU_A:
			return (tag->a.pl_len);
		case FRU_B:
			return (tag->b.pl_len);
		case FRU_C:
			return (tag->c.pl_len);
		case FRU_D:
			return (tag->d.pl_len);
		case FRU_E:
			return (tag->e.pl_len);
		case FRU_F:
			return (tag->f.pl_len);
		case FRU_G:
			return (tag->g.pl_len);
		default:
			errno = EINVAL;
			return ((uint32_t)-1);
	}
}
#endif  /* _LITTLE_ENDIAN */

int
tags_equal(fru_tag_t t1, fru_tag_t t2)
{
	return ((get_tag_type(&t1) == get_tag_type(&t2)) &&
	    (get_tag_dense(&t1) == get_tag_dense(&t2)) &&
	    (get_payload_length(&t1) == get_payload_length(&t2)));
}
