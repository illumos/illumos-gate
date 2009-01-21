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
#ifndef	_INLINE_H
#define	_INLINE_H

#include	<sys/types.h>
#include	<sys/mman.h>

inline static mmapobj_result_t *
find_segment(caddr_t roffset, Rt_map *lmp)
{
	mmapobj_result_t	*mpp = MMAPS(lmp);
	uint_t			mnum = MMAPCNT(lmp);

	/*
	 * Scan segments backwards.  The heaviest use of this function stems
	 * from relocation processing.  And typically, relocations are against
	 * the data segment.  By scanning segments in reverse order, the data
	 * segment is processed first.
	 */
	for (mpp += (mnum - 1); mnum; mnum--, mpp--) {
		if ((roffset >= (mpp->mr_addr + mpp->mr_offset)) &&
		    (roffset < (mpp->mr_addr + mpp->mr_msize)))
			return (mpp);
	}
	return (NULL);
}

#endif	/* _INLINE_H */
