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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _XHAT_SFMMU_H
#define	_XHAT_SFMMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"



#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <vm/hat_sfmmu.h>
#include <vm/page.h>
#include <vm/xhat.h>

struct xhat;
struct xhat_hme_blk;


/*
 * Pads to align xhat_hme_blk's xhat_hme_blk_misc
 * and with xblk_hme with corresponding fields in
 * those of hme_blk.
 */
#define	XHAT_PADHI	(offsetof(struct hme_blk, hblk_misc) - \
			    sizeof (struct xhat *))

#define	XHAT_PADLO	(offsetof(struct hme_blk, hblk_hme[0]) - \
				(offsetof(struct hme_blk, hblk_misc) + \
					sizeof (struct hme_blk_misc)))

/*
 * This (or, rather, xblk_hme[] member of the structure) is
 * what gets put on page's p_mappings list.
 */
struct xhat_hme_blk {
	struct xhat		*xhat_hme_blk_hat;
	char			xblk_pad1[XHAT_PADHI];
	struct hme_blk_misc	xhat_hme_blk_misc;
	char			xblk_pad2[XHAT_PADLO];
	struct sf_hment		xblk_hme[1];
};

/*
 * Convert pointers between xhat_hme_blk and provider's
 * block (these two blocks are always allocated adjacent to
 * each other).
 */
#define	XBLK2PROVBLK(xblk)	((void *)(((struct xhat_hme_blk *)(xblk)) + 1))
#define	PROVBLK2XBLK(pblk)	(((struct xhat_hme_blk *)(pblk)) - 1)



void	xhat_xblkcache_reclaim(void *);



#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _XHAT_SFMMU_H */
