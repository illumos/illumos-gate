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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DVMA_H
#define	_SYS_DVMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DVMAO_REV	1

struct dvma_ops  {
#ifdef __STDC__
	int dvmaops_rev;		/* rev of this structure */
	void (*dvma_kaddr_load)(ddi_dma_handle_t h, caddr_t a,
			    uint_t len, uint_t index, ddi_dma_cookie_t *cp);
	void (*dvma_unload)(ddi_dma_handle_t h, uint_t objindex,
			    uint_t view);
	void (*dvma_sync)(ddi_dma_handle_t h, uint_t objindex,
			    uint_t view);
#else /* __STDC__ */
	int dvmaops_rev;
	void (*dvma_kaddr_load)();
	void (*dvma_unload)();
	void (*dvma_sync)();
#endif /* __STDC__ */
};

struct	fast_dvma	{
	caddr_t softsp;
	uint_t *pagecnt;
	unsigned long long  *phys_sync_flag;
	int *sync_flag;
	struct dvma_ops *ops;
	caddr_t *kvbase;
	void **cbcookie;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DVMA_H */
