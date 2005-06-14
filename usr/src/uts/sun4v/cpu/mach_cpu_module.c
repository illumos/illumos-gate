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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpu_module.h>
#include <vm/page.h>
#include <vm/seg_map.h>

void
cpu_fiximp(struct cpu_node *cpunode)
{}

void
cpu_flush_ecache(void)
{}

/*ARGSUSED*/
void
cpu_faulted_enter(struct cpu *cp)
{}

/*ARGSUSED*/
void
cpu_faulted_exit(struct cpu *cp)
{}

/*
 * Ecache scrub operations
 */
void
cpu_init_cache_scrub(void)
{}

/* ARGSUSED */
void
prefetch_page_w(void *pp)
{
#define	ECACHE_SUBBLOCKS_PER_PAGE	2
#define	ECACHE_SUBBLOCK_SIZE_BYTES	64
#define	ECACHE_PAGE_BYTE_MAX	\
	(ECACHE_SUBBLOCKS_PER_PAGE*ECACHE_SUBBLOCK_SIZE_BYTES+1)

	/*
	 * The following line is intended to cause an error
	 * whenever the sun4u page_t grows beyond 128
	 * bytes.
	 *
	 * If you get an error here, you'll need to change
	 * the 'prefetch_page_w' assembly language code
	 * (see also prefetch_page_w prologue comment)
	 */
	/*LINTED*/
	volatile int garbage[ECACHE_PAGE_BYTE_MAX - sizeof (page_t)];
}

/* ARGSUSED */
void
prefetch_page_r(void *pp)
{
#define	ECACHE_SUBBLOCKS_PER_PAGE	2
#define	ECACHE_SUBBLOCK_SIZE_BYTES	64
#define	ECACHE_PAGE_BYTE_MAX	\
	(ECACHE_SUBBLOCKS_PER_PAGE*ECACHE_SUBBLOCK_SIZE_BYTES+1)

	/*
	 * The following line is intended to cause an error
	 * whenever the sun4u page_t grows beyond 128
	 * bytes.
	 *
	 * If you get an error here, you'll need to change
	 * the 'prefetch_page_r' assembly language code
	 * (see also prefetch_page_w prologue comment)
	 */
	/*LINTED*/
	volatile int garbage[ECACHE_PAGE_BYTE_MAX - sizeof (page_t)];
}


#ifdef	SEGKPM_SUPPORT
#define	SMAP_SIZE	80
#else
#define	SMAP_SIZE	56
#endif

/* ARGSUSED */
void
prefetch_smap_w(void *smp)
{

	/*
	 * The following lines are intended to cause an error
	 * whenever the smap object size changes from the current
	 * size of 48 bytes.  If you get an error here, you'll
	 * need to update the code in the 'prefetch_smap_w' assembly
	 * language code.
	 */
	/*LINTED*/
	volatile int smap_size_changed [SMAP_SIZE - sizeof (struct smap) + 1];
	volatile int smap_size_changed2 [sizeof (struct smap) - SMAP_SIZE + 1];
}

void
kdi_flush_caches(void)
{}

/*ARGSUSED*/
int
kzero(void *addr, size_t count)
{ return (0); }

/*ARGSUSED*/
void
uzero(void *addr, size_t count)
{}

/*ARGSUSED*/
void
bzero(void *addr, size_t count)
{}

/*ARGSUSED*/
void
cpu_inv_tsb(caddr_t tsb_base, uint_t tsb_bytes)
{}
