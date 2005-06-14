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
 * Copyright (c) 1996, by Sun Microsystem, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_DADA_DADA_RESOURCE_H
#define	_SYS_DADA_DADA_RESOURCE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dada/dada_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DCD Resource Function Declarations
 */

/*
 * Defines for stating preferences in resource allocation
 */

#define	NULL_FUNC	((int (*)())0)
#define	SLEEP_FUNC	((int (*)())1)

#ifdef _KERNEL
/*
 * defines for the flags to scsi_init_pkt()
 */
#define	PKT_CONSISTENT		0x0001	/* This is an 'iopb' packet */
#define	PKT_DMA_PARTIAL		0x040000 /* Partial xfer Ok */


/*
 * Old PKT_CONSITENT value for binary compatibility with x86 2.1
 */
#define	PKT_CONSISTENT_OLD		0x001000

/*
 * Kernel function declarations
 */

#ifdef	__STDC__
extern struct buf *dcd_alloc_consistent_buf(struct dcd_address *,
	struct buf *, size_t, uint_t, int (*)(caddr_t), caddr_t);

extern struct dcd_pkt *dcd_init_pkt(struct dcd_address *,
	struct dcd_pkt *, struct buf *, int, int, int, int,
	int (*)(caddr_t), caddr_t);

extern void dcd_destroy_pkt(struct dcd_pkt *);

extern void dcd_free_consistent_buf(struct buf *);

extern struct dcd_pkt *dcd_resalloc(struct dcd_address *, int,
	int, ataopaque_t, int (*)());

extern struct dcd_pkt *dcd_pktalloc(struct dcd_address *, int, int,
	int (*)());

extern void dcd_dmafree(struct dcd_pkt *);

extern void dcd_sync_pkt(struct dcd_pkt *);
extern void dcd_resfree(struct dcd_pkt *);

#else	/* __STDC__ */
extern struct dcd_pkt *dcd_init_pkt();
extern void dcd_destroy_pkt();
extern struct buf *dcd_alloc_consistent_buf();
extern void	dcd_free_consistent_buf();
extern struct dcd_pkt *dcd_resalloc();
extern struct dcd_pkt *dcd_pktalloc();
extren struct dcd_pkt dcd_dmaget();
extern void  	dcd_resfree();
extern void	dcd_dmafree();
extern void	dcd_sync_pkt();
#endif	/* __STDC__ */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DADA_DADA_RESOURCE_H */
