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

#ifndef	_SYS_SCSI_SCSI_RESOURCE_H
#define	_SYS_SCSI_SCSI_RESOURCE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/scsi/scsi_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCSI Resource Function Declarations
 */

/*
 * Defines for stating preferences in resource allocation
 */

#define	NULL_FUNC	((int (*)())0)
#define	SLEEP_FUNC	((int (*)())1)

#ifdef	_KERNEL
/*
 * Defines for the flags to scsi_init_pkt()
 */
#define	PKT_CONSISTENT	0x0001		/* this is an 'iopb' packet */
#define	PKT_DMA_PARTIAL	0x040000	/* partial xfer ok */

/*
 * Old PKT_CONSISTENT value for binary compatibility with x86 2.1
 */
#define	PKT_CONSISTENT_OLD	0x001000

/*
 * Kernel function declarations
 */
struct buf	*scsi_alloc_consistent_buf(struct scsi_address *,
		    struct buf *, size_t, uint_t, int (*)(caddr_t), caddr_t);
struct scsi_pkt	*scsi_init_pkt(struct scsi_address *,
		    struct scsi_pkt *, struct buf *, int, int, int, int,
		    int (*)(caddr_t), caddr_t);
void		scsi_destroy_pkt(struct scsi_pkt *);
void		scsi_free_consistent_buf(struct buf *);
struct scsi_pkt	*scsi_resalloc(struct scsi_address *, int,
		    int, opaque_t, int (*)(void));
struct scsi_pkt	*scsi_pktalloc(struct scsi_address *, int, int, int (*)(void));
struct scsi_pkt	*scsi_dmaget(struct scsi_pkt *, opaque_t, int (*)(void));
void		scsi_dmafree(struct scsi_pkt *);
void		scsi_sync_pkt(struct scsi_pkt *);
void		scsi_resfree(struct scsi_pkt *);

/*
 * Preliminary version of the SCSA specification
 * mentioned a routine called scsi_pktfree, which
 * turned out to be semantically equivialent to
 * scsi_resfree.
 */
#define	scsi_pktfree	scsi_resfree

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_SCSI_RESOURCE_H */
