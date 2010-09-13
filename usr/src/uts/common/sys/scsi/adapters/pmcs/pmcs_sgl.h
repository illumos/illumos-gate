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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef	_PMCS_SGL_H
#define	_PMCS_SGL_H
#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This is the strict physical representation of an external
 * S/G list entry that the PMCS hardware uses. We manage them
 * in chunks.
 */
typedef struct {
	uint32_t	sglal;	/* Low 32 bit DMA address */
	uint32_t	sglah;	/* High 32 bit DMA address */
	uint32_t	sglen;	/* Length */
	uint32_t	flags;
} pmcs_dmasgl_t;

/*
 * If this is bit is set in flags, then the address
 * described by this structure is an array of SGLs,
 * the last of which may contain *another* flag
 * to continue the list.
 */
#define	PMCS_DMASGL_EXTENSION	(1U << 31)

#define	PMCS_SGL_CHUNKSZ	(PMCS_SGL_NCHUNKS * (sizeof (pmcs_dmasgl_t)))

/*
 * This is how we keep track of chunks- we have a linked list of
 * chunk pointers that are either on the free list or are tagged
 * off of a SCSA command. We used to maintain offsets indices
 * within the sglen area of the lest element of a chunk, but this
 * is marked reserved and may not be reliably used future firmware
 * revisions.
 */
typedef struct pmcs_dmachunk pmcs_dmachunk_t;
struct pmcs_dmachunk {
	pmcs_dmachunk_t	*nxt;
	pmcs_dmasgl_t	*chunks;
	unsigned long	addr;
	ddi_acc_handle_t	acc_handle;
	ddi_dma_handle_t	dma_handle;
};

/*
 * DMA related functions
 */
int pmcs_dma_load(pmcs_hw_t *, pmcs_cmd_t *, uint32_t *);
void pmcs_dma_unload(pmcs_hw_t *, pmcs_cmd_t *);

/*
 * After allocating some DMA chunks, insert them
 * into the free list and set them up for use.
 */
void pmcs_idma_chunks(pmcs_hw_t *, pmcs_dmachunk_t *,
    pmcs_chunk_t *, unsigned long);

#ifdef	__cplusplus
}
#endif
#endif	/* _PMCS_SGL_H */
