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

#ifndef	_SYS_SBP2_BUS_H
#define	_SYS_SBP2_BUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Serial Bus Protocol 2 (SBP-2) bus interface
 */

#include <sys/sbp2/common.h>
#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

enum {
	SBP2_BUS_REV_1	= 1,
	SBP2_BUS_REV	= SBP2_BUS_REV_1
};

typedef struct sbp2_bus_buf {
	struct sbp2_bus_buf *bb_next;	/* next in free list */
	void		*bb_hdl;	/* buffer handle */
	void		*bb_sbp2_priv;	/* SBP2 private data */
	size_t		bb_len;		/* buffer length */
	int		bb_flags;	/* flags */
	int		bb_dma_flags;	/* DDI_DMA_* flags */
	caddr_t		bb_kaddr;	/* kernel virtual address */
	uint64_t	bb_paddr;	/* physical address */
	uint64_t	bb_baddr;	/* bus address */
	void		(*bb_rq_cb)(struct sbp2_bus_buf *bb, void *reqh,
			    uint32_t *q);	/* quadlet read callback */
	void		(*bb_rb_cb)(struct sbp2_bus_buf *bb, void *reqh,
			    mblk_t **bpp, size_t len); /* block read callback */
	void		(*bb_wq_cb)(struct sbp2_bus_buf *bb, void *reqh,
			    uint32_t q);	/* quadlet write callback */
	void		(*bb_wb_cb)(struct sbp2_bus_buf *bb, void *reqh,
			    mblk_t **bpp);	/* block write callback */
} sbp2_bus_buf_t;

_NOTE(SCHEME_PROTECTS_DATA("unique per call", sbp2_bus_buf))

/* buffer flags */
enum {
	SBP2_BUS_BUF_DMA	= 0x01,	/* DMA buffer */
	SBP2_BUS_BUF_RD		= 0x02,	/* read buffer */
	SBP2_BUS_BUF_WR		= 0x04,	/* write buffer */
	SBP2_BUS_BUF_POSTED	= 0x08,	/* posted buffer */
	SBP2_BUS_BUF_RW		= (SBP2_BUS_BUF_RD | SBP2_BUS_BUF_WR),
	SBP2_BUS_BUF_WR_POSTED	= (SBP2_BUS_BUF_WR | SBP2_BUS_BUF_POSTED)
};

/* buffer request error codes */
enum {
	SBP2_BUS_BUF_SUCCESS		= 0,
	SBP2_BUS_BUF_FAILURE		= -1,	/* unspecified error */
	SBP2_BUS_BUF_ELENGTH		= 1,	/* wrong data length */
	SBP2_BUS_BUF_EBUSY		= 2	/* device busy */
};

typedef struct sbp2_bus {
	int		sb_rev;

	/* static parameters */
	uint64_t	sb_csr_base;	/* CSR base address */
	uint64_t	sb_cfgrom_addr;	/* Config ROM address */

	/* functions */
	ddi_iblock_cookie_t (*sb_get_iblock_cookie)(void *hdl);
	uint_t		(*sb_get_node_id)(void *hdl);
	int		(*sb_alloc_buf)(void *hdl, sbp2_bus_buf_t *buf);
	void		(*sb_free_buf)(void *hdl, sbp2_bus_buf_t *buf);
	int		(*sb_sync_buf)(void *hdl, sbp2_bus_buf_t *buf,
			    off_t offset, size_t length, int type);
	void		(*sb_buf_rd_done)(void *hdl, sbp2_bus_buf_t *buf,
			    void *reqh, int error);
	void		(*sb_buf_wr_done)(void *hdl, sbp2_bus_buf_t *buf,
			    void *reqh, int error);

	int		(*sb_alloc_cmd)(void *hdl, void **cmdp, int flags);
	void		(*sb_free_cmd)(void *hdl, void *cmd);
	int		(*sb_rq)(void *hdl, void *cmd, uint64_t addr,
			    uint32_t *q, int *berr);
	int		(*sb_rb)(void *hdl, void *cmd, uint64_t addr,
			    mblk_t **bpp, int len, int *err);
	int		(*sb_wq)(void *hdl, void *cmd, uint64_t addr,
			    uint32_t q, int *berr);
	int		(*sb_wb)(void *hdl, void *cmd, uint64_t addr,
			    mblk_t *bp, int len, int *berr);
} sbp2_bus_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBP2_BUS_H */
