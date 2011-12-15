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

/* Copyright © 2003-2011 Emulex. All rights reserved.  */

/*
 * Header file defining the driver buffer management interface
 */

#ifndef _OCE_BUF_H_
#define	_OCE_BUF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddidmareq.h>
#include <oce_io.h>
#include <oce_utils.h>

#define	GET_Q_NEXT(_START, _STEP, _END) \
	(((_START) + (_STEP)) < (_END) ? ((_START) + (_STEP)) \
	: (((_START) + (_STEP)) - (_END)))

#define	OCE_MAX_TX_HDL		8
#define	OCE_MAX_TXDMA_COOKIES	18
#define	OCE_TXMAP_ALIGN		1
#define	OCE_TX_MAX_FRAGS	(OCE_MAX_TX_HDL * OCE_MAX_TXDMA_COOKIES)

/* helper structure to access OS addresses */
typedef union  oce_addr_s {
	uint64_t addr64;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t addr_hi;
		uint32_t addr_lo;
#else
		uint32_t addr_lo;
		uint32_t addr_hi;
#endif
	}dw;
}oce_addr64_t;

typedef struct oce_dma_buf_s {
	caddr_t		base;
	uint64_t	addr;
	ddi_acc_handle_t acc_handle;
	ddi_dma_handle_t dma_handle;
	/* size of the memory */
	size_t		size;
	size_t		off;
	size_t		len;
	uint32_t	num_pages;
}oce_dma_buf_t;

#define	DBUF_PA(obj) (((oce_dma_buf_t *)(obj))->addr)
#define	DBUF_VA(obj) (((oce_dma_buf_t *)(obj))->base)
#define	DBUF_DHDL(obj) (((oce_dma_buf_t *)(obj))->dma_handle)
#define	DBUF_AHDL(obj) (((oce_dma_buf_t *)obj))->acc_handle)
#define	DBUF_SYNC(obj, flags)	(void) ddi_dma_sync(DBUF_DHDL(obj), 0,\
			0, (flags))

typedef struct oce_ring_buffer_s {
	uint16_t    cidx; 	/* Get ptr */
	uint16_t    pidx;	/* Put Ptr */
	size_t	item_size;	/* Size */
	size_t  num_items;	/* count */
	uint32_t  num_used;
	oce_dma_buf_t   *dbuf;	/* dma buffer */
}oce_ring_buffer_t;

typedef struct oce_rq_bdesc_s {
	oce_dma_buf_t	*rqb;
	struct oce_rq	*rq;
	oce_addr64_t 	frag_addr;
	mblk_t		*mp;
	frtn_t		fr_rtn;
    uint32_t    ref_cnt;
}oce_rq_bdesc_t;

typedef struct oce_wq_bdesc_s {
	OCE_LIST_NODE_T  link;
	oce_dma_buf_t	*wqb;
	oce_addr64_t 	frag_addr;
} oce_wq_bdesc_t;

typedef struct oce_wq_mdesc_s {
	OCE_LIST_NODE_T  	link;
	ddi_dma_handle_t	dma_handle;
} oce_wq_mdesc_t;

enum entry_type {
	HEADER_WQE = 0x1, /* arbitrary value */
	MAPPED_WQE,
	COPY_WQE,
	DUMMY_WQE
};

typedef struct _oce_handle_s {
    enum entry_type	type;
	void		*hdl; /* opaque handle */
}oce_handle_t;

typedef struct _oce_wqe_desc_s {
	OCE_LIST_NODE_T  link;
	oce_handle_t	hdesc[OCE_MAX_TX_HDL];
	struct oce_nic_frag_wqe frag[OCE_TX_MAX_FRAGS];
	struct oce_wq  *wq;
	mblk_t		*mp;
	uint16_t	wqe_cnt;
	uint16_t	frag_idx;
	uint16_t	frag_cnt;
	uint16_t	nhdl;
}oce_wqe_desc_t;

#pragma pack(1)
/* Always keep it 2 mod 4 */
typedef struct _oce_rq_buf_hdr_s {
	void *datap;
	uint8_t pad[18];
	/* ether_vlan_header_t vhdr; */
} oce_rq_buf_hdr_t;
#pragma pack()

#define	OCE_RQE_BUF_HEADROOM	18
#define	MAX_POOL_NAME		32

#define	RING_NUM_PENDING(ring)	ring->num_used

#define	RING_NUM_FREE(ring)	\
	(uint32_t)(ring->num_items - ring->num_used)

#define	RING_FULL(ring) (ring->num_used == ring->num_items)

#define	RING_EMPTY(ring) (ring->num_used == 0)

#define	RING_GET(ring, n)			\
	ring->cidx = GET_Q_NEXT(ring->cidx, n, ring->num_items)

#define	RING_PUT(ring, n)			\
	ring->pidx = GET_Q_NEXT(ring->pidx, n, ring->num_items)

#define	RING_GET_CONSUMER_ITEM_VA(ring, type) 	\
	(void*)(((type *)DBUF_VA(ring->dbuf)) + ring->cidx)

#define	RING_GET_CONSUMER_ITEM_PA(ring, type)		\
	(uint64_t)(((type *)DBUF_PA(ring->dbuf)) + ring->cidx)

#define	RING_GET_PRODUCER_ITEM_VA(ring, type)		\
	(void *)(((type *)DBUF_VA(ring->dbuf)) + ring->pidx)

#define	RING_GET_PRODUCER_ITEM_PA(ring, type)		\
	(uint64_t)(((type *)DBUF_PA(ring->dbuf)) + ring->pidx)

/* Rq cache */
int oce_rqb_cache_create(struct oce_rq *rq, size_t buf_size);
void oce_rqb_cache_destroy(struct oce_rq *rq);

/* Wq Cache */
int oce_wqe_desc_ctor(void *buf, void *arg, int kmflags);
void oce_wqe_desc_dtor(void *buf, void *arg);

int oce_wqb_cache_create(struct oce_wq *wq, size_t buf_size);
void oce_wqb_cache_destroy(struct oce_wq *wq);

void oce_wqm_cache_destroy(struct oce_wq *wq);
int oce_wqm_cache_create(struct oce_wq *wq);

void oce_page_list(oce_dma_buf_t *dbuf,
    struct phys_addr *pa_list, int list_size);


#ifdef __cplusplus
}
#endif

#endif /* _OCE_BUF_H_ */
