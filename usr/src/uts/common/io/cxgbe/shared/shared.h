/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGBE_SHARED_H
#define	__CXGBE_SHARED_H

#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	UNIMPLEMENTED() cmn_err(CE_WARN, "%s (%s:%d) unimplemented.", \
    __func__, __FILE__, __LINE__)

#define	bitloc(a, i)	((a)[(i)/NBBY])
#define	setbit(a, i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define	clrbit(a, i)	((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define	isset(a, i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define	isclr(a, i)	(((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)

/* TODO: really icky, but we don't want to include adapter.h in cxgb/cxgbe */
#define	PORT_INFO_HDR \
	dev_info_t *dip; \
	void *mh; \
	void *mc; \
	void *props; \
	int mtu; \
	uint8_t hw_addr[ETHERADDRL]

struct mblk_pair {
	mblk_t *head, *tail;
};

struct rxbuf {
	kmem_cache_t *cache;		/* the kmem_cache this rxb came from */
	ddi_dma_handle_t dhdl;
	ddi_acc_handle_t ahdl;
	caddr_t va;			/* KVA of buffer */
	uint64_t ba;			/* bus address of buffer */
	frtn_t freefunc;
	uint_t buf_size;
	volatile uint_t ref_cnt;
};

struct rxbuf_cache_params {
	dev_info_t		*dip;
	ddi_dma_attr_t		dma_attr_rx;
	ddi_device_acc_attr_t	acc_attr_rx;
	size_t			buf_size;
};

void cxgb_printf(dev_info_t *dip, int level, char *f, ...);
kmem_cache_t *rxbuf_cache_create(struct rxbuf_cache_params *p);
void rxbuf_cache_destroy(kmem_cache_t *cache);
struct rxbuf *rxbuf_alloc(kmem_cache_t *cache, int kmflags, uint_t ref_cnt);
void rxbuf_free(struct rxbuf *rxb);

#endif /* __CXGBE_SHARED_H */
