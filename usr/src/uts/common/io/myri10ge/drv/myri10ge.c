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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2007-2009 Myricom, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#ifndef	lint
static const char __idstring[] =
	"@(#)$Id: myri10ge.c,v 1.186 2009-06-29 13:47:22 gallatin Exp $";
#endif

#define	MXGEFW_NDIS
#include "myri10ge_var.h"
#include "rss_eth_z8e.h"
#include "rss_ethp_z8e.h"
#include "mcp_gen_header.h"

#define	MYRI10GE_MAX_ETHER_MTU 9014
#define	MYRI10GE_MAX_GLD_MTU	9000
#define	MYRI10GE_MIN_GLD_MTU	1500

#define	MYRI10GE_ETH_STOPPED 0
#define	MYRI10GE_ETH_STOPPING 1
#define	MYRI10GE_ETH_STARTING 2
#define	MYRI10GE_ETH_RUNNING 3
#define	MYRI10GE_ETH_OPEN_FAILED 4
#define	MYRI10GE_ETH_SUSPENDED_RUNNING 5

static int myri10ge_small_bytes = 510;
static int myri10ge_intr_coal_delay = 125;
static int myri10ge_flow_control = 1;
#if defined __i386 || defined i386 || defined __i386__ || defined __x86_64__
static int myri10ge_nvidia_ecrc_enable = 1;
#endif
static int myri10ge_mtu_override = 0;
static int myri10ge_tx_copylen = 512;
static int myri10ge_deassert_wait = 1;
static int myri10ge_verbose = 0;
static int myri10ge_watchdog_reset = 0;
static int myri10ge_use_msix = 1;
static int myri10ge_max_slices = -1;
static int myri10ge_use_msi = 1;
int myri10ge_force_firmware = 0;
static boolean_t myri10ge_use_lso = B_TRUE;
static int myri10ge_rss_hash = MXGEFW_RSS_HASH_TYPE_SRC_DST_PORT;
static int myri10ge_tx_hash = 1;
static int myri10ge_lro = 0;
static int myri10ge_lro_cnt = 8;
int myri10ge_lro_max_aggr = 2;
static int myri10ge_lso_copy = 0;
static mblk_t *myri10ge_send_wrapper(void *arg, mblk_t *mp);
int myri10ge_tx_handles_initial = 128;

static 	kmutex_t myri10ge_param_lock;
static void* myri10ge_db_lastfree;

static int myri10ge_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int myri10ge_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int myri10ge_quiesce(dev_info_t *dip);

DDI_DEFINE_STREAM_OPS(myri10ge_ops, nulldev, nulldev, myri10ge_attach,
    myri10ge_detach, nodev, NULL, D_MP, NULL, myri10ge_quiesce);


static struct modldrv modldrv = {
	&mod_driverops,
	"Myricom 10G driver (10GbE)",
	&myri10ge_ops,
};


static struct modlinkage modlinkage = {
	MODREV_1,
	{&modldrv, NULL},
};

unsigned char myri10ge_broadcastaddr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static ddi_dma_attr_t myri10ge_misc_dma_attr = {
	DMA_ATTR_V0,			/* version number. */
	(uint64_t)0, 			/* low address */
	(uint64_t)0xffffffffffffffffULL, /* high address */
	(uint64_t)0x7ffffff,		/* address counter max */
	(uint64_t)4096,			/* alignment */
	(uint_t)0x7f,			/* burstsizes for 32b and 64b xfers */
	(uint32_t)0x1,			/* minimum transfer size */
	(uint64_t)0x7fffffff,		/* maximum transfer size */
	(uint64_t)0x7fffffff,		/* maximum segment size */
	1,				/* scatter/gather list length */
	1,				/* granularity */
	0				/* attribute flags */
};

/*
 * The Myri10GE NIC has the following constraints on receive buffers:
 * 1) Buffers which cross a 4KB boundary must be aligned to 4KB
 * 2) Buffers which are not aligned to 4KB must not cross a 4KB boundary
 */

static ddi_dma_attr_t myri10ge_rx_jumbo_dma_attr = {
	DMA_ATTR_V0,			/* version number. */
	(uint64_t)0, 			/* low address */
	(uint64_t)0xffffffffffffffffULL, /* high address */
	(uint64_t)0x7ffffff,		/* address counter max */
	(uint64_t)4096,			/* alignment */
	(uint_t)0x7f,			/* burstsizes for 32b and 64b xfers */
	(uint32_t)0x1,			/* minimum transfer size */
	(uint64_t)0x7fffffff,		/* maximum transfer size */
	UINT64_MAX,			/* maximum segment size */
	1,				/* scatter/gather list length */
	1,				/* granularity */
	0				/* attribute flags */
};

static ddi_dma_attr_t myri10ge_rx_std_dma_attr = {
	DMA_ATTR_V0,			/* version number. */
	(uint64_t)0, 			/* low address */
	(uint64_t)0xffffffffffffffffULL, /* high address */
	(uint64_t)0x7ffffff,		/* address counter max */
#if defined sparc64 || defined __sparcv9
	(uint64_t)4096,			/* alignment */
#else
	(uint64_t)0x80,			/* alignment */
#endif
	(uint_t)0x7f,			/* burstsizes for 32b and 64b xfers */
	(uint32_t)0x1,			/* minimum transfer size */
	(uint64_t)0x7fffffff,		/* maximum transfer size */
#if defined sparc64 || defined __sparcv9
	UINT64_MAX,			/* maximum segment size */
#else
	(uint64_t)0xfff,		/* maximum segment size */
#endif
	1,				/* scatter/gather list length */
	1,				/* granularity */
	0				/* attribute flags */
};

static ddi_dma_attr_t myri10ge_tx_dma_attr = {
	DMA_ATTR_V0,			/* version number. */
	(uint64_t)0, 			/* low address */
	(uint64_t)0xffffffffffffffffULL, /* high address */
	(uint64_t)0x7ffffff,		/* address counter max */
	(uint64_t)1,			/* alignment */
	(uint_t)0x7f,			/* burstsizes for 32b and 64b xfers */
	(uint32_t)0x1,			/* minimum transfer size */
	(uint64_t)0x7fffffff,		/* maximum transfer size */
	UINT64_MAX,			/* maximum segment size */
	INT32_MAX,			/* scatter/gather list length */
	1,				/* granularity */
	0			/* attribute flags */
};

#if defined sparc64 || defined __sparcv9
#define	WC 0
#else
#define	WC 1
#endif

struct ddi_device_acc_attr myri10ge_dev_access_attr = {
	DDI_DEVICE_ATTR_V0,		/* version */
	DDI_NEVERSWAP_ACC,		/* endian flash */
#if WC
	DDI_MERGING_OK_ACC		/* data order */
#else
	DDI_STRICTORDER_ACC
#endif
};

static void myri10ge_watchdog(void *arg);

#ifdef MYRICOM_PRIV
int myri10ge_mtu = MYRI10GE_MAX_ETHER_MTU + MXGEFW_PAD + VLAN_TAGSZ;
#define	MYRI10GE_DEFAULT_GLD_MTU	MYRI10GE_MAX_GLD_MTU
#else
int myri10ge_mtu = ETHERMAX + MXGEFW_PAD + VLAN_TAGSZ;
#define	MYRI10GE_DEFAULT_GLD_MTU	MYRI10GE_MIN_GLD_MTU
#endif
int myri10ge_bigbufs_initial = 1024;
int myri10ge_bigbufs_max = 4096;


caddr_t
myri10ge_dma_alloc(dev_info_t *dip, size_t len,
    ddi_dma_attr_t *attr, ddi_device_acc_attr_t  *accattr,
    uint_t alloc_flags, int bind_flags, struct myri10ge_dma_stuff *dma,
    int warn, int (*wait)(caddr_t))
{
	caddr_t  kaddr;
	size_t real_length;
	ddi_dma_cookie_t cookie;
	uint_t count;
	int err;

	err = ddi_dma_alloc_handle(dip, attr, wait,
	    NULL, &dma->handle);
	if (err != DDI_SUCCESS) {
		if (warn)
			cmn_err(CE_WARN,
			    "myri10ge: ddi_dma_alloc_handle failed\n");
		goto abort_with_nothing;
	}

	err = ddi_dma_mem_alloc(dma->handle, len, accattr, alloc_flags,
	    wait, NULL, &kaddr, &real_length,
	    &dma->acc_handle);
	if (err != DDI_SUCCESS) {
		if (warn)
			cmn_err(CE_WARN,
			    "myri10ge: ddi_dma_mem_alloc failed\n");
		goto abort_with_handle;
	}

	err = ddi_dma_addr_bind_handle(dma->handle, NULL, kaddr, len,
	    bind_flags, wait, NULL, &cookie, &count);

	if (err != DDI_SUCCESS) {
		if (warn)
			cmn_err(CE_WARN,
			    "myri10ge: ddi_dma_addr_bind_handle failed\n");
		goto abort_with_mem;
	}

	if (count != 1) {
		if (warn)
			cmn_err(CE_WARN,
			    "myri10ge: got too many dma segments ");
		goto abort_with_bind;
	}
	dma->low = htonl(MYRI10GE_LOWPART_TO_U32(cookie.dmac_laddress));
	dma->high = htonl(MYRI10GE_HIGHPART_TO_U32(cookie.dmac_laddress));
	return (kaddr);

abort_with_bind:
	(void) ddi_dma_unbind_handle(dma->handle);

abort_with_mem:
	ddi_dma_mem_free(&dma->acc_handle);

abort_with_handle:
	ddi_dma_free_handle(&dma->handle);
abort_with_nothing:
	if (warn) {
		cmn_err(CE_WARN, "myri10ge: myri10ge_dma_alloc failed.\n  ");
		cmn_err(CE_WARN, "args: dip=%p len=0x%lx ddi_dma_attr=%p\n",
		    (void*) dip, len, (void*) attr);
		cmn_err(CE_WARN,
		    "args: ddi_device_acc_attr=%p  alloc_flags=0x%x\n",
		    (void*) accattr, alloc_flags);
		cmn_err(CE_WARN, "args: bind_flags=0x%x  dmastuff=%p",
		    bind_flags, (void*) dma);
	}
	return (NULL);

}

void
myri10ge_dma_free(struct myri10ge_dma_stuff *dma)
{
	(void) ddi_dma_unbind_handle(dma->handle);
	ddi_dma_mem_free(&dma->acc_handle);
	ddi_dma_free_handle(&dma->handle);
}

static inline void
myri10ge_pio_copy32(void *to, uint32_t *from32, size_t size)
{
	register volatile uint32_t *to32;
	size_t i;

	to32 = (volatile uint32_t *) to;
	for (i = (size / 4); i; i--) {
		*to32 = *from32;
		to32++;
		from32++;
	}
}

#if defined(_LP64)
static inline void
myri10ge_pio_copy64(void *to, uint64_t *from64, size_t size)
{
	register volatile uint64_t *to64;
	size_t i;

	to64 = (volatile uint64_t *) to;
	for (i = (size / 8); i; i--) {
		*to64 = *from64;
		to64++;
		from64++;
	}
}
#endif

/*
 * This routine copies memory from the host to the NIC.
 * The "size" argument must always be a multiple of
 * the size of long (4 or 8 bytes), and to/from must also
 * be naturally aligned.
 */
static inline void
myri10ge_pio_copy(void *to, void *from, size_t size)
{
#if !defined(_LP64)
	ASSERT((size % 4) == 0);
	myri10ge_pio_copy32(to, (uint32_t *)from, size);
#else
	ASSERT((size % 8) == 0);
	myri10ge_pio_copy64(to, (uint64_t *)from, size);
#endif
}


/*
 * Due to various bugs in Solaris (especially bug 6186772 where the
 * TCP/UDP checksum is calculated incorrectly on mblk chains with more
 * than two elements), and the design bug where hardware checksums are
 * ignored on mblk chains with more than 2 elements, we need to
 * allocate private pool of physically contiguous receive buffers.
 */

static void
myri10ge_jpool_init(struct myri10ge_slice_state *ss)
{
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;

	bzero(jpool, sizeof (*jpool));
	mutex_init(&jpool->mtx, NULL, MUTEX_DRIVER,
	    ss->mgp->icookie);
	jpool->head = NULL;
}

static void
myri10ge_jpool_fini(struct myri10ge_slice_state *ss)
{
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;

	if (jpool->head != NULL) {
		cmn_err(CE_WARN,
		    "%s: BUG! myri10ge_jpool_fini called on non-empty pool\n",
		    ss->mgp->name);
	}
	mutex_destroy(&jpool->mtx);
}


/*
 * copy an array of mcp_kreq_ether_recv_t's to the mcp.  Copy
 * at most 32 bytes at a time, so as to avoid involving the software
 * pio handler in the nic.   We re-write the first segment's low
 * DMA address to mark it valid only after we write the entire chunk
 * in a burst
 */
static inline void
myri10ge_submit_8rx(mcp_kreq_ether_recv_t *dst, mcp_kreq_ether_recv_t *src)
{
	src->addr_low |= BE_32(1);
	myri10ge_pio_copy(dst, src, 4 * sizeof (*src));
	mb();
	myri10ge_pio_copy(dst + 4, src + 4, 4 * sizeof (*src));
	mb();
	src->addr_low &= ~(BE_32(1));
	dst->addr_low = src->addr_low;
	mb();
}

static void
myri10ge_pull_jpool(struct myri10ge_slice_state *ss)
{
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;
	struct myri10ge_jpool_entry *jtail, *j, *jfree;
	volatile uintptr_t *putp;
	uintptr_t put;
	int i;

	/* find tail */
	jtail = NULL;
	if (jpool->head != NULL) {
		j = jpool->head;
		while (j->next != NULL)
			j = j->next;
		jtail = j;
	}

	/*
	 * iterate over all per-CPU caches, and add contents into
	 * jpool
	 */
	for (i = 0; i < MYRI10GE_MAX_CPUS; i++) {
		/* take per-CPU free list */
		putp = (void *)&jpool->cpu[i & MYRI10GE_MAX_CPU_MASK].head;
		if (*putp == NULL)
			continue;
		put = atomic_swap_ulong(putp, 0);
		jfree = (struct myri10ge_jpool_entry *)put;

		/* append to pool */
		if (jtail == NULL) {
			jpool->head = jfree;
		} else {
			jtail->next = jfree;
		}
		j = jfree;
		while (j->next != NULL)
			j = j->next;
		jtail = j;
	}
}

/*
 * Transfers buffers from the free pool to the nic
 * Must be called holding the jpool mutex.
 */

static inline void
myri10ge_restock_jumbos(struct myri10ge_slice_state *ss)
{
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;
	struct myri10ge_jpool_entry *j;
	myri10ge_rx_ring_t *rx;
	int i, idx, limit;

	rx = &ss->rx_big;
	limit = ss->j_rx_cnt + (rx->mask + 1);

	for (i = rx->cnt; i != limit; i++) {
		idx = i & (rx->mask);
		j = jpool->head;
		if (j == NULL) {
			myri10ge_pull_jpool(ss);
			j = jpool->head;
			if (j == NULL) {
				break;
			}
		}
		jpool->head = j->next;
		rx->info[idx].j = j;
		rx->shadow[idx].addr_low = j->dma.low;
		rx->shadow[idx].addr_high = j->dma.high;
		/* copy 4 descriptors (32-bytes) to the mcp at a time */
		if ((idx & 7) == 7) {
			myri10ge_submit_8rx(&rx->lanai[idx - 7],
			    &rx->shadow[idx - 7]);
		}
	}
	rx->cnt = i;
}

/*
 * Transfer buffers from the nic to the free pool.
 * Should be called holding the jpool mutex
 */

static inline void
myri10ge_unstock_jumbos(struct myri10ge_slice_state *ss)
{
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;
	struct myri10ge_jpool_entry *j;
	myri10ge_rx_ring_t *rx;
	int i;

	mutex_enter(&jpool->mtx);
	rx = &ss->rx_big;

	for (i = 0; i < rx->mask + 1; i++) {
		j = rx->info[i].j;
		rx->info[i].j = NULL;
		if (j == NULL)
			continue;
		j->next = jpool->head;
		jpool->head = j;
	}
	mutex_exit(&jpool->mtx);

}


/*
 * Free routine which is called when the mblk allocated via
 * esballoc() is freed.   Here we return the jumbo buffer
 * to the free pool, and possibly pass some jumbo buffers
 * to the nic
 */

static void
myri10ge_jfree_rtn(void *arg)
{
	struct myri10ge_jpool_entry *j = (struct myri10ge_jpool_entry *)arg;
	struct myri10ge_jpool_stuff *jpool;
	volatile uintptr_t *putp;
	uintptr_t old, new;

	jpool = &j->ss->jpool;

	/* prepend buffer locklessly to per-CPU freelist */
	putp = (void *)&jpool->cpu[CPU->cpu_seqid & MYRI10GE_MAX_CPU_MASK].head;
	new = (uintptr_t)j;
	do {
		old = *putp;
		j->next = (void *)old;
	} while (atomic_cas_ulong(putp, old, new) != old);
}

static void
myri10ge_remove_jbuf(struct myri10ge_jpool_entry *j)
{
	(void) ddi_dma_unbind_handle(j->dma_handle);
	ddi_dma_mem_free(&j->acc_handle);
	ddi_dma_free_handle(&j->dma_handle);
	kmem_free(j, sizeof (*j));
}


/*
 * Allocates one physically contiguous descriptor
 * and add it to the jumbo buffer pool.
 */

static int
myri10ge_add_jbuf(struct myri10ge_slice_state *ss)
{
	struct myri10ge_jpool_entry *j;
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;
	ddi_dma_attr_t *rx_dma_attr;
	size_t real_length;
	ddi_dma_cookie_t cookie;
	uint_t count;
	int err;

	if (myri10ge_mtu < 2048)
		rx_dma_attr = &myri10ge_rx_std_dma_attr;
	else
		rx_dma_attr = &myri10ge_rx_jumbo_dma_attr;

again:
	j = (struct myri10ge_jpool_entry *)
	    kmem_alloc(sizeof (*j), KM_SLEEP);
	err = ddi_dma_alloc_handle(ss->mgp->dip, rx_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &j->dma_handle);
	if (err != DDI_SUCCESS)
		goto abort_with_j;

	err = ddi_dma_mem_alloc(j->dma_handle, myri10ge_mtu,
	    &myri10ge_dev_access_attr,  DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
	    NULL, &j->buf, &real_length, &j->acc_handle);
	if (err != DDI_SUCCESS)
		goto abort_with_handle;

	err = ddi_dma_addr_bind_handle(j->dma_handle, NULL, j->buf,
	    real_length, DDI_DMA_READ|DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
	    NULL, &cookie, &count);
	if (err != DDI_SUCCESS)
		goto abort_with_mem;

	/*
	 * Make certain std MTU buffers do not cross a 4KB boundary:
	 *
	 * Setting dma_attr_align=4096 will do this, but the system
	 * will only allocate 1 RX buffer per 4KB page, rather than 2.
	 * Setting dma_attr_granular=4096 *seems* to work around this,
	 * but I'm paranoid about future systems no longer honoring
	 * this, so fall back to the safe, but memory wasting way if a
	 * buffer crosses a 4KB boundary.
	 */

	if (rx_dma_attr == &myri10ge_rx_std_dma_attr &&
	    rx_dma_attr->dma_attr_align != 4096) {
		uint32_t start, end;

		start = MYRI10GE_LOWPART_TO_U32(cookie.dmac_laddress);
		end = start + myri10ge_mtu;
		if (((end >> 12) != (start >> 12)) && (start & 4095U)) {
			printf("std buffer crossed a 4KB boundary!\n");
			myri10ge_remove_jbuf(j);
			rx_dma_attr->dma_attr_align = 4096;
			rx_dma_attr->dma_attr_seg = UINT64_MAX;
			goto again;
		}
	}

	j->dma.low =
	    htonl(MYRI10GE_LOWPART_TO_U32(cookie.dmac_laddress));
	j->dma.high =
	    htonl(MYRI10GE_HIGHPART_TO_U32(cookie.dmac_laddress));
	j->ss = ss;


	j->free_func.free_func = myri10ge_jfree_rtn;
	j->free_func.free_arg = (char *)j;
	mutex_enter(&jpool->mtx);
	j->next = jpool->head;
	jpool->head = j;
	jpool->num_alloc++;
	mutex_exit(&jpool->mtx);
	return (0);

abort_with_mem:
	ddi_dma_mem_free(&j->acc_handle);

abort_with_handle:
	ddi_dma_free_handle(&j->dma_handle);

abort_with_j:
	kmem_free(j, sizeof (*j));

	/*
	 * If an allocation failed, perhaps it failed because it could
	 * not satisfy granularity requirement.  Disable that, and
	 * try agin.
	 */
	if (rx_dma_attr == &myri10ge_rx_std_dma_attr &&
	    rx_dma_attr->dma_attr_align != 4096) {
			cmn_err(CE_NOTE,
			    "!alloc failed, reverting to gran=1\n");
			rx_dma_attr->dma_attr_align = 4096;
			rx_dma_attr->dma_attr_seg = UINT64_MAX;
			goto again;
	}
	return (err);
}

static int
myri10ge_jfree_cnt(struct myri10ge_jpool_stuff *jpool)
{
	int i;
	struct myri10ge_jpool_entry *j;

	mutex_enter(&jpool->mtx);
	j = jpool->head;
	i = 0;
	while (j != NULL) {
		i++;
		j = j->next;
	}
	mutex_exit(&jpool->mtx);
	return (i);
}

static int
myri10ge_add_jbufs(struct myri10ge_slice_state *ss, int num, int total)
{
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;
	int allocated = 0;
	int err;
	int needed;

	/*
	 * if total is set, user wants "num" jbufs in the pool,
	 * otherwise the user wants to "num" additional jbufs
	 * added to the pool
	 */
	if (total && jpool->num_alloc) {
		allocated = myri10ge_jfree_cnt(jpool);
		needed = num - allocated;
	} else {
		needed = num;
	}

	while (needed > 0) {
		needed--;
		err = myri10ge_add_jbuf(ss);
		if (err == 0) {
			allocated++;
		}
	}
	return (allocated);
}

static void
myri10ge_remove_jbufs(struct myri10ge_slice_state *ss)
{
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;
	struct myri10ge_jpool_entry *j;

	mutex_enter(&jpool->mtx);
	myri10ge_pull_jpool(ss);
	while (jpool->head != NULL) {
		jpool->num_alloc--;
		j = jpool->head;
		jpool->head = j->next;
		myri10ge_remove_jbuf(j);
	}
	mutex_exit(&jpool->mtx);
}

static void
myri10ge_carve_up_jbufs_into_small_ring(struct myri10ge_slice_state *ss)
{
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;
	struct myri10ge_jpool_entry *j = NULL;
	caddr_t ptr;
	uint32_t dma_low, dma_high;
	int idx, len;
	unsigned int alloc_size;

	dma_low = dma_high = len = 0;
	alloc_size = myri10ge_small_bytes + MXGEFW_PAD;
	ptr = NULL;
	for (idx = 0; idx < ss->rx_small.mask + 1; idx++) {
		/* Allocate a jumbo frame and carve it into small frames */
		if (len < alloc_size) {
			mutex_enter(&jpool->mtx);
			/* remove jumbo from freelist */
			j = jpool->head;
			jpool->head = j->next;
			/* place it onto small list */
			j->next = ss->small_jpool;
			ss->small_jpool = j;
			mutex_exit(&jpool->mtx);
			len = myri10ge_mtu;
			dma_low = ntohl(j->dma.low);
			dma_high = ntohl(j->dma.high);
			ptr = j->buf;
		}
		ss->rx_small.info[idx].ptr = ptr;
		ss->rx_small.shadow[idx].addr_low = htonl(dma_low);
		ss->rx_small.shadow[idx].addr_high = htonl(dma_high);
		len -= alloc_size;
		ptr += alloc_size;
		dma_low += alloc_size;
	}
}

/*
 * Return the jumbo bufs we carved up for small to the jumbo pool
 */

static void
myri10ge_release_small_jbufs(struct myri10ge_slice_state *ss)
{
	struct myri10ge_jpool_stuff *jpool = &ss->jpool;
	struct myri10ge_jpool_entry *j = NULL;

	mutex_enter(&jpool->mtx);
	while (ss->small_jpool != NULL) {
		j = ss->small_jpool;
		ss->small_jpool = j->next;
		j->next = jpool->head;
		jpool->head = j;
	}
	mutex_exit(&jpool->mtx);
	ss->jbufs_for_smalls = 0;
}

static int
myri10ge_add_tx_handle(struct myri10ge_slice_state *ss)
{
	myri10ge_tx_ring_t *tx = &ss->tx;
	struct myri10ge_priv *mgp = ss->mgp;
	struct myri10ge_tx_dma_handle *handle;
	int err;

	handle = kmem_zalloc(sizeof (*handle), KM_SLEEP);
	err = ddi_dma_alloc_handle(mgp->dip,
	    &myri10ge_tx_dma_attr,
	    DDI_DMA_SLEEP, NULL,
	    &handle->h);
	if (err) {
		static int limit = 0;
		if (limit == 0)
			cmn_err(CE_WARN, "%s: Falled to alloc tx dma handle\n",
			    mgp->name);
		limit++;
		kmem_free(handle, sizeof (*handle));
		return (err);
	}
	mutex_enter(&tx->handle_lock);
	MYRI10GE_SLICE_STAT_INC(tx_handles_alloced);
	handle->next = tx->free_tx_handles;
	tx->free_tx_handles = handle;
	mutex_exit(&tx->handle_lock);
	return (DDI_SUCCESS);
}

static void
myri10ge_remove_tx_handles(struct myri10ge_slice_state *ss)
{
	myri10ge_tx_ring_t *tx = &ss->tx;
	struct myri10ge_tx_dma_handle *handle;
	mutex_enter(&tx->handle_lock);

	handle = tx->free_tx_handles;
	while (handle != NULL) {
		tx->free_tx_handles = handle->next;
		ddi_dma_free_handle(&handle->h);
		kmem_free(handle, sizeof (*handle));
		handle = tx->free_tx_handles;
		MYRI10GE_SLICE_STAT_DEC(tx_handles_alloced);
	}
	mutex_exit(&tx->handle_lock);
	if (MYRI10GE_SLICE_STAT(tx_handles_alloced) != 0) {
		cmn_err(CE_WARN, "%s: %d tx dma handles allocated at close\n",
		    ss->mgp->name,
		    (int)MYRI10GE_SLICE_STAT(tx_handles_alloced));
	}
}

static void
myri10ge_free_tx_handles(myri10ge_tx_ring_t *tx,
    struct myri10ge_tx_dma_handle_head *list)
{
	mutex_enter(&tx->handle_lock);
	list->tail->next = tx->free_tx_handles;
	tx->free_tx_handles = list->head;
	mutex_exit(&tx->handle_lock);
}

static void
myri10ge_free_tx_handle_slist(myri10ge_tx_ring_t *tx,
    struct myri10ge_tx_dma_handle *handle)
{
	struct myri10ge_tx_dma_handle_head list;

	if (handle == NULL)
		return;
	list.head = handle;
	list.tail = handle;
	while (handle != NULL) {
		list.tail = handle;
		handle = handle->next;
	}
	myri10ge_free_tx_handles(tx, &list);
}

static int
myri10ge_alloc_tx_handles(struct myri10ge_slice_state *ss, int count,
    struct myri10ge_tx_dma_handle **ret)
{
	myri10ge_tx_ring_t *tx = &ss->tx;
	struct myri10ge_tx_dma_handle *handle;
	int err, i;

	mutex_enter(&tx->handle_lock);
	for (i = 0; i < count; i++) {
		handle = tx->free_tx_handles;
		while (handle == NULL) {
			mutex_exit(&tx->handle_lock);
			err = myri10ge_add_tx_handle(ss);
			if (err != DDI_SUCCESS) {
				goto abort_with_handles;
			}
			mutex_enter(&tx->handle_lock);
			handle = tx->free_tx_handles;
		}
		tx->free_tx_handles = handle->next;
		handle->next = *ret;
		*ret = handle;
	}
	mutex_exit(&tx->handle_lock);
	return (DDI_SUCCESS);

abort_with_handles:
	myri10ge_free_tx_handle_slist(tx, *ret);
	return (err);
}


/*
 * Frees DMA resources associated with the send ring
 */
static void
myri10ge_unprepare_tx_ring(struct myri10ge_slice_state *ss)
{
	myri10ge_tx_ring_t *tx;
	struct myri10ge_tx_dma_handle_head handles;
	size_t bytes;
	int idx;

	tx = &ss->tx;
	handles.head = NULL;
	handles.tail = NULL;
	for (idx = 0; idx < ss->tx.mask + 1; idx++) {
		if (tx->info[idx].m) {
			(void) ddi_dma_unbind_handle(tx->info[idx].handle->h);
			handles.head = tx->info[idx].handle;
			if (handles.tail == NULL)
				handles.tail = tx->info[idx].handle;
			freeb(tx->info[idx].m);
			tx->info[idx].m = 0;
			tx->info[idx].handle = 0;
		}
		tx->cp[idx].va = NULL;
		myri10ge_dma_free(&tx->cp[idx].dma);
	}
	bytes = sizeof (*tx->cp) * (tx->mask + 1);
	kmem_free(tx->cp, bytes);
	tx->cp = NULL;
	if (handles.head != NULL)
		myri10ge_free_tx_handles(tx, &handles);
	myri10ge_remove_tx_handles(ss);
}

/*
 * Allocates DMA handles associated with the send ring
 */
static inline int
myri10ge_prepare_tx_ring(struct myri10ge_slice_state *ss)
{
	struct myri10ge_tx_dma_handle *handles;
	int h;
	size_t bytes;

	bytes = sizeof (*ss->tx.cp) * (ss->tx.mask + 1);
	ss->tx.cp = kmem_zalloc(bytes, KM_SLEEP);
	if (ss->tx.cp == NULL) {
		cmn_err(CE_WARN,
		    "%s: Failed to allocate tx copyblock storage\n",
		    ss->mgp->name);
		return (DDI_FAILURE);
	}


	/* allocate the TX copyblocks */
	for (h = 0; h < ss->tx.mask + 1; h++) {
		ss->tx.cp[h].va = myri10ge_dma_alloc(ss->mgp->dip,
		    4096, &myri10ge_rx_jumbo_dma_attr,
		    &myri10ge_dev_access_attr, DDI_DMA_STREAMING,
		    DDI_DMA_WRITE|DDI_DMA_STREAMING, &ss->tx.cp[h].dma, 1,
		    DDI_DMA_DONTWAIT);
		if (ss->tx.cp[h].va == NULL) {
			cmn_err(CE_WARN, "%s: Failed to allocate tx "
			    "copyblock %d\n", ss->mgp->name, h);
			goto abort_with_copyblocks;
		}
	}
	/* pre-allocate transmit handles */
	handles = NULL;
	(void) myri10ge_alloc_tx_handles(ss, myri10ge_tx_handles_initial,
	    &handles);
	if (handles != NULL)
		myri10ge_free_tx_handle_slist(&ss->tx, handles);

	return (DDI_SUCCESS);

abort_with_copyblocks:
	while (h > 0)  {
		h--;
		myri10ge_dma_free(&ss->tx.cp[h].dma);
	}

	bytes = sizeof (*ss->tx.cp) * (ss->tx.mask + 1);
	kmem_free(ss->tx.cp, bytes);
	ss->tx.cp = NULL;
	return (DDI_FAILURE);
}

/*
 * The eeprom strings on the lanaiX have the format
 * SN=x\0
 * MAC=x:x:x:x:x:x\0
 * PT:ddd mmm xx xx:xx:xx xx\0
 * PV:ddd mmm xx xx:xx:xx xx\0
 */
static int
myri10ge_read_mac_addr(struct myri10ge_priv *mgp)
{
#define	MYRI10GE_NEXT_STRING(p) while (ptr < limit && *ptr++)
#define	myri10ge_digit(c) (((c) >= '0' && (c) <= '9') ? ((c) - '0') :	\
		(((c) >= 'A' && (c) <= 'F') ? (10 + (c) - 'A') :	\
		(((c) >= 'a' && (c) <= 'f') ? (10 + (c) - 'a') : -1)))

	char *ptr, *limit;
	int i, hv, lv;

	ptr = mgp->eeprom_strings;
	limit = mgp->eeprom_strings + MYRI10GE_EEPROM_STRINGS_SIZE;

	while (*ptr != '\0' && ptr < limit) {
		if (memcmp(ptr, "MAC=", 4) == 0) {
			ptr += 4;
			if (myri10ge_verbose)
				printf("%s: mac address = %s\n", mgp->name,
				    ptr);
			mgp->mac_addr_string = ptr;
			for (i = 0; i < 6; i++) {
				if ((ptr + 2) > limit)
					goto abort;

				if (*(ptr+1) == ':') {
					hv = 0;
					lv = myri10ge_digit(*ptr); ptr++;
				} else {
					hv = myri10ge_digit(*ptr); ptr++;
					lv = myri10ge_digit(*ptr); ptr++;
				}
				mgp->mac_addr[i] = (hv << 4) | lv;
				ptr++;
			}
		}
		if (memcmp((const void *)ptr, "SN=", 3) == 0) {
			ptr += 3;
			mgp->sn_str = (char *)ptr;
		}
		if (memcmp((const void *)ptr, "PC=", 3) == 0) {
			ptr += 3;
			mgp->pc_str = (char *)ptr;
		}
		MYRI10GE_NEXT_STRING(ptr);
	}

	return (0);

abort:
	cmn_err(CE_WARN, "%s: failed to parse eeprom_strings", mgp->name);
	return (ENXIO);
}


/*
 * Determine the register set containing the PCI resource we
 * want to map: the memory-mappable part of the interface. We do
 * this by scanning the DDI "reg" property of the interface,
 * which is an array of mx_ddi_reg_set structures.
 */
static int
myri10ge_reg_set(dev_info_t *dip, int *reg_set, int *span,
    unsigned long *busno, unsigned long *devno,
    unsigned long *funcno)
{

#define	REGISTER_NUMBER(ip)	(ip[0] >>  0 & 0xff)
#define	FUNCTION_NUMBER(ip)	(ip[0] >>  8 & 0x07)
#define	DEVICE_NUMBER(ip)	(ip[0] >> 11 & 0x1f)
#define	BUS_NUMBER(ip)		(ip[0] >> 16 & 0xff)
#define	ADDRESS_SPACE(ip)	(ip[0] >> 24 & 0x03)
#define	PCI_ADDR_HIGH(ip)	(ip[1])
#define	PCI_ADDR_LOW(ip) 	(ip[2])
#define	PCI_SPAN_HIGH(ip)	(ip[3])
#define	PCI_SPAN_LOW(ip)	(ip[4])

#define	MX_DDI_REG_SET_32_BIT_MEMORY_SPACE 2
#define	MX_DDI_REG_SET_64_BIT_MEMORY_SPACE 3

	int *data, i, *rs;
	uint32_t nelementsp;

#ifdef MYRI10GE_REGSET_VERBOSE
	char *address_space_name[] = { "Configuration Space",
					"I/O Space",
					"32-bit Memory Space",
					"64-bit Memory Space"
	};
#endif

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &data, &nelementsp) != DDI_SUCCESS) {
		printf("Could not determine register set.\n");
		return (ENXIO);
	}

#ifdef MYRI10GE_REGSET_VERBOSE
	printf("There are %d register sets.\n", nelementsp / 5);
#endif
	if (!nelementsp) {
		printf("Didn't find any \"reg\" properties.\n");
		ddi_prop_free(data);
		return (ENODEV);
	}

	/* Scan for the register number. */
	rs = &data[0];
	*busno = BUS_NUMBER(rs);
	*devno = DEVICE_NUMBER(rs);
	*funcno = FUNCTION_NUMBER(rs);

#ifdef MYRI10GE_REGSET_VERBOSE
	printf("*** Scanning for register number.\n");
#endif
	for (i = 0; i < nelementsp / 5; i++) {
		rs = &data[5 * i];
#ifdef MYRI10GE_REGSET_VERBOSE
		printf("Examining register set %d:\n", i);
		printf("  Register number = %d.\n", REGISTER_NUMBER(rs));
		printf("  Function number = %d.\n", FUNCTION_NUMBER(rs));
		printf("  Device number   = %d.\n", DEVICE_NUMBER(rs));
		printf("  Bus number      = %d.\n", BUS_NUMBER(rs));
		printf("  Address space   = %d (%s ).\n", ADDRESS_SPACE(rs),
		    address_space_name[ADDRESS_SPACE(rs)]);
		printf("  pci address 0x%08x %08x\n", PCI_ADDR_HIGH(rs),
		    PCI_ADDR_LOW(rs));
		printf("  pci span 0x%08x %08x\n", PCI_SPAN_HIGH(rs),
		    PCI_SPAN_LOW(rs));
#endif
		/* We are looking for a memory property. */

		if (ADDRESS_SPACE(rs) == MX_DDI_REG_SET_64_BIT_MEMORY_SPACE ||
		    ADDRESS_SPACE(rs) == MX_DDI_REG_SET_32_BIT_MEMORY_SPACE) {
			*reg_set = i;

#ifdef MYRI10GE_REGSET_VERBOSE
			printf("%s uses register set %d.\n",
			    address_space_name[ADDRESS_SPACE(rs)], *reg_set);
#endif

			*span = (PCI_SPAN_LOW(rs));
#ifdef MYRI10GE_REGSET_VERBOSE
			printf("Board span is 0x%x\n", *span);
#endif
			break;
		}
	}

	ddi_prop_free(data);

	/* If no match, fail. */
	if (i >= nelementsp / 5) {
		return (EIO);
	}

	return (0);
}


static int
myri10ge_load_firmware_from_zlib(struct myri10ge_priv *mgp, uint32_t *limit)
{
	void *inflate_buffer;
	int rv, status;
	size_t sram_size = mgp->sram_size - MYRI10GE_EEPROM_STRINGS_SIZE;
	size_t destlen;
	mcp_gen_header_t *hdr;
	unsigned hdr_offset, i;


	*limit = 0; /* -Wuninitialized */
	status = 0;

	inflate_buffer = kmem_zalloc(sram_size, KM_NOSLEEP);
	if (!inflate_buffer) {
		cmn_err(CE_WARN,
		    "%s: Could not allocate buffer to inflate mcp\n",
		    mgp->name);
		return (ENOMEM);
	}

	destlen = sram_size;
	rv = z_uncompress(inflate_buffer, &destlen, mgp->eth_z8e,
	    mgp->eth_z8e_length);

	if (rv != Z_OK) {
		cmn_err(CE_WARN, "%s: Could not inflate mcp: %s\n",
		    mgp->name, z_strerror(rv));
		status = ENXIO;
		goto abort;
	}

	*limit = (uint32_t)destlen;

	hdr_offset = htonl(*(uint32_t *)(void *)((char *)inflate_buffer +
	    MCP_HEADER_PTR_OFFSET));
	hdr = (void *)((char *)inflate_buffer + hdr_offset);
	if (ntohl(hdr->mcp_type) != MCP_TYPE_ETH) {
		cmn_err(CE_WARN, "%s: Bad firmware type: 0x%x\n", mgp->name,
		    ntohl(hdr->mcp_type));
		status = EIO;
		goto abort;
	}

	/* save firmware version for kstat */
	(void) strncpy(mgp->fw_version, hdr->version, sizeof (mgp->fw_version));
	if (myri10ge_verbose)
		printf("%s: firmware id: %s\n", mgp->name, hdr->version);

	/* Copy the inflated firmware to NIC SRAM. */
	for (i = 0; i < *limit; i += 256) {
		myri10ge_pio_copy((char *)mgp->sram + MYRI10GE_FW_OFFSET + i,
		    (char *)inflate_buffer + i,
		    min(256U, (unsigned)(*limit - i)));
		mb();
		(void) *(int *)(void *)mgp->sram;
		mb();
	}

abort:
	kmem_free(inflate_buffer, sram_size);

	return (status);

}


int
myri10ge_send_cmd(struct myri10ge_priv *mgp, uint32_t cmd,
		myri10ge_cmd_t *data)
{
	mcp_cmd_t *buf;
	char buf_bytes[sizeof (*buf) + 8];
	volatile mcp_cmd_response_t *response = mgp->cmd;
	volatile char *cmd_addr =
	    (volatile char *)mgp->sram + MXGEFW_ETH_CMD;
	int sleep_total = 0;

	/* ensure buf is aligned to 8 bytes */
	buf = (mcp_cmd_t *)((unsigned long)(buf_bytes + 7) & ~7UL);

	buf->data0 = htonl(data->data0);
	buf->data1 = htonl(data->data1);
	buf->data2 = htonl(data->data2);
	buf->cmd = htonl(cmd);
	buf->response_addr.low = mgp->cmd_dma.low;
	buf->response_addr.high = mgp->cmd_dma.high;
	mutex_enter(&mgp->cmd_lock);
	response->result = 0xffffffff;
	mb();

	myri10ge_pio_copy((void *)cmd_addr, buf, sizeof (*buf));

	/* wait up to 20ms */
	for (sleep_total = 0; sleep_total < 20; sleep_total++) {
		mb();
		if (response->result != 0xffffffff) {
			if (response->result == 0) {
				data->data0 = ntohl(response->data);
				mutex_exit(&mgp->cmd_lock);
				return (0);
			} else if (ntohl(response->result)
			    == MXGEFW_CMD_UNKNOWN) {
				mutex_exit(&mgp->cmd_lock);
				return (ENOSYS);
			} else if (ntohl(response->result)
			    == MXGEFW_CMD_ERROR_UNALIGNED) {
				mutex_exit(&mgp->cmd_lock);
				return (E2BIG);
			} else {
				cmn_err(CE_WARN,
				    "%s: command %d failed, result = %d\n",
				    mgp->name, cmd, ntohl(response->result));
				mutex_exit(&mgp->cmd_lock);
				return (ENXIO);
			}
		}
		drv_usecwait(1000);
	}
	mutex_exit(&mgp->cmd_lock);
	cmn_err(CE_WARN, "%s: command %d timed out, result = %d\n",
	    mgp->name, cmd, ntohl(response->result));
	return (EAGAIN);
}

/*
 * Enable or disable periodic RDMAs from the host to make certain
 * chipsets resend dropped PCIe messages
 */

static void
myri10ge_dummy_rdma(struct myri10ge_priv *mgp, int enable)
{
	char buf_bytes[72];
	volatile uint32_t *confirm;
	volatile char *submit;
	uint32_t *buf;
	int i;

	buf = (uint32_t *)((unsigned long)(buf_bytes + 7) & ~7UL);

	/* clear confirmation addr */
	confirm = (volatile uint32_t *)mgp->cmd;
	*confirm = 0;
	mb();

	/*
	 * send an rdma command to the PCIe engine, and wait for the
	 * response in the confirmation address.  The firmware should
	 *  write a -1 there to indicate it is alive and well
	 */

	buf[0] = mgp->cmd_dma.high;		/* confirm addr MSW */
	buf[1] = mgp->cmd_dma.low;		/* confirm addr LSW */
	buf[2] = htonl(0xffffffff);		/* confirm data */
	buf[3] = htonl(mgp->cmd_dma.high); 	/* dummy addr MSW */
	buf[4] = htonl(mgp->cmd_dma.low); 	/* dummy addr LSW */
	buf[5] = htonl(enable);			/* enable? */


	submit = (volatile char *)(mgp->sram + MXGEFW_BOOT_DUMMY_RDMA);

	myri10ge_pio_copy((char *)submit, buf, 64);
	mb();
	drv_usecwait(1000);
	mb();
	i = 0;
	while (*confirm != 0xffffffff && i < 20) {
		drv_usecwait(1000);
		i++;
	}
	if (*confirm != 0xffffffff) {
		cmn_err(CE_WARN, "%s: dummy rdma %s failed (%p = 0x%x)",
		    mgp->name,
		    (enable ? "enable" : "disable"), (void*) confirm, *confirm);
	}
}

static int
myri10ge_load_firmware(struct myri10ge_priv *mgp)
{
	myri10ge_cmd_t cmd;
	volatile uint32_t *confirm;
	volatile char *submit;
	char buf_bytes[72];
	uint32_t *buf, size;
	int status, i;

	buf = (uint32_t *)((unsigned long)(buf_bytes + 7) & ~7UL);

	status = myri10ge_load_firmware_from_zlib(mgp, &size);
	if (status) {
		cmn_err(CE_WARN, "%s: firmware loading failed\n", mgp->name);
		return (status);
	}

	/* clear confirmation addr */
	confirm = (volatile uint32_t *)mgp->cmd;
	*confirm = 0;
	mb();

	/*
	 * send a reload command to the bootstrap MCP, and wait for the
	 * response in the confirmation address.  The firmware should
	 * write a -1 there to indicate it is alive and well
	 */

	buf[0] = mgp->cmd_dma.high;	/* confirm addr MSW */
	buf[1] = mgp->cmd_dma.low;	/* confirm addr LSW */
	buf[2] = htonl(0xffffffff);	/* confirm data */

	/*
	 * FIX: All newest firmware should un-protect the bottom of
	 * the sram before handoff. However, the very first interfaces
	 * do not. Therefore the handoff copy must skip the first 8 bytes
	 */
	buf[3] = htonl(MYRI10GE_FW_OFFSET + 8); /* where the code starts */
	buf[4] = htonl(size - 8); 	/* length of code */
	buf[5] = htonl(8);		/* where to copy to */
	buf[6] = htonl(0);		/* where to jump to */

	submit = (volatile char *)(mgp->sram + MXGEFW_BOOT_HANDOFF);

	myri10ge_pio_copy((char *)submit, buf, 64);
	mb();
	drv_usecwait(1000);
	mb();
	i = 0;
	while (*confirm != 0xffffffff && i < 1000) {
		drv_usecwait(1000);
		i++;
	}
	if (*confirm != 0xffffffff) {
		cmn_err(CE_WARN, "%s: handoff failed (%p = 0x%x)",
		    mgp->name, (void *) confirm, *confirm);

		return (ENXIO);
	}
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_GET_RX_RING_SIZE, &cmd);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed MXGEFW_CMD_GET_RX_RING_SIZE\n",
		    mgp->name);
		return (ENXIO);
	}

	mgp->max_intr_slots = 2 * (cmd.data0 / sizeof (mcp_dma_addr_t));
	myri10ge_dummy_rdma(mgp, 1);
	return (0);
}

static int
myri10ge_m_unicst(void *arg, const uint8_t *addr)
{
	struct myri10ge_priv *mgp = arg;
	myri10ge_cmd_t cmd;
	int status;

	cmd.data0 = ((addr[0] << 24) | (addr[1] << 16)
	    | (addr[2] << 8) | addr[3]);

	cmd.data1 = ((addr[4] << 8) | (addr[5]));

	status = myri10ge_send_cmd(mgp, MXGEFW_SET_MAC_ADDRESS, &cmd);
	if (status == 0 && (addr != mgp->mac_addr))
		(void) memcpy(mgp->mac_addr, addr, sizeof (mgp->mac_addr));

	return (status);
}

static int
myri10ge_change_pause(struct myri10ge_priv *mgp, int pause)
{
	myri10ge_cmd_t cmd;
	int status;

	if (pause)
		status = myri10ge_send_cmd(mgp, MXGEFW_ENABLE_FLOW_CONTROL,
		    &cmd);
	else
		status = myri10ge_send_cmd(mgp, MXGEFW_DISABLE_FLOW_CONTROL,
		    &cmd);

	if (status) {
		cmn_err(CE_WARN, "%s: Failed to set flow control mode\n",
		    mgp->name);
		return (ENXIO);
	}
	mgp->pause = pause;
	return (0);
}

static void
myri10ge_change_promisc(struct myri10ge_priv *mgp, int promisc)
{
	myri10ge_cmd_t cmd;
	int status;

	if (promisc)
		status = myri10ge_send_cmd(mgp, MXGEFW_ENABLE_PROMISC, &cmd);
	else
		status = myri10ge_send_cmd(mgp, MXGEFW_DISABLE_PROMISC, &cmd);

	if (status) {
		cmn_err(CE_WARN, "%s: Failed to set promisc mode\n",
		    mgp->name);
	}
}

static int
myri10ge_dma_test(struct myri10ge_priv *mgp, int test_type)
{
	myri10ge_cmd_t cmd;
	int status;
	uint32_t len;
	void *dmabench;
	struct myri10ge_dma_stuff dmabench_dma;
	char *test = " ";

	/*
	 * Run a small DMA test.
	 * The magic multipliers to the length tell the firmware
	 * tp do DMA read, write, or read+write tests.  The
	 * results are returned in cmd.data0.  The upper 16
	 * bits or the return is the number of transfers completed.
	 * The lower 16 bits is the time in 0.5us ticks that the
	 * transfers took to complete
	 */

	len = mgp->tx_boundary;

	dmabench = myri10ge_dma_alloc(mgp->dip, len,
	    &myri10ge_rx_jumbo_dma_attr, &myri10ge_dev_access_attr,
	    DDI_DMA_STREAMING,  DDI_DMA_RDWR|DDI_DMA_STREAMING,
	    &dmabench_dma, 1, DDI_DMA_DONTWAIT);
	mgp->read_dma = mgp->write_dma = mgp->read_write_dma = 0;
	if (dmabench == NULL) {
		cmn_err(CE_WARN, "%s dma benchmark aborted\n", mgp->name);
		return (ENOMEM);
	}

	cmd.data0 = ntohl(dmabench_dma.low);
	cmd.data1 = ntohl(dmabench_dma.high);
	cmd.data2 = len * 0x10000;
	status = myri10ge_send_cmd(mgp, test_type, &cmd);
	if (status != 0) {
		test = "read";
		goto abort;
	}
	mgp->read_dma = ((cmd.data0>>16) * len * 2) / (cmd.data0 & 0xffff);

	cmd.data0 = ntohl(dmabench_dma.low);
	cmd.data1 = ntohl(dmabench_dma.high);
	cmd.data2 = len * 0x1;
	status = myri10ge_send_cmd(mgp, test_type, &cmd);
	if (status != 0) {
		test = "write";
		goto abort;
	}
	mgp->write_dma = ((cmd.data0>>16) * len * 2) / (cmd.data0 & 0xffff);

	cmd.data0 = ntohl(dmabench_dma.low);
	cmd.data1 = ntohl(dmabench_dma.high);
	cmd.data2 = len * 0x10001;
	status = myri10ge_send_cmd(mgp, test_type, &cmd);
	if (status != 0) {
		test = "read/write";
		goto abort;
	}
	mgp->read_write_dma = ((cmd.data0>>16) * len * 2 * 2) /
	    (cmd.data0 & 0xffff);


abort:
	myri10ge_dma_free(&dmabench_dma);
	if (status != 0 && test_type != MXGEFW_CMD_UNALIGNED_TEST)
		cmn_err(CE_WARN, "%s %s dma benchmark failed\n", mgp->name,
		    test);
	return (status);
}

static int
myri10ge_reset(struct myri10ge_priv *mgp)
{
	myri10ge_cmd_t cmd;
	struct myri10ge_nic_stat *ethstat;
	struct myri10ge_slice_state *ss;
	int i, status;
	size_t bytes;

	/* send a reset command to the card to see if it is alive */
	(void) memset(&cmd, 0, sizeof (cmd));
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_RESET, &cmd);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed reset\n", mgp->name);
		return (ENXIO);
	}

	/* Now exchange information about interrupts  */

	bytes = mgp->max_intr_slots * sizeof (*mgp->ss[0].rx_done.entry);
	cmd.data0 = (uint32_t)bytes;
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_INTRQ_SIZE, &cmd);

	/*
	 * Even though we already know how many slices are supported
	 * via myri10ge_probe_slices() MXGEFW_CMD_GET_MAX_RSS_QUEUES
	 * has magic side effects, and must be called after a reset.
	 * It must be called prior to calling any RSS related cmds,
	 * including assigning an interrupt queue for anything but
	 * slice 0.  It must also be called *after*
	 * MXGEFW_CMD_SET_INTRQ_SIZE, since the intrq size is used by
	 * the firmware to compute offsets.
	 */

	if (mgp->num_slices > 1) {

		/* ask the maximum number of slices it supports */
		status = myri10ge_send_cmd(mgp, MXGEFW_CMD_GET_MAX_RSS_QUEUES,
		    &cmd);
		if (status != 0) {
			cmn_err(CE_WARN,
			    "%s: failed to get number of slices\n",
			    mgp->name);
			return (status);
		}

		/*
		 * MXGEFW_CMD_ENABLE_RSS_QUEUES must be called prior
		 * to setting up the interrupt queue DMA
		 */

		cmd.data0 = mgp->num_slices;
		cmd.data1 = MXGEFW_SLICE_INTR_MODE_ONE_PER_SLICE |
		    MXGEFW_SLICE_ENABLE_MULTIPLE_TX_QUEUES;
		status = myri10ge_send_cmd(mgp, MXGEFW_CMD_ENABLE_RSS_QUEUES,
		    &cmd);
		if (status != 0) {
			cmn_err(CE_WARN,
			    "%s: failed to set number of slices\n",
			    mgp->name);
			return (status);
		}
	}
	for (i = 0; i < mgp->num_slices; i++) {
		ss = &mgp->ss[i];
		cmd.data0 = ntohl(ss->rx_done.dma.low);
		cmd.data1 = ntohl(ss->rx_done.dma.high);
		cmd.data2 = i;
		status |= myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_INTRQ_DMA,
		    &cmd);
	};

	status |= myri10ge_send_cmd(mgp,  MXGEFW_CMD_GET_IRQ_ACK_OFFSET, &cmd);
	for (i = 0; i < mgp->num_slices; i++) {
		ss = &mgp->ss[i];
		ss->irq_claim = (volatile unsigned int *)
		    (void *)(mgp->sram + cmd.data0 + 8 * i);
	}

	if (mgp->ddi_intr_type == DDI_INTR_TYPE_FIXED) {
		status |= myri10ge_send_cmd(mgp,
		    MXGEFW_CMD_GET_IRQ_DEASSERT_OFFSET, &cmd);
		mgp->irq_deassert = (uint32_t *)(void *)(mgp->sram + cmd.data0);
	}

	status |= myri10ge_send_cmd(mgp,
	    MXGEFW_CMD_GET_INTR_COAL_DELAY_OFFSET, &cmd);
	mgp->intr_coal_delay_ptr = (uint32_t *)(void *)(mgp->sram + cmd.data0);

	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed set interrupt parameters\n",
		    mgp->name);
		return (status);
	}

	*mgp->intr_coal_delay_ptr = htonl(mgp->intr_coal_delay);
	(void) myri10ge_dma_test(mgp, MXGEFW_DMA_TEST);

	/* reset mcp/driver shared state back to 0 */

	for (i = 0; i < mgp->num_slices; i++) {
		ss = &mgp->ss[i];
		bytes = mgp->max_intr_slots *
		    sizeof (*mgp->ss[0].rx_done.entry);
		(void) memset(ss->rx_done.entry, 0, bytes);
		ss->tx.req = 0;
		ss->tx.done = 0;
		ss->tx.pkt_done = 0;
		ss->rx_big.cnt = 0;
		ss->rx_small.cnt = 0;
		ss->rx_done.idx = 0;
		ss->rx_done.cnt = 0;
		ss->rx_token = 0;
		ss->tx.watchdog_done = 0;
		ss->tx.watchdog_req = 0;
		ss->tx.active = 0;
		ss->tx.activate = 0;
	}
	mgp->watchdog_rx_pause = 0;
	if (mgp->ksp_stat != NULL) {
		ethstat = (struct myri10ge_nic_stat *)mgp->ksp_stat->ks_data;
		ethstat->link_changes.value.ul = 0;
	}
	status = myri10ge_m_unicst(mgp, mgp->mac_addr);
	myri10ge_change_promisc(mgp, 0);
	(void) myri10ge_change_pause(mgp, mgp->pause);
	return (status);
}

static int
myri10ge_init_toeplitz(struct myri10ge_priv *mgp)
{
	myri10ge_cmd_t cmd;
	int i, b, s, t, j;
	int status;
	uint32_t k[8];
	uint32_t tmp;
	uint8_t *key;

	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_GET_RSS_KEY_OFFSET,
	    &cmd);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed to get rss key\n",
		    mgp->name);
		return (EIO);
	}
	myri10ge_pio_copy32(mgp->rss_key,
	    (uint32_t *)(void*)((char *)mgp->sram + cmd.data0),
	    sizeof (mgp->rss_key));

	mgp->toeplitz_hash_table = kmem_alloc(sizeof (uint32_t) * 12 * 256,
	    KM_SLEEP);
	key = (uint8_t *)mgp->rss_key;
	t = 0;
	for (b = 0; b < 12; b++) {
		for (s = 0; s < 8; s++) {
			/* Bits: b*8+s, ..., b*8+s+31 */
			k[s] = 0;
			for (j = 0; j < 32; j++) {
				int bit = b*8+s+j;
				bit = 0x1 & (key[bit / 8] >> (7 -(bit & 0x7)));
				k[s] |= bit << (31 - j);
			}
		}

		for (i = 0; i <= 0xff; i++) {
			tmp = 0;
			if (i & (1 << 7)) { tmp ^= k[0]; }
			if (i & (1 << 6)) { tmp ^= k[1]; }
			if (i & (1 << 5)) { tmp ^= k[2]; }
			if (i & (1 << 4)) { tmp ^= k[3]; }
			if (i & (1 << 3)) { tmp ^= k[4]; }
			if (i & (1 << 2)) { tmp ^= k[5]; }
			if (i & (1 << 1)) { tmp ^= k[6]; }
			if (i & (1 << 0)) { tmp ^= k[7]; }
			mgp->toeplitz_hash_table[t++] = tmp;
		}
	}
	return (0);
}

static inline struct myri10ge_slice_state *
myri10ge_toeplitz_send_hash(struct myri10ge_priv *mgp, struct ip *ip)
{
	struct tcphdr *hdr;
	uint32_t saddr, daddr;
	uint32_t hash, slice;
	uint32_t *table = mgp->toeplitz_hash_table;
	uint16_t src, dst;

	/*
	 * Note hashing order is reversed from how it is done
	 * in the NIC, so as to generate the same hash value
	 * for the connection to try to keep connections CPU local
	 */

	/* hash on IPv4 src/dst address */
	saddr = ntohl(ip->ip_src.s_addr);
	daddr = ntohl(ip->ip_dst.s_addr);
	hash = table[(256 * 0) + ((daddr >> 24) & 0xff)];
	hash ^= table[(256 * 1) + ((daddr >> 16) & 0xff)];
	hash ^= table[(256 * 2) + ((daddr >> 8) & 0xff)];
	hash ^= table[(256 * 3) + ((daddr) & 0xff)];
	hash ^= table[(256 * 4) + ((saddr >> 24) & 0xff)];
	hash ^= table[(256 * 5) + ((saddr >> 16) & 0xff)];
	hash ^= table[(256 * 6) + ((saddr >> 8) & 0xff)];
	hash ^= table[(256 * 7) + ((saddr) & 0xff)];
	/* hash on TCP port, if required */
	if ((myri10ge_rss_hash & MXGEFW_RSS_HASH_TYPE_TCP_IPV4) &&
	    ip->ip_p == IPPROTO_TCP) {
		hdr = (struct tcphdr *)(void *)
		    (((uint8_t *)ip) +  (ip->ip_hl << 2));
		src = ntohs(hdr->th_sport);
		dst = ntohs(hdr->th_dport);

		hash ^= table[(256 * 8) + ((dst >> 8) & 0xff)];
		hash ^= table[(256 * 9) + ((dst) & 0xff)];
		hash ^= table[(256 * 10) + ((src >> 8) & 0xff)];
		hash ^= table[(256 * 11) + ((src) & 0xff)];
	}
	slice = (mgp->num_slices - 1) & hash;
	return (&mgp->ss[slice]);

}

static inline struct myri10ge_slice_state *
myri10ge_simple_send_hash(struct myri10ge_priv *mgp, struct ip *ip)
{
	struct tcphdr *hdr;
	uint32_t slice, hash_val;


	if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) {
		return (&mgp->ss[0]);
	}
	hdr = (struct tcphdr *)(void *)(((uint8_t *)ip) +  (ip->ip_hl << 2));

	/*
	 * Use the second byte of the *destination* address for
	 * MXGEFW_RSS_HASH_TYPE_SRC_PORT, so as to match NIC's hashing
	 */
	hash_val = ntohs(hdr->th_dport) & 0xff;
	if (myri10ge_rss_hash == MXGEFW_RSS_HASH_TYPE_SRC_DST_PORT)
		hash_val += ntohs(hdr->th_sport) & 0xff;

	slice = (mgp->num_slices - 1) & hash_val;
	return (&mgp->ss[slice]);
}

static inline struct myri10ge_slice_state *
myri10ge_send_hash(struct myri10ge_priv *mgp, mblk_t *mp)
{
	unsigned int slice = 0;
	struct ether_header *eh;
	struct ether_vlan_header *vh;
	struct ip *ip;
	int ehl, ihl;

	if (mgp->num_slices == 1)
		return (&mgp->ss[0]);

	if (myri10ge_tx_hash == 0) {
		slice = CPU->cpu_id & (mgp->num_slices - 1);
		return (&mgp->ss[slice]);
	}

	/*
	 *  ensure it is a TCP or UDP over IPv4 packet, and that the
	 *  headers are in the 1st mblk.  Otherwise, punt
	 */
	ehl = sizeof (*eh);
	ihl = sizeof (*ip);
	if ((MBLKL(mp)) <  (ehl + ihl + 8))
		return (&mgp->ss[0]);
	eh = (struct ether_header *)(void *)mp->b_rptr;
	ip = (struct ip *)(void *)(eh + 1);
	if (eh->ether_type != BE_16(ETHERTYPE_IP)) {
		if (eh->ether_type != BE_16(ETHERTYPE_VLAN))
			return (&mgp->ss[0]);
		vh = (struct ether_vlan_header *)(void *)mp->b_rptr;
		if (vh->ether_type != BE_16(ETHERTYPE_IP))
			return (&mgp->ss[0]);
		ehl += 4;
		ip = (struct ip *)(void *)(vh + 1);
	}
	ihl = ip->ip_hl << 2;
	if (MBLKL(mp) <  (ehl + ihl + 8))
		return (&mgp->ss[0]);
	switch (myri10ge_rss_hash) {
	case MXGEFW_RSS_HASH_TYPE_IPV4:
		/* fallthru */
	case MXGEFW_RSS_HASH_TYPE_TCP_IPV4:
		/* fallthru */
	case (MXGEFW_RSS_HASH_TYPE_IPV4|MXGEFW_RSS_HASH_TYPE_TCP_IPV4):
		return (myri10ge_toeplitz_send_hash(mgp, ip));
	case MXGEFW_RSS_HASH_TYPE_SRC_PORT:
		/* fallthru */
	case MXGEFW_RSS_HASH_TYPE_SRC_DST_PORT:
		return (myri10ge_simple_send_hash(mgp, ip));
	default:
		break;
	}
	return (&mgp->ss[0]);
}

static int
myri10ge_setup_slice(struct myri10ge_slice_state *ss)
{
	struct myri10ge_priv *mgp = ss->mgp;
	myri10ge_cmd_t cmd;
	int tx_ring_size, rx_ring_size;
	int tx_ring_entries, rx_ring_entries;
	int slice, status;
	int allocated, idx;
	size_t bytes;

	slice = ss - mgp->ss;
	cmd.data0 = slice;
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_GET_SEND_RING_SIZE, &cmd);
	tx_ring_size = cmd.data0;
	cmd.data0 = slice;
	status |= myri10ge_send_cmd(mgp, MXGEFW_CMD_GET_RX_RING_SIZE, &cmd);
	if (status != 0)
		return (status);
	rx_ring_size = cmd.data0;

	tx_ring_entries = tx_ring_size / sizeof (struct mcp_kreq_ether_send);
	rx_ring_entries = rx_ring_size / sizeof (struct mcp_dma_addr);
	ss->tx.mask = tx_ring_entries - 1;
	ss->rx_small.mask = ss->rx_big.mask = rx_ring_entries - 1;

	/* get the lanai pointers to the send and receive rings */

	cmd.data0 = slice;
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_GET_SEND_OFFSET, &cmd);
	ss->tx.lanai = (mcp_kreq_ether_send_t *)(void *)(mgp->sram + cmd.data0);
	if (mgp->num_slices > 1) {
		ss->tx.go = (char *)mgp->sram + MXGEFW_ETH_SEND_GO + 64 * slice;
		ss->tx.stop = (char *)mgp->sram + MXGEFW_ETH_SEND_STOP +
		    64 * slice;
	} else {
		ss->tx.go = NULL;
		ss->tx.stop = NULL;
	}

	cmd.data0 = slice;
	status |= myri10ge_send_cmd(mgp, MXGEFW_CMD_GET_SMALL_RX_OFFSET, &cmd);
	ss->rx_small.lanai = (mcp_kreq_ether_recv_t *)
	    (void *)(mgp->sram + cmd.data0);

	cmd.data0 = slice;
	status |= myri10ge_send_cmd(mgp, MXGEFW_CMD_GET_BIG_RX_OFFSET, &cmd);
	ss->rx_big.lanai = (mcp_kreq_ether_recv_t *)(void *)
	    (mgp->sram + cmd.data0);

	if (status != 0) {
		cmn_err(CE_WARN,
		    "%s: failed to get ring sizes or locations\n", mgp->name);
		return (status);
	}

	status = ENOMEM;
	bytes = rx_ring_entries * sizeof (*ss->rx_small.shadow);
	ss->rx_small.shadow = kmem_zalloc(bytes, KM_SLEEP);
	if (ss->rx_small.shadow == NULL)
		goto abort;
	(void) memset(ss->rx_small.shadow, 0, bytes);

	bytes = rx_ring_entries * sizeof (*ss->rx_big.shadow);
	ss->rx_big.shadow = kmem_zalloc(bytes, KM_SLEEP);
	if (ss->rx_big.shadow == NULL)
		goto abort_with_rx_small_shadow;
	(void) memset(ss->rx_big.shadow, 0, bytes);

	/* allocate the host info rings */

	bytes = tx_ring_entries * sizeof (*ss->tx.info);
	ss->tx.info = kmem_zalloc(bytes, KM_SLEEP);
	if (ss->tx.info == NULL)
		goto abort_with_rx_big_shadow;
	(void) memset(ss->tx.info, 0, bytes);

	bytes = rx_ring_entries * sizeof (*ss->rx_small.info);
	ss->rx_small.info = kmem_zalloc(bytes, KM_SLEEP);
	if (ss->rx_small.info == NULL)
		goto abort_with_tx_info;
	(void) memset(ss->rx_small.info, 0, bytes);

	bytes = rx_ring_entries * sizeof (*ss->rx_big.info);
	ss->rx_big.info = kmem_zalloc(bytes, KM_SLEEP);
	if (ss->rx_big.info == NULL)
		goto abort_with_rx_small_info;
	(void) memset(ss->rx_big.info, 0, bytes);

	ss->tx.stall = ss->tx.sched = 0;
	ss->tx.stall_early = ss->tx.stall_late = 0;

	ss->jbufs_for_smalls = 1 + (1 + ss->rx_small.mask) /
	    (myri10ge_mtu / (myri10ge_small_bytes + MXGEFW_PAD));

	allocated = myri10ge_add_jbufs(ss,
	    myri10ge_bigbufs_initial + ss->jbufs_for_smalls, 1);
	if (allocated < ss->jbufs_for_smalls + myri10ge_bigbufs_initial) {
		cmn_err(CE_WARN,
		    "%s: Could not allocate enough receive buffers (%d/%d)\n",
		    mgp->name, allocated,
		    myri10ge_bigbufs_initial + ss->jbufs_for_smalls);
		goto abort_with_jumbos;
	}

	myri10ge_carve_up_jbufs_into_small_ring(ss);
	ss->j_rx_cnt = 0;

	mutex_enter(&ss->jpool.mtx);
	if (allocated < rx_ring_entries)
		ss->jpool.low_water = allocated / 4;
	else
		ss->jpool.low_water = rx_ring_entries / 2;

	/*
	 * invalidate the big receive ring in case we do not
	 * allocate sufficient jumbos to fill it
	 */
	(void) memset(ss->rx_big.shadow, 1,
	    (ss->rx_big.mask + 1) * sizeof (ss->rx_big.shadow[0]));
	for (idx = 7; idx <= ss->rx_big.mask; idx += 8) {
		myri10ge_submit_8rx(&ss->rx_big.lanai[idx - 7],
		    &ss->rx_big.shadow[idx - 7]);
		mb();
	}


	myri10ge_restock_jumbos(ss);

	for (idx = 7; idx <= ss->rx_small.mask; idx += 8) {
		myri10ge_submit_8rx(&ss->rx_small.lanai[idx - 7],
		    &ss->rx_small.shadow[idx - 7]);
		mb();
	}
	ss->rx_small.cnt = ss->rx_small.mask + 1;

	mutex_exit(&ss->jpool.mtx);

	status = myri10ge_prepare_tx_ring(ss);

	if (status != 0)
		goto abort_with_small_jbufs;

	cmd.data0 = ntohl(ss->fw_stats_dma.low);
	cmd.data1 = ntohl(ss->fw_stats_dma.high);
	cmd.data2 = sizeof (mcp_irq_data_t);
	cmd.data2 |= (slice << 16);
	bzero(ss->fw_stats, sizeof (*ss->fw_stats));
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_STATS_DMA_V2, &cmd);
	if (status == ENOSYS) {
		cmd.data0 = ntohl(ss->fw_stats_dma.low) +
		    offsetof(mcp_irq_data_t, send_done_count);
		cmd.data1 = ntohl(ss->fw_stats_dma.high);
		status = myri10ge_send_cmd(mgp,
		    MXGEFW_CMD_SET_STATS_DMA_OBSOLETE, &cmd);
	}
	if (status) {
		cmn_err(CE_WARN, "%s: Couldn't set stats DMA\n", mgp->name);
		goto abort_with_tx;
	}

	return (0);

abort_with_tx:
	myri10ge_unprepare_tx_ring(ss);

abort_with_small_jbufs:
	myri10ge_release_small_jbufs(ss);

abort_with_jumbos:
	if (allocated != 0) {
		mutex_enter(&ss->jpool.mtx);
		ss->jpool.low_water = 0;
		mutex_exit(&ss->jpool.mtx);
		myri10ge_unstock_jumbos(ss);
		myri10ge_remove_jbufs(ss);
	}

	bytes = rx_ring_entries * sizeof (*ss->rx_big.info);
	kmem_free(ss->rx_big.info, bytes);

abort_with_rx_small_info:
	bytes = rx_ring_entries * sizeof (*ss->rx_small.info);
	kmem_free(ss->rx_small.info, bytes);

abort_with_tx_info:
	bytes = tx_ring_entries * sizeof (*ss->tx.info);
	kmem_free(ss->tx.info, bytes);

abort_with_rx_big_shadow:
	bytes = rx_ring_entries * sizeof (*ss->rx_big.shadow);
	kmem_free(ss->rx_big.shadow, bytes);

abort_with_rx_small_shadow:
	bytes = rx_ring_entries * sizeof (*ss->rx_small.shadow);
	kmem_free(ss->rx_small.shadow, bytes);
abort:
	return (status);

}

static void
myri10ge_teardown_slice(struct myri10ge_slice_state *ss)
{
	int tx_ring_entries, rx_ring_entries;
	size_t bytes;

	/* ignore slices that have not been fully setup */
	if (ss->tx.cp == NULL)
		return;
	/* Free the TX copy buffers */
	myri10ge_unprepare_tx_ring(ss);

	/* stop passing returned buffers to firmware */

	mutex_enter(&ss->jpool.mtx);
	ss->jpool.low_water = 0;
	mutex_exit(&ss->jpool.mtx);
	myri10ge_release_small_jbufs(ss);

	/* Release the free jumbo frame pool */
	myri10ge_unstock_jumbos(ss);
	myri10ge_remove_jbufs(ss);

	rx_ring_entries = ss->rx_big.mask + 1;
	tx_ring_entries = ss->tx.mask + 1;

	bytes = rx_ring_entries * sizeof (*ss->rx_big.info);
	kmem_free(ss->rx_big.info, bytes);

	bytes = rx_ring_entries * sizeof (*ss->rx_small.info);
	kmem_free(ss->rx_small.info, bytes);

	bytes = tx_ring_entries * sizeof (*ss->tx.info);
	kmem_free(ss->tx.info, bytes);

	bytes = rx_ring_entries * sizeof (*ss->rx_big.shadow);
	kmem_free(ss->rx_big.shadow, bytes);

	bytes = rx_ring_entries * sizeof (*ss->rx_small.shadow);
	kmem_free(ss->rx_small.shadow, bytes);

}
static int
myri10ge_start_locked(struct myri10ge_priv *mgp)
{
	myri10ge_cmd_t cmd;
	int status, big_pow2, i;
	volatile uint8_t *itable;

	status = DDI_SUCCESS;
	/* Allocate DMA resources and receive buffers */

	status = myri10ge_reset(mgp);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed reset\n", mgp->name);
		return (DDI_FAILURE);
	}

	if (mgp->num_slices > 1) {
		cmd.data0 = mgp->num_slices;
		cmd.data1 = 1; /* use MSI-X */
		status = myri10ge_send_cmd(mgp, MXGEFW_CMD_ENABLE_RSS_QUEUES,
		    &cmd);
		if (status != 0) {
			cmn_err(CE_WARN,
			    "%s: failed to set number of slices\n",
			    mgp->name);
			goto abort_with_nothing;
		}
		/* setup the indirection table */
		cmd.data0 = mgp->num_slices;
		status = myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_RSS_TABLE_SIZE,
		    &cmd);

		status |= myri10ge_send_cmd(mgp,
		    MXGEFW_CMD_GET_RSS_TABLE_OFFSET, &cmd);
		if (status != 0) {
			cmn_err(CE_WARN,
			    "%s: failed to setup rss tables\n", mgp->name);
		}

		/* just enable an identity mapping */
		itable = mgp->sram + cmd.data0;
		for (i = 0; i < mgp->num_slices; i++)
			itable[i] = (uint8_t)i;

		if (myri10ge_rss_hash & MYRI10GE_TOEPLITZ_HASH) {
			status = myri10ge_init_toeplitz(mgp);
			if (status != 0) {
				cmn_err(CE_WARN, "%s: failed to setup "
				    "toeplitz tx hash table", mgp->name);
				goto abort_with_nothing;
			}
		}
		cmd.data0 = 1;
		cmd.data1 = myri10ge_rss_hash;
		status = myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_RSS_ENABLE,
		    &cmd);
		if (status != 0) {
			cmn_err(CE_WARN,
			    "%s: failed to enable slices\n", mgp->name);
			goto abort_with_toeplitz;
		}
	}

	for (i = 0; i < mgp->num_slices; i++) {
		status = myri10ge_setup_slice(&mgp->ss[i]);
		if (status != 0)
			goto abort_with_slices;
	}

	/*
	 * Tell the MCP how many buffers it has, and to
	 *  bring the ethernet interface up
	 *
	 * Firmware needs the big buff size as a power of 2.  Lie and
	 * tell it the buffer is larger, because we only use 1
	 * buffer/pkt, and the mtu will prevent overruns
	 */
	big_pow2 = myri10ge_mtu + MXGEFW_PAD;
	while (!ISP2(big_pow2))
		big_pow2++;

	/* now give firmware buffers sizes, and MTU */
	cmd.data0 = myri10ge_mtu;
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_MTU, &cmd);
	cmd.data0 = myri10ge_small_bytes;
	status |=
	    myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_SMALL_BUFFER_SIZE, &cmd);
	cmd.data0 = big_pow2;
	status |= myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_BIG_BUFFER_SIZE, &cmd);
	if (status) {
		cmn_err(CE_WARN, "%s: Couldn't set buffer sizes\n", mgp->name);
		goto abort_with_slices;
	}


	cmd.data0 = 1;
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_TSO_MODE, &cmd);
	if (status) {
		cmn_err(CE_WARN, "%s: unable to setup TSO (%d)\n",
		    mgp->name, status);
	} else {
		mgp->features |= MYRI10GE_TSO;
	}

	mgp->link_state = -1;
	mgp->rdma_tags_available = 15;
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_ETHERNET_UP, &cmd);
	if (status) {
		cmn_err(CE_WARN, "%s: unable to start ethernet\n", mgp->name);
		goto abort_with_slices;
	}
	mgp->running = MYRI10GE_ETH_RUNNING;
	return (DDI_SUCCESS);

abort_with_slices:
	for (i = 0; i < mgp->num_slices; i++)
		myri10ge_teardown_slice(&mgp->ss[i]);

	mgp->running = MYRI10GE_ETH_STOPPED;

abort_with_toeplitz:
	if (mgp->toeplitz_hash_table != NULL) {
		kmem_free(mgp->toeplitz_hash_table,
		    sizeof (uint32_t) * 12 * 256);
		mgp->toeplitz_hash_table = NULL;
	}

abort_with_nothing:
	return (DDI_FAILURE);
}

static void
myri10ge_stop_locked(struct myri10ge_priv *mgp)
{
	int status, old_down_cnt;
	myri10ge_cmd_t cmd;
	int wait_time = 10;
	int i, polling;

	old_down_cnt = mgp->down_cnt;
	mb();
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_ETHERNET_DOWN, &cmd);
	if (status) {
		cmn_err(CE_WARN, "%s: Couldn't bring down link\n", mgp->name);
	}

	while (old_down_cnt == *((volatile int *)&mgp->down_cnt)) {
		delay(1 * drv_usectohz(1000000));
		wait_time--;
		if (wait_time == 0)
			break;
	}
again:
	if (old_down_cnt == *((volatile int *)&mgp->down_cnt)) {
		cmn_err(CE_WARN, "%s: didn't get down irq\n", mgp->name);
		for (i = 0; i < mgp->num_slices; i++) {
			/*
			 * take and release the rx lock to ensure
			 * that no interrupt thread is blocked
			 * elsewhere in the stack, preventing
			 * completion
			 */

			mutex_enter(&mgp->ss[i].rx_lock);
			printf("%s: slice %d rx irq idle\n",
			    mgp->name, i);
			mutex_exit(&mgp->ss[i].rx_lock);

			/* verify that the poll handler is inactive */
			mutex_enter(&mgp->ss->poll_lock);
			polling = mgp->ss->rx_polling;
			mutex_exit(&mgp->ss->poll_lock);
			if (polling) {
				printf("%s: slice %d is polling\n",
				    mgp->name, i);
				delay(1 * drv_usectohz(1000000));
				goto again;
			}
		}
		delay(1 * drv_usectohz(1000000));
		if (old_down_cnt == *((volatile int *)&mgp->down_cnt)) {
			cmn_err(CE_WARN, "%s: Never got down irq\n", mgp->name);
		}
	}

	for (i = 0; i < mgp->num_slices; i++)
		myri10ge_teardown_slice(&mgp->ss[i]);

	if (mgp->toeplitz_hash_table != NULL) {
		kmem_free(mgp->toeplitz_hash_table,
		    sizeof (uint32_t) * 12 * 256);
		mgp->toeplitz_hash_table = NULL;
	}
	mgp->running = MYRI10GE_ETH_STOPPED;
}

static int
myri10ge_m_start(void *arg)
{
	struct myri10ge_priv *mgp = arg;
	int status;

	mutex_enter(&mgp->intrlock);

	if (mgp->running != MYRI10GE_ETH_STOPPED) {
		mutex_exit(&mgp->intrlock);
		return (DDI_FAILURE);
	}
	status = myri10ge_start_locked(mgp);
	mutex_exit(&mgp->intrlock);

	if (status != DDI_SUCCESS)
		return (status);

	/* start the watchdog timer */
	mgp->timer_id = timeout(myri10ge_watchdog, mgp,
	    mgp->timer_ticks);
	return (DDI_SUCCESS);

}

static void
myri10ge_m_stop(void *arg)
{
	struct myri10ge_priv *mgp = arg;

	mutex_enter(&mgp->intrlock);
	/* if the device not running give up */
	if (mgp->running != MYRI10GE_ETH_RUNNING) {
		mutex_exit(&mgp->intrlock);
		return;
	}

	mgp->running = MYRI10GE_ETH_STOPPING;
	mutex_exit(&mgp->intrlock);
	(void) untimeout(mgp->timer_id);
	mutex_enter(&mgp->intrlock);
	myri10ge_stop_locked(mgp);
	mutex_exit(&mgp->intrlock);

}

static inline void
myri10ge_rx_csum(mblk_t *mp, struct myri10ge_rx_ring_stats *s, uint32_t csum)
{
	struct ether_header *eh;
	struct ip *ip;
	struct ip6_hdr *ip6;
	uint32_t start, stuff, end, partial, hdrlen;


	csum = ntohs((uint16_t)csum);
	eh = (struct ether_header *)(void *)mp->b_rptr;
	hdrlen = sizeof (*eh);
	if (eh->ether_dhost.ether_addr_octet[0] & 1) {
		if (0 == (bcmp(eh->ether_dhost.ether_addr_octet,
		    myri10ge_broadcastaddr, sizeof (eh->ether_dhost))))
			s->brdcstrcv++;
		else
			s->multircv++;
	}

	if (eh->ether_type == BE_16(ETHERTYPE_VLAN)) {
		/*
		 * fix checksum by subtracting 4 bytes after what the
		 * firmware thought was the end of the ether hdr
		 */
		partial = *(uint32_t *)
		    (void *)(mp->b_rptr + ETHERNET_HEADER_SIZE);
		csum += ~partial;
		csum +=  (csum < ~partial);
		csum = (csum >> 16) + (csum & 0xFFFF);
		csum = (csum >> 16) + (csum & 0xFFFF);
		hdrlen += VLAN_TAGSZ;
	}

	if (eh->ether_type ==  BE_16(ETHERTYPE_IP)) {
		ip = (struct ip *)(void *)(mp->b_rptr + hdrlen);
		start = ip->ip_hl << 2;

		if (ip->ip_p == IPPROTO_TCP)
			stuff = start + offsetof(struct tcphdr, th_sum);
		else if (ip->ip_p == IPPROTO_UDP)
			stuff = start + offsetof(struct udphdr, uh_sum);
		else
			return;
		end = ntohs(ip->ip_len);
	} else if (eh->ether_type ==  BE_16(ETHERTYPE_IPV6)) {
		ip6 = (struct ip6_hdr *)(void *)(mp->b_rptr + hdrlen);
		start = sizeof (*ip6);
		if (ip6->ip6_nxt == IPPROTO_TCP) {
			stuff = start + offsetof(struct tcphdr, th_sum);
		} else if (ip6->ip6_nxt == IPPROTO_UDP)
			stuff = start + offsetof(struct udphdr, uh_sum);
		else
			return;
		end = start + ntohs(ip6->ip6_plen);
		/*
		 * IPv6 headers do not contain a checksum, and hence
		 * do not checksum to zero, so they don't "fall out"
		 * of the partial checksum calculation like IPv4
		 * headers do.  We need to fix the partial checksum by
		 * subtracting the checksum of the IPv6 header.
		 */

		partial = myri10ge_csum_generic((uint16_t *)ip6, sizeof (*ip6));
		csum += ~partial;
		csum +=  (csum < ~partial);
		csum = (csum >> 16) + (csum & 0xFFFF);
		csum = (csum >> 16) + (csum & 0xFFFF);
	} else {
		return;
	}

	if (MBLKL(mp) > hdrlen + end) {
		/* padded frame, so hw csum may be invalid */
		return;
	}

	mac_hcksum_set(mp, start, stuff, end, csum, HCK_PARTIALCKSUM);
}

static mblk_t *
myri10ge_rx_done_small(struct myri10ge_slice_state *ss, uint32_t len,
    uint32_t csum)
{
	mblk_t *mp;
	myri10ge_rx_ring_t *rx;
	int idx;

	rx = &ss->rx_small;
	idx = rx->cnt & rx->mask;
	ss->rx_small.cnt++;

	/* allocate a new buffer to pass up the stack */
	mp = allocb(len + MXGEFW_PAD, 0);
	if (mp == NULL) {
		MYRI10GE_ATOMIC_SLICE_STAT_INC(rx_small_nobuf);
		goto abort;
	}
	bcopy(ss->rx_small.info[idx].ptr,
	    (caddr_t)mp->b_wptr, len + MXGEFW_PAD);
	mp->b_wptr += len + MXGEFW_PAD;
	mp->b_rptr += MXGEFW_PAD;

	ss->rx_stats.ibytes += len;
	ss->rx_stats.ipackets += 1;
	myri10ge_rx_csum(mp, &ss->rx_stats, csum);

abort:
	if ((idx & 7) == 7) {
		myri10ge_submit_8rx(&rx->lanai[idx - 7],
		    &rx->shadow[idx - 7]);
	}

	return (mp);
}


static mblk_t *
myri10ge_rx_done_big(struct myri10ge_slice_state *ss, uint32_t len,
    uint32_t csum)
{
	struct myri10ge_jpool_stuff *jpool;
	struct myri10ge_jpool_entry *j;
	mblk_t *mp;
	int idx, num_owned_by_mcp;

	jpool = &ss->jpool;
	idx = ss->j_rx_cnt & ss->rx_big.mask;
	j = ss->rx_big.info[idx].j;

	if (j == NULL) {
		printf("%s: null j at idx=%d, rx_big.cnt = %d, j_rx_cnt=%d\n",
		    ss->mgp->name, idx, ss->rx_big.cnt, ss->j_rx_cnt);
		return (NULL);
	}


	ss->rx_big.info[idx].j = NULL;
	ss->j_rx_cnt++;


	/*
	 * Check to see if we are low on rx buffers.
	 * Note that we must leave at least 8 free so there are
	 * enough to free in a single 64-byte write.
	 */
	num_owned_by_mcp = ss->rx_big.cnt - ss->j_rx_cnt;
	if (num_owned_by_mcp < jpool->low_water) {
		mutex_enter(&jpool->mtx);
		myri10ge_restock_jumbos(ss);
		mutex_exit(&jpool->mtx);
		num_owned_by_mcp = ss->rx_big.cnt - ss->j_rx_cnt;
		/* if we are still low, then we have to copy */
		if (num_owned_by_mcp < 16) {
			MYRI10GE_ATOMIC_SLICE_STAT_INC(rx_copy);
			/* allocate a new buffer to pass up the stack */
			mp = allocb(len + MXGEFW_PAD, 0);
			if (mp == NULL) {
				goto abort;
			}
			bcopy(j->buf,
			    (caddr_t)mp->b_wptr, len + MXGEFW_PAD);
			myri10ge_jfree_rtn(j);
			/* push buffer back to NIC */
			mutex_enter(&jpool->mtx);
			myri10ge_restock_jumbos(ss);
			mutex_exit(&jpool->mtx);
			goto set_len;
		}
	}

	/* loan our buffer to the stack */
	mp = desballoc((unsigned char *)j->buf, myri10ge_mtu, 0, &j->free_func);
	if (mp == NULL) {
		goto abort;
	}

set_len:
	mp->b_rptr += MXGEFW_PAD;
	mp->b_wptr = ((unsigned char *) mp->b_rptr + len);

	ss->rx_stats.ibytes += len;
	ss->rx_stats.ipackets += 1;
	myri10ge_rx_csum(mp, &ss->rx_stats, csum);

	return (mp);

abort:
	myri10ge_jfree_rtn(j);
	MYRI10GE_ATOMIC_SLICE_STAT_INC(rx_big_nobuf);
	return (NULL);
}

/*
 * Free all transmit buffers up until the specified index
 */
static inline void
myri10ge_tx_done(struct myri10ge_slice_state *ss, uint32_t mcp_index)
{
	myri10ge_tx_ring_t *tx;
	struct myri10ge_tx_dma_handle_head handles;
	int idx;
	int limit = 0;

	tx = &ss->tx;
	handles.head = NULL;
	handles.tail = NULL;
	while (tx->pkt_done != (int)mcp_index) {
		idx = tx->done & tx->mask;

		/*
		 * mblk & DMA handle attached only to first slot
		 * per buffer in the packet
		 */

		if (tx->info[idx].m) {
			(void) ddi_dma_unbind_handle(tx->info[idx].handle->h);
			tx->info[idx].handle->next = handles.head;
			handles.head = tx->info[idx].handle;
			if (handles.tail == NULL)
				handles.tail = tx->info[idx].handle;
			freeb(tx->info[idx].m);
			tx->info[idx].m = 0;
			tx->info[idx].handle = 0;
		}
		if (tx->info[idx].ostat.opackets != 0) {
			tx->stats.multixmt += tx->info[idx].ostat.multixmt;
			tx->stats.brdcstxmt += tx->info[idx].ostat.brdcstxmt;
			tx->stats.obytes += tx->info[idx].ostat.obytes;
			tx->stats.opackets += tx->info[idx].ostat.opackets;
			tx->info[idx].stat.un.all = 0;
			tx->pkt_done++;
		}

		tx->done++;
		/*
		 * if we stalled the queue, wake it.  But Wait until
		 * we have at least 1/2 our slots free.
		 */
		if ((tx->req - tx->done) < (tx->mask >> 1) &&
		    tx->stall != tx->sched) {
			mutex_enter(&ss->tx.lock);
			tx->sched = tx->stall;
			mutex_exit(&ss->tx.lock);
			mac_tx_ring_update(ss->mgp->mh, tx->rh);
		}

		/* limit potential for livelock */
		if (unlikely(++limit >  2 * tx->mask))
			break;
	}
	if (tx->req == tx->done && tx->stop != NULL) {
		/*
		 * Nic has sent all pending requests, allow it
		 * to stop polling this queue
		 */
		mutex_enter(&tx->lock);
		if (tx->req == tx->done && tx->active) {
			*(int *)(void *)tx->stop = 1;
			tx->active = 0;
			mb();
		}
		mutex_exit(&tx->lock);
	}
	if (handles.head != NULL)
		myri10ge_free_tx_handles(tx, &handles);
}

static void
myri10ge_mbl_init(struct myri10ge_mblk_list *mbl)
{
	mbl->head = NULL;
	mbl->tail = &mbl->head;
	mbl->cnt = 0;
}

/*ARGSUSED*/
void
myri10ge_mbl_append(struct myri10ge_slice_state *ss,
    struct myri10ge_mblk_list *mbl, mblk_t *mp)
{
	*(mbl->tail) = mp;
	mbl->tail = &mp->b_next;
	mp->b_next = NULL;
	mbl->cnt++;
}


static inline void
myri10ge_clean_rx_done(struct myri10ge_slice_state *ss,
    struct myri10ge_mblk_list *mbl, int limit, boolean_t *stop)
{
	myri10ge_rx_done_t *rx_done = &ss->rx_done;
	struct myri10ge_priv *mgp = ss->mgp;
	mblk_t *mp;
	struct lro_entry *lro;
	uint16_t length;
	uint16_t checksum;


	while (rx_done->entry[rx_done->idx].length != 0) {
		if (unlikely (*stop)) {
			break;
		}
		length = ntohs(rx_done->entry[rx_done->idx].length);
		length &= (~MXGEFW_RSS_HASH_MASK);

		/* limit potential for livelock */
		limit -= length;
		if (unlikely(limit < 0))
			break;

		rx_done->entry[rx_done->idx].length = 0;
		checksum = ntohs(rx_done->entry[rx_done->idx].checksum);
		if (length <= myri10ge_small_bytes)
			mp = myri10ge_rx_done_small(ss, length, checksum);
		else
			mp = myri10ge_rx_done_big(ss, length, checksum);
		if (mp != NULL) {
			if (!myri10ge_lro ||
			    0 != myri10ge_lro_rx(ss, mp, checksum, mbl))
				myri10ge_mbl_append(ss, mbl, mp);
		}
		rx_done->cnt++;
		rx_done->idx = rx_done->cnt & (mgp->max_intr_slots - 1);
	}
	while (ss->lro_active != NULL) {
		lro = ss->lro_active;
		ss->lro_active = lro->next;
		myri10ge_lro_flush(ss, lro, mbl);
	}
}

static void
myri10ge_intr_rx(struct myri10ge_slice_state *ss)
{
	uint64_t gen;
	struct myri10ge_mblk_list mbl;

	myri10ge_mbl_init(&mbl);
	if (mutex_tryenter(&ss->rx_lock) == 0)
		return;
	gen = ss->rx_gen_num;
	myri10ge_clean_rx_done(ss, &mbl, MYRI10GE_POLL_NULL,
	    &ss->rx_polling);
	if (mbl.head != NULL)
		mac_rx_ring(ss->mgp->mh, ss->rx_rh, mbl.head, gen);
	mutex_exit(&ss->rx_lock);

}

static mblk_t *
myri10ge_poll_rx(void *arg, int bytes)
{
	struct myri10ge_slice_state *ss = arg;
	struct myri10ge_mblk_list mbl;
	boolean_t dummy = B_FALSE;

	if (bytes == 0)
		return (NULL);

	myri10ge_mbl_init(&mbl);
	mutex_enter(&ss->rx_lock);
	if (ss->rx_polling)
		myri10ge_clean_rx_done(ss, &mbl, bytes, &dummy);
	else
		printf("%d: poll_rx: token=%d, polling=%d\n", (int)(ss -
		    ss->mgp->ss), ss->rx_token, ss->rx_polling);
	mutex_exit(&ss->rx_lock);
	return (mbl.head);
}

/*ARGSUSED*/
static uint_t
myri10ge_intr(caddr_t arg0, caddr_t arg1)
{
	struct myri10ge_slice_state *ss =
	    (struct myri10ge_slice_state *)(void *)arg0;
	struct myri10ge_priv *mgp = ss->mgp;
	mcp_irq_data_t *stats = ss->fw_stats;
	myri10ge_tx_ring_t *tx = &ss->tx;
	uint32_t send_done_count;
	uint8_t valid;


	/* make sure the DMA has finished */
	if (!stats->valid) {
		return (DDI_INTR_UNCLAIMED);
	}
	valid = stats->valid;

	/* low bit indicates receives are present */
	if (valid & 1)
		myri10ge_intr_rx(ss);

	if (mgp->ddi_intr_type == DDI_INTR_TYPE_FIXED) {
		/* lower legacy IRQ  */
		*mgp->irq_deassert = 0;
		if (!myri10ge_deassert_wait)
			/* don't wait for conf. that irq is low */
			stats->valid = 0;
		mb();
	} else {
		/* no need to wait for conf. that irq is low */
		stats->valid = 0;
	}

	do {
		/* check for transmit completes and receives */
		send_done_count = ntohl(stats->send_done_count);
		if (send_done_count != tx->pkt_done)
			myri10ge_tx_done(ss, (int)send_done_count);
	} while (*((volatile uint8_t *) &stats->valid));

	if (stats->stats_updated) {
		if (mgp->link_state != stats->link_up || stats->link_down) {
			mgp->link_state = stats->link_up;
			if (stats->link_down) {
				mgp->down_cnt += stats->link_down;
				mgp->link_state = 0;
			}
			if (mgp->link_state) {
				if (myri10ge_verbose)
					printf("%s: link up\n", mgp->name);
				mac_link_update(mgp->mh, LINK_STATE_UP);
			} else {
				if (myri10ge_verbose)
					printf("%s: link down\n", mgp->name);
				mac_link_update(mgp->mh, LINK_STATE_DOWN);
			}
			MYRI10GE_NIC_STAT_INC(link_changes);
		}
		if (mgp->rdma_tags_available !=
		    ntohl(ss->fw_stats->rdma_tags_available)) {
			mgp->rdma_tags_available =
			    ntohl(ss->fw_stats->rdma_tags_available);
			cmn_err(CE_NOTE, "%s: RDMA timed out! "
			    "%d tags left\n", mgp->name,
			    mgp->rdma_tags_available);
		}
	}

	mb();
	/* check to see if we have rx token to pass back */
	if (valid & 0x1) {
		mutex_enter(&ss->poll_lock);
		if (ss->rx_polling) {
			ss->rx_token = 1;
		} else {
			*ss->irq_claim = BE_32(3);
			ss->rx_token = 0;
		}
		mutex_exit(&ss->poll_lock);
	}
	*(ss->irq_claim + 1) = BE_32(3);
	return (DDI_INTR_CLAIMED);
}

/*
 * Add or remove a multicast address.  This is called with our
 * macinfo's lock held by GLD, so we do not need to worry about
 * our own locking here.
 */
static int
myri10ge_m_multicst(void *arg, boolean_t add, const uint8_t *multicastaddr)
{
	myri10ge_cmd_t cmd;
	struct myri10ge_priv *mgp = arg;
	int status, join_leave;

	if (add)
		join_leave = MXGEFW_JOIN_MULTICAST_GROUP;
	else
		join_leave = MXGEFW_LEAVE_MULTICAST_GROUP;
	(void) memcpy(&cmd.data0, multicastaddr, 4);
	(void) memcpy(&cmd.data1, multicastaddr + 4, 2);
	cmd.data0 = htonl(cmd.data0);
	cmd.data1 = htonl(cmd.data1);
	status = myri10ge_send_cmd(mgp, join_leave, &cmd);
	if (status == 0)
		return (0);

	cmn_err(CE_WARN, "%s: failed to set multicast address\n",
	    mgp->name);
	return (status);
}


static int
myri10ge_m_promisc(void *arg, boolean_t on)
{
	struct myri10ge_priv *mgp = arg;

	myri10ge_change_promisc(mgp, on);
	return (0);
}

/*
 * copy an array of mcp_kreq_ether_send_t's to the mcp.  Copy
 *  backwards one at a time and handle ring wraps
 */

static inline void
myri10ge_submit_req_backwards(myri10ge_tx_ring_t *tx,
    mcp_kreq_ether_send_t *src, int cnt)
{
	int idx, starting_slot;
	starting_slot = tx->req;
	while (cnt > 1) {
		cnt--;
		idx = (starting_slot + cnt) & tx->mask;
		myri10ge_pio_copy(&tx->lanai[idx],
		    &src[cnt], sizeof (*src));
		mb();
	}
}

/*
 * copy an array of mcp_kreq_ether_send_t's to the mcp.  Copy
 * at most 32 bytes at a time, so as to avoid involving the software
 * pio handler in the nic.   We re-write the first segment's flags
 * to mark them valid only after writing the entire chain
 */

static inline void
myri10ge_submit_req(myri10ge_tx_ring_t *tx, mcp_kreq_ether_send_t *src,
    int cnt)
{
	int idx, i;
	uint32_t *src_ints, *dst_ints;
	mcp_kreq_ether_send_t *srcp, *dstp, *dst;
	uint8_t last_flags;

	idx = tx->req & tx->mask;

	last_flags = src->flags;
	src->flags = 0;
	mb();
	dst = dstp = &tx->lanai[idx];
	srcp = src;

	if ((idx + cnt) < tx->mask) {
		for (i = 0; i < (cnt - 1); i += 2) {
			myri10ge_pio_copy(dstp, srcp, 2 * sizeof (*src));
			mb(); /* force write every 32 bytes */
			srcp += 2;
			dstp += 2;
		}
	} else {
		/*
		 * submit all but the first request, and ensure
		 *  that it is submitted below
		 */
		myri10ge_submit_req_backwards(tx, src, cnt);
		i = 0;
	}
	if (i < cnt) {
		/* submit the first request */
		myri10ge_pio_copy(dstp, srcp, sizeof (*src));
		mb(); /* barrier before setting valid flag */
	}

	/* re-write the last 32-bits with the valid flags */
	src->flags |= last_flags;
	src_ints = (uint32_t *)src;
	src_ints += 3;
	dst_ints = (uint32_t *)dst;
	dst_ints += 3;
	*dst_ints =  *src_ints;
	tx->req += cnt;
	mb();
	/* notify NIC to poll this tx ring */
	if (!tx->active && tx->go != NULL) {
		*(int *)(void *)tx->go = 1;
		tx->active = 1;
		tx->activate++;
		mb();
	}
}

/* ARGSUSED */
static inline void
myri10ge_lso_info_get(mblk_t *mp, uint32_t *mss, uint32_t *flags)
{
	uint32_t lso_flag;
	mac_lso_get(mp, mss, &lso_flag);
	(*flags) |= lso_flag;
}


/* like pullupmsg, except preserve hcksum/LSO attributes */
static int
myri10ge_pullup(struct myri10ge_slice_state *ss, mblk_t *mp)
{
	uint32_t start, stuff, tx_offload_flags, mss;
	int ok;

	mss = 0;
	mac_hcksum_get(mp, &start, &stuff, NULL, NULL, &tx_offload_flags);
	myri10ge_lso_info_get(mp, &mss, &tx_offload_flags);

	ok = pullupmsg(mp, -1);
	if (!ok) {
		printf("pullupmsg failed");
		return (DDI_FAILURE);
	}
	MYRI10GE_ATOMIC_SLICE_STAT_INC(xmit_pullup);
	mac_hcksum_set(mp, start, stuff, NULL, NULL, tx_offload_flags);
	if (tx_offload_flags & HW_LSO)
		DB_LSOMSS(mp) = (uint16_t)mss;
	lso_info_set(mp, mss, tx_offload_flags);
	return (DDI_SUCCESS);
}

static inline void
myri10ge_tx_stat(struct myri10ge_tx_pkt_stats *s, struct ether_header *eh,
    int opackets, int obytes)
{
	s->un.all = 0;
	if (eh->ether_dhost.ether_addr_octet[0] & 1) {
		if (0 == (bcmp(eh->ether_dhost.ether_addr_octet,
		    myri10ge_broadcastaddr, sizeof (eh->ether_dhost))))
			s->un.s.brdcstxmt = 1;
		else
			s->un.s.multixmt = 1;
	}
	s->un.s.opackets = (uint16_t)opackets;
	s->un.s.obytes = obytes;
}

static int
myri10ge_tx_copy(struct myri10ge_slice_state *ss, mblk_t *mp,
    mcp_kreq_ether_send_t *req)
{
	myri10ge_tx_ring_t *tx = &ss->tx;
	caddr_t ptr;
	struct myri10ge_tx_copybuf *cp;
	mblk_t *bp;
	int idx, mblen, avail;
	uint16_t len;

	mutex_enter(&tx->lock);
	avail = tx->mask - (tx->req - tx->done);
	if (avail <= 1) {
		mutex_exit(&tx->lock);
		return (EBUSY);
	}
	idx = tx->req & tx->mask;
	cp = &tx->cp[idx];
	ptr = cp->va;
	for (len = 0, bp = mp; bp != NULL; bp = bp->b_cont) {
		mblen = MBLKL(bp);
		bcopy(bp->b_rptr, ptr, mblen);
		ptr += mblen;
		len += mblen;
	}
	/* ensure runts are padded to 60 bytes */
	if (len < 60) {
		bzero(ptr, 64 - len);
		len = 60;
	}
	req->addr_low = cp->dma.low;
	req->addr_high = cp->dma.high;
	req->length = htons(len);
	req->pad = 0;
	req->rdma_count = 1;
	myri10ge_tx_stat(&tx->info[idx].stat,
	    (struct ether_header *)(void *)cp->va, 1, len);
	(void) ddi_dma_sync(cp->dma.handle, 0, len, DDI_DMA_SYNC_FORDEV);
	myri10ge_submit_req(&ss->tx, req, 1);
	mutex_exit(&tx->lock);
	freemsg(mp);
	return (DDI_SUCCESS);
}


static void
myri10ge_send_locked(myri10ge_tx_ring_t *tx, mcp_kreq_ether_send_t *req_list,
    struct myri10ge_tx_buffer_state *tx_info,
    int count)
{
	int i, idx;

	idx = 0; /* gcc -Wuninitialized */
	/* store unmapping and bp info for tx irq handler */
	for (i = 0; i < count; i++) {
		idx = (tx->req + i) & tx->mask;
		tx->info[idx].m = tx_info[i].m;
		tx->info[idx].handle = tx_info[i].handle;
	}
	tx->info[idx].stat.un.all = tx_info[0].stat.un.all;

	/* submit the frame to the nic */
	myri10ge_submit_req(tx, req_list, count);


}



static void
myri10ge_copydata(mblk_t *mp, int off, int len, caddr_t buf)
{
	mblk_t *bp;
	int seglen;
	uint_t count;

	bp = mp;

	while (off > 0) {
		seglen = MBLKL(bp);
		if (off < seglen)
			break;
		off -= seglen;
		bp = bp->b_cont;
	}
	while (len > 0) {
		seglen = MBLKL(bp);
		count = min(seglen - off, len);
		bcopy(bp->b_rptr + off, buf, count);
		len -= count;
		buf += count;
		off = 0;
		bp = bp->b_cont;
	}
}

static int
myri10ge_ether_parse_header(mblk_t *mp)
{
	struct ether_header eh_copy;
	struct ether_header *eh;
	int eth_hdr_len, seglen;

	seglen = MBLKL(mp);
	eth_hdr_len = sizeof (*eh);
	if (seglen < eth_hdr_len) {
		myri10ge_copydata(mp, 0, eth_hdr_len, (caddr_t)&eh_copy);
		eh = &eh_copy;
	} else {
		eh = (struct ether_header *)(void *)mp->b_rptr;
	}
	if (eh->ether_type == BE_16(ETHERTYPE_VLAN)) {
		eth_hdr_len += 4;
	}

	return (eth_hdr_len);
}

static int
myri10ge_lso_parse_header(mblk_t *mp, int off)
{
	char buf[128];
	int seglen, sum_off;
	struct ip *ip;
	struct tcphdr *tcp;

	seglen = MBLKL(mp);
	if (seglen < off + sizeof (*ip)) {
		myri10ge_copydata(mp, off, sizeof (*ip), buf);
		ip = (struct ip *)(void *)buf;
	} else {
		ip = (struct ip *)(void *)(mp->b_rptr + off);
	}
	if (seglen < off + (ip->ip_hl << 2) + sizeof (*tcp)) {
		myri10ge_copydata(mp, off,
		    (ip->ip_hl << 2) + sizeof (*tcp), buf);
		ip = (struct ip *)(void *)buf;
	}
	tcp = (struct tcphdr *)(void *)((char *)ip + (ip->ip_hl << 2));

	/*
	 * NIC expects ip_sum to be zero.  Recent changes to
	 * OpenSolaris leave the correct ip checksum there, rather
	 * than the required zero, so we need to zero it.  Otherwise,
	 * the NIC will produce bad checksums when sending LSO packets.
	 */
	if (ip->ip_sum != 0) {
		if (((char *)ip) != buf) {
			/* ip points into mblk, so just zero it */
			ip->ip_sum = 0;
		} else {
			/*
			 * ip points into a copy, so walk the chain
			 * to find the ip_csum, then zero it
			 */
			sum_off = off + _PTRDIFF(&ip->ip_sum, buf);
			while (sum_off > (int)(MBLKL(mp) - 1)) {
				sum_off -= MBLKL(mp);
				mp = mp->b_cont;
			}
			mp->b_rptr[sum_off] = 0;
			sum_off++;
			while (sum_off > MBLKL(mp) - 1) {
				sum_off -= MBLKL(mp);
				mp = mp->b_cont;
			}
			mp->b_rptr[sum_off] = 0;
		}
	}
	return (off + ((ip->ip_hl + tcp->th_off) << 2));
}

static int
myri10ge_tx_tso_copy(struct myri10ge_slice_state *ss, mblk_t *mp,
    mcp_kreq_ether_send_t *req_list, int hdr_size, int pkt_size,
    uint16_t mss, uint8_t cksum_offset)
{
	myri10ge_tx_ring_t *tx = &ss->tx;
	struct myri10ge_priv *mgp = ss->mgp;
	mblk_t *bp;
	mcp_kreq_ether_send_t *req;
	struct myri10ge_tx_copybuf *cp;
	caddr_t rptr, ptr;
	int mblen, count, cum_len, mss_resid, tx_req, pkt_size_tmp;
	int resid, avail, idx, hdr_size_tmp, tx_boundary;
	int rdma_count;
	uint32_t seglen, len, boundary, low, high_swapped;
	uint16_t pseudo_hdr_offset = htons(mss);
	uint8_t flags;

	tx_boundary = mgp->tx_boundary;
	hdr_size_tmp = hdr_size;
	resid = tx_boundary;
	count = 1;
	mutex_enter(&tx->lock);

	/* check to see if the slots are really there */
	avail = tx->mask - (tx->req - tx->done);
	if (unlikely(avail <=  MYRI10GE_MAX_SEND_DESC_TSO)) {
		atomic_inc_32(&tx->stall);
		mutex_exit(&tx->lock);
		return (EBUSY);
	}

	/* copy */
	cum_len = -hdr_size;
	count = 0;
	req = req_list;
	idx = tx->mask & tx->req;
	cp = &tx->cp[idx];
	low = ntohl(cp->dma.low);
	ptr = cp->va;
	cp->len = 0;
	if (mss) {
		int payload = pkt_size - hdr_size;
		uint16_t opackets = (payload / mss) + ((payload % mss) != 0);
		tx->info[idx].ostat.opackets = opackets;
		tx->info[idx].ostat.obytes = (opackets - 1) * hdr_size
		    + pkt_size;
	}
	hdr_size_tmp = hdr_size;
	mss_resid = mss;
	flags = (MXGEFW_FLAGS_TSO_HDR | MXGEFW_FLAGS_FIRST);
	tx_req = tx->req;
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblen = MBLKL(bp);
		rptr = (caddr_t)bp->b_rptr;
		len = min(hdr_size_tmp, mblen);
		if (len) {
			bcopy(rptr, ptr, len);
			rptr += len;
			ptr += len;
			resid -= len;
			mblen -= len;
			hdr_size_tmp -= len;
			cp->len += len;
			if (hdr_size_tmp)
				continue;
			if (resid < mss) {
				tx_req++;
				idx = tx->mask & tx_req;
				cp = &tx->cp[idx];
				low = ntohl(cp->dma.low);
				ptr = cp->va;
				resid = tx_boundary;
			}
		}
		while (mblen) {
			len = min(mss_resid, mblen);
			bcopy(rptr, ptr, len);
			mss_resid -= len;
			resid -= len;
			mblen -= len;
			rptr += len;
			ptr += len;
			cp->len += len;
			if (mss_resid == 0) {
				mss_resid = mss;
				if (resid < mss) {
					tx_req++;
					idx = tx->mask & tx_req;
					cp = &tx->cp[idx];
					cp->len = 0;
					low = ntohl(cp->dma.low);
					ptr = cp->va;
					resid = tx_boundary;
				}
			}
		}
	}

	req = req_list;
	pkt_size_tmp = pkt_size;
	count = 0;
	rdma_count = 0;
	tx_req = tx->req;
	while (pkt_size_tmp) {
		idx = tx->mask & tx_req;
		cp = &tx->cp[idx];
		high_swapped = cp->dma.high;
		low = ntohl(cp->dma.low);
		len = cp->len;
		if (len == 0) {
			printf("len=0! pkt_size_tmp=%d, pkt_size=%d\n",
			    pkt_size_tmp, pkt_size);
			for (bp = mp; bp != NULL; bp = bp->b_cont) {
				mblen = MBLKL(bp);
				printf("mblen:%d\n", mblen);
			}
			pkt_size_tmp = pkt_size;
			tx_req = tx->req;
			while (pkt_size_tmp > 0) {
				idx = tx->mask & tx_req;
				cp = &tx->cp[idx];
				printf("cp->len = %d\n", cp->len);
				pkt_size_tmp -= cp->len;
				tx_req++;
			}
			printf("dropped\n");
			MYRI10GE_ATOMIC_SLICE_STAT_INC(xmit_err);
			goto done;
		}
		pkt_size_tmp -= len;
		while (len) {
			while (len) {
				uint8_t flags_next;
				int cum_len_next;

				boundary = (low + mgp->tx_boundary) &
				    ~(mgp->tx_boundary - 1);
				seglen = boundary - low;
				if (seglen > len)
					seglen = len;

				flags_next = flags & ~MXGEFW_FLAGS_FIRST;
				cum_len_next = cum_len + seglen;
				(req-rdma_count)->rdma_count = rdma_count + 1;
				if (likely(cum_len >= 0)) {
					/* payload */
					int next_is_first, chop;

					chop = (cum_len_next > mss);
					cum_len_next = cum_len_next % mss;
					next_is_first = (cum_len_next == 0);
					flags |= chop *
					    MXGEFW_FLAGS_TSO_CHOP;
					flags_next |= next_is_first *
					    MXGEFW_FLAGS_FIRST;
					rdma_count |= -(chop | next_is_first);
					rdma_count += chop & !next_is_first;
				} else if (likely(cum_len_next >= 0)) {
					/* header ends */
					int small;

					rdma_count = -1;
					cum_len_next = 0;
					seglen = -cum_len;
					small = (mss <= MXGEFW_SEND_SMALL_SIZE);
					flags_next = MXGEFW_FLAGS_TSO_PLD |
					    MXGEFW_FLAGS_FIRST |
					    (small * MXGEFW_FLAGS_SMALL);
				}
				req->addr_high = high_swapped;
				req->addr_low = htonl(low);
				req->pseudo_hdr_offset = pseudo_hdr_offset;
				req->pad = 0; /* complete solid 16-byte block */
				req->rdma_count = 1;
				req->cksum_offset = cksum_offset;
				req->length = htons(seglen);
				req->flags = flags | ((cum_len & 1) *
				    MXGEFW_FLAGS_ALIGN_ODD);
				if (cksum_offset > seglen)
					cksum_offset -= seglen;
				else
					cksum_offset = 0;
				low += seglen;
				len -= seglen;
				cum_len = cum_len_next;
				req++;
				req->flags = 0;
				flags = flags_next;
				count++;
				rdma_count++;
			}
		}
		tx_req++;
	}
	(req-rdma_count)->rdma_count = (uint8_t)rdma_count;
	do {
		req--;
		req->flags |= MXGEFW_FLAGS_TSO_LAST;
	} while (!(req->flags & (MXGEFW_FLAGS_TSO_CHOP |
	    MXGEFW_FLAGS_FIRST)));

	myri10ge_submit_req(tx, req_list, count);
done:
	mutex_exit(&tx->lock);
	freemsg(mp);
	return (DDI_SUCCESS);
}

/*
 * Try to send the chain of buffers described by the mp.  We must not
 * encapsulate more than eth->tx.req - eth->tx.done, or
 * MXGEFW_MAX_SEND_DESC, whichever is more.
 */

static int
myri10ge_send(struct myri10ge_slice_state *ss, mblk_t *mp,
    mcp_kreq_ether_send_t *req_list, struct myri10ge_tx_buffer_state *tx_info)
{
	struct myri10ge_priv *mgp = ss->mgp;
	myri10ge_tx_ring_t *tx = &ss->tx;
	mcp_kreq_ether_send_t *req;
	struct myri10ge_tx_dma_handle *handles, *dma_handle = NULL;
	mblk_t  *bp;
	ddi_dma_cookie_t cookie;
	int err, rv, count, avail, mblen, try_pullup, i, max_segs, maclen,
	    rdma_count, cum_len, lso_hdr_size;
	uint32_t start, stuff, tx_offload_flags;
	uint32_t seglen, len, mss, boundary, low, high_swapped;
	uint_t ncookies;
	uint16_t pseudo_hdr_offset;
	uint8_t flags, cksum_offset, odd_flag;
	int pkt_size;
	int lso_copy = myri10ge_lso_copy;
	try_pullup = 1;

again:
	/* Setup checksum offloading, if needed */
	mac_hcksum_get(mp, &start, &stuff, NULL, NULL, &tx_offload_flags);
	myri10ge_lso_info_get(mp, &mss, &tx_offload_flags);
	if (tx_offload_flags & HW_LSO) {
		max_segs = MYRI10GE_MAX_SEND_DESC_TSO;
		if ((tx_offload_flags & HCK_PARTIALCKSUM) == 0) {
			MYRI10GE_ATOMIC_SLICE_STAT_INC(xmit_lsobadflags);
			freemsg(mp);
			return (DDI_SUCCESS);
		}
	} else {
		max_segs = MXGEFW_MAX_SEND_DESC;
		mss = 0;
	}
	req = req_list;
	cksum_offset = 0;
	pseudo_hdr_offset = 0;

	/* leave an extra slot keep the ring from wrapping */
	avail = tx->mask - (tx->req - tx->done);

	/*
	 * If we have > MXGEFW_MAX_SEND_DESC, then any over-length
	 * message will need to be pulled up in order to fit.
	 * Otherwise, we are low on transmit descriptors, it is
	 * probably better to stall and try again rather than pullup a
	 * message to fit.
	 */

	if (avail < max_segs) {
		err = EBUSY;
		atomic_inc_32(&tx->stall_early);
		goto stall;
	}

	/* find out how long the frame is and how many segments it is */
	count = 0;
	odd_flag = 0;
	pkt_size = 0;
	flags = (MXGEFW_FLAGS_NO_TSO | MXGEFW_FLAGS_FIRST);
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		dblk_t *dbp;
		mblen = MBLKL(bp);
		if (mblen == 0) {
			/*
			 * we can't simply skip over 0-length mblks
			 * because the hardware can't deal with them,
			 * and we could leak them.
			 */
			MYRI10GE_ATOMIC_SLICE_STAT_INC(xmit_zero_len);
			err = EIO;
			goto pullup;
		}
		/*
		 * There's no advantage to copying most gesballoc
		 * attached blocks, so disable lso copy in that case
		 */
		if (mss && lso_copy == 1 && ((dbp = bp->b_datap) != NULL)) {
			if ((void *)dbp->db_lastfree != myri10ge_db_lastfree) {
				lso_copy = 0;
			}
		}
		pkt_size += mblen;
		count++;
	}

	/* Try to pull up excessivly long chains */
	if (count >= max_segs) {
		err = myri10ge_pullup(ss, mp);
		if (likely(err == DDI_SUCCESS)) {
			count = 1;
		} else {
			if (count <  MYRI10GE_MAX_SEND_DESC_TSO) {
				/*
				 * just let the h/w send it, it will be
				 * inefficient, but us better than dropping
				 */
				max_segs = MYRI10GE_MAX_SEND_DESC_TSO;
			} else {
				/* drop it */
				MYRI10GE_ATOMIC_SLICE_STAT_INC(xmit_err);
				freemsg(mp);
				return (0);
			}
		}
	}

	cum_len = 0;
	maclen = myri10ge_ether_parse_header(mp);

	if (tx_offload_flags & HCK_PARTIALCKSUM) {

		cksum_offset = start + maclen;
		pseudo_hdr_offset = htons(stuff + maclen);
		odd_flag = MXGEFW_FLAGS_ALIGN_ODD;
		flags |= MXGEFW_FLAGS_CKSUM;
	}

	lso_hdr_size = 0; /* -Wunitinialized */
	if (mss) { /* LSO */
		/* this removes any CKSUM flag from before */
		flags = (MXGEFW_FLAGS_TSO_HDR | MXGEFW_FLAGS_FIRST);
		/*
		 * parse the headers and set cum_len to a negative
		 * value to reflect the offset of the TCP payload
		 */
		lso_hdr_size =  myri10ge_lso_parse_header(mp, maclen);
		cum_len = -lso_hdr_size;
		if ((mss < mgp->tx_boundary) && lso_copy) {
			err = myri10ge_tx_tso_copy(ss, mp, req_list,
			    lso_hdr_size, pkt_size, mss, cksum_offset);
			return (err);
		}

		/*
		 * for TSO, pseudo_hdr_offset holds mss.  The firmware
		 * figures out where to put the checksum by parsing
		 * the header.
		 */

		pseudo_hdr_offset = htons(mss);
	} else if (pkt_size <= MXGEFW_SEND_SMALL_SIZE) {
		flags |= MXGEFW_FLAGS_SMALL;
		if (pkt_size < myri10ge_tx_copylen) {
			req->cksum_offset = cksum_offset;
			req->pseudo_hdr_offset = pseudo_hdr_offset;
			req->flags = flags;
			err = myri10ge_tx_copy(ss, mp, req);
			return (err);
		}
		cum_len = 0;
	}

	/* pull one DMA handle for each bp from our freelist */
	handles = NULL;
	err = myri10ge_alloc_tx_handles(ss, count, &handles);
	if (err != DDI_SUCCESS) {
		err = DDI_FAILURE;
		goto stall;
	}
	count = 0;
	rdma_count = 0;
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblen = MBLKL(bp);
		dma_handle = handles;
		handles = handles->next;

		rv = ddi_dma_addr_bind_handle(dma_handle->h, NULL,
		    (caddr_t)bp->b_rptr, mblen,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
		    &cookie, &ncookies);
		if (unlikely(rv != DDI_DMA_MAPPED)) {
			err = EIO;
			try_pullup = 0;
			dma_handle->next = handles;
			handles = dma_handle;
			goto abort_with_handles;
		}

		/* reserve the slot */
		tx_info[count].m = bp;
		tx_info[count].handle = dma_handle;

		for (; ; ) {
			low = MYRI10GE_LOWPART_TO_U32(cookie.dmac_laddress);
			high_swapped =
			    htonl(MYRI10GE_HIGHPART_TO_U32(
			    cookie.dmac_laddress));
			len = (uint32_t)cookie.dmac_size;
			while (len) {
				uint8_t flags_next;
				int cum_len_next;

				boundary = (low + mgp->tx_boundary) &
				    ~(mgp->tx_boundary - 1);
				seglen = boundary - low;
				if (seglen > len)
					seglen = len;

				flags_next = flags & ~MXGEFW_FLAGS_FIRST;
				cum_len_next = cum_len + seglen;
				if (mss) {
					(req-rdma_count)->rdma_count =
					    rdma_count + 1;
					if (likely(cum_len >= 0)) {
						/* payload */
						int next_is_first, chop;

						chop = (cum_len_next > mss);
						cum_len_next =
						    cum_len_next % mss;
						next_is_first =
						    (cum_len_next == 0);
						flags |= chop *
						    MXGEFW_FLAGS_TSO_CHOP;
						flags_next |= next_is_first *
						    MXGEFW_FLAGS_FIRST;
						rdma_count |=
						    -(chop | next_is_first);
						rdma_count +=
						    chop & !next_is_first;
					} else if (likely(cum_len_next >= 0)) {
						/* header ends */
						int small;

						rdma_count = -1;
						cum_len_next = 0;
						seglen = -cum_len;
						small = (mss <=
						    MXGEFW_SEND_SMALL_SIZE);
						flags_next =
						    MXGEFW_FLAGS_TSO_PLD
						    | MXGEFW_FLAGS_FIRST
						    | (small *
						    MXGEFW_FLAGS_SMALL);
					}
				}
				req->addr_high = high_swapped;
				req->addr_low = htonl(low);
				req->pseudo_hdr_offset = pseudo_hdr_offset;
				req->pad = 0; /* complete solid 16-byte block */
				req->rdma_count = 1;
				req->cksum_offset = cksum_offset;
				req->length = htons(seglen);
				req->flags = flags | ((cum_len & 1) * odd_flag);
				if (cksum_offset > seglen)
					cksum_offset -= seglen;
				else
					cksum_offset = 0;
				low += seglen;
				len -= seglen;
				cum_len = cum_len_next;
				count++;
				rdma_count++;
				/*  make sure all the segments will fit */
				if (unlikely(count >= max_segs)) {
					MYRI10GE_ATOMIC_SLICE_STAT_INC(
					    xmit_lowbuf);
					/* may try a pullup */
					err = EBUSY;
					if (try_pullup)
						try_pullup = 2;
					goto abort_with_handles;
				}
				req++;
				req->flags = 0;
				flags = flags_next;
				tx_info[count].m = 0;
			}
			ncookies--;
			if (ncookies == 0)
				break;
			ddi_dma_nextcookie(dma_handle->h, &cookie);
		}
	}
	(req-rdma_count)->rdma_count = (uint8_t)rdma_count;

	if (mss) {
		do {
			req--;
			req->flags |= MXGEFW_FLAGS_TSO_LAST;
		} while (!(req->flags & (MXGEFW_FLAGS_TSO_CHOP |
		    MXGEFW_FLAGS_FIRST)));
	}

	/* calculate tx stats */
	if (mss) {
		uint16_t opackets;
		int payload;

		payload = pkt_size - lso_hdr_size;
		opackets = (payload / mss) + ((payload % mss) != 0);
		tx_info[0].stat.un.all = 0;
		tx_info[0].ostat.opackets = opackets;
		tx_info[0].ostat.obytes = (opackets - 1) * lso_hdr_size
		    + pkt_size;
	} else {
		myri10ge_tx_stat(&tx_info[0].stat,
		    (struct ether_header *)(void *)mp->b_rptr, 1, pkt_size);
	}
	mutex_enter(&tx->lock);

	/* check to see if the slots are really there */
	avail = tx->mask - (tx->req - tx->done);
	if (unlikely(avail <= count)) {
		mutex_exit(&tx->lock);
		err = 0;
		goto late_stall;
	}

	myri10ge_send_locked(tx, req_list, tx_info, count);
	mutex_exit(&tx->lock);
	return (DDI_SUCCESS);

late_stall:
	try_pullup = 0;
	atomic_inc_32(&tx->stall_late);

abort_with_handles:
	/* unbind and free handles from previous mblks */
	for (i = 0; i < count; i++) {
		bp = tx_info[i].m;
		tx_info[i].m = 0;
		if (bp) {
			dma_handle = tx_info[i].handle;
			(void) ddi_dma_unbind_handle(dma_handle->h);
			dma_handle->next = handles;
			handles = dma_handle;
			tx_info[i].handle = NULL;
			tx_info[i].m = NULL;
		}
	}
	myri10ge_free_tx_handle_slist(tx, handles);
pullup:
	if (try_pullup) {
		err = myri10ge_pullup(ss, mp);
		if (err != DDI_SUCCESS && try_pullup == 2) {
			/* drop */
			MYRI10GE_ATOMIC_SLICE_STAT_INC(xmit_err);
			freemsg(mp);
			return (0);
		}
		try_pullup = 0;
		goto again;
	}

stall:
	if (err != 0) {
		if (err == EBUSY) {
			atomic_inc_32(&tx->stall);
		} else {
			MYRI10GE_ATOMIC_SLICE_STAT_INC(xmit_err);
		}
	}
	return (err);
}

static mblk_t *
myri10ge_send_wrapper(void *arg, mblk_t *mp)
{
	struct myri10ge_slice_state *ss = arg;
	int err = 0;
	mcp_kreq_ether_send_t *req_list;
#if defined(__i386)
	/*
	 * We need about 2.5KB of scratch space to handle transmits.
	 * i86pc has only 8KB of kernel stack space, so we malloc the
	 * scratch space there rather than keeping it on the stack.
	 */
	size_t req_size, tx_info_size;
	struct myri10ge_tx_buffer_state *tx_info;
	caddr_t req_bytes;

	req_size = sizeof (*req_list) * (MYRI10GE_MAX_SEND_DESC_TSO + 4)
	    + 8;
	req_bytes = kmem_alloc(req_size, KM_SLEEP);
	tx_info_size = sizeof (*tx_info) * (MYRI10GE_MAX_SEND_DESC_TSO + 1);
	tx_info = kmem_alloc(tx_info_size, KM_SLEEP);
#else
	char req_bytes[sizeof (*req_list) * (MYRI10GE_MAX_SEND_DESC_TSO + 4)
	    + 8];
	struct myri10ge_tx_buffer_state tx_info[MYRI10GE_MAX_SEND_DESC_TSO + 1];
#endif

	/* ensure req_list entries are aligned to 8 bytes */
	req_list = (struct mcp_kreq_ether_send *)
	    (((unsigned long)req_bytes + 7UL) & ~7UL);

	err = myri10ge_send(ss, mp, req_list, tx_info);

#if defined(__i386)
	kmem_free(tx_info, tx_info_size);
	kmem_free(req_bytes, req_size);
#endif
	if (err)
		return (mp);
	else
		return (NULL);
}

static int
myri10ge_addmac(void *arg, const uint8_t *mac_addr)
{
	struct myri10ge_priv *mgp = arg;
	int err;

	if (mac_addr == NULL)
		return (EINVAL);

	mutex_enter(&mgp->intrlock);
	if (mgp->macaddr_cnt) {
		mutex_exit(&mgp->intrlock);
		return (ENOSPC);
	}
	err = myri10ge_m_unicst(mgp, mac_addr);
	if (!err)
		mgp->macaddr_cnt++;

	mutex_exit(&mgp->intrlock);
	if (err)
		return (err);

	bcopy(mac_addr, mgp->mac_addr, sizeof (mgp->mac_addr));
	return (0);
}

/*ARGSUSED*/
static int
myri10ge_remmac(void *arg, const uint8_t *mac_addr)
{
	struct myri10ge_priv *mgp = arg;

	mutex_enter(&mgp->intrlock);
	mgp->macaddr_cnt--;
	mutex_exit(&mgp->intrlock);

	return (0);
}

/*ARGSUSED*/
static void
myri10ge_fill_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	struct myri10ge_priv *mgp = arg;

	if (rtype != MAC_RING_TYPE_RX)
		return;

	infop->mgi_driver = (mac_group_driver_t)mgp;
	infop->mgi_start = NULL;
	infop->mgi_stop = NULL;
	infop->mgi_addmac = myri10ge_addmac;
	infop->mgi_remmac = myri10ge_remmac;
	infop->mgi_count = mgp->num_slices;
}

static int
myri10ge_ring_start(mac_ring_driver_t rh, uint64_t mr_gen_num)
{
	struct myri10ge_slice_state *ss;

	ss = (struct myri10ge_slice_state *)rh;
	mutex_enter(&ss->rx_lock);
	ss->rx_gen_num = mr_gen_num;
	mutex_exit(&ss->rx_lock);
	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
myri10ge_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	struct myri10ge_slice_state *ss;

	ss = (struct myri10ge_slice_state *)rh;
	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = ss->rx_stats.ibytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = ss->rx_stats.ipackets;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular tx ring
 */
int
myri10ge_tx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	struct myri10ge_slice_state *ss;

	ss = (struct myri10ge_slice_state *)rh;
	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = ss->tx.stats.obytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = ss->tx.stats.opackets;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

static int
myri10ge_rx_ring_intr_disable(mac_intr_handle_t intrh)
{
	struct myri10ge_slice_state *ss;

	ss = (struct myri10ge_slice_state *)intrh;
	mutex_enter(&ss->poll_lock);
	ss->rx_polling = B_TRUE;
	mutex_exit(&ss->poll_lock);
	return (0);
}

static int
myri10ge_rx_ring_intr_enable(mac_intr_handle_t intrh)
{
	struct myri10ge_slice_state *ss;

	ss = (struct myri10ge_slice_state *)intrh;
	mutex_enter(&ss->poll_lock);
	ss->rx_polling = B_FALSE;
	if (ss->rx_token) {
		*ss->irq_claim = BE_32(3);
		ss->rx_token = 0;
	}
	mutex_exit(&ss->poll_lock);
	return (0);
}

/*ARGSUSED*/
static void
myri10ge_fill_ring(void *arg, mac_ring_type_t rtype, const int rg_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	struct myri10ge_priv *mgp = arg;
	struct myri10ge_slice_state *ss;
	mac_intr_t *mintr = &infop->mri_intr;

	ASSERT((unsigned int)ring_index < mgp->num_slices);

	ss = &mgp->ss[ring_index];
	switch (rtype) {
	case MAC_RING_TYPE_RX:
		ss->rx_rh = rh;
		infop->mri_driver = (mac_ring_driver_t)ss;
		infop->mri_start = myri10ge_ring_start;
		infop->mri_stop = NULL;
		infop->mri_poll = myri10ge_poll_rx;
		infop->mri_stat = myri10ge_rx_ring_stat;
		mintr->mi_handle = (mac_intr_handle_t)ss;
		mintr->mi_enable = myri10ge_rx_ring_intr_enable;
		mintr->mi_disable = myri10ge_rx_ring_intr_disable;
		break;
	case MAC_RING_TYPE_TX:
		ss->tx.rh = rh;
		infop->mri_driver = (mac_ring_driver_t)ss;
		infop->mri_start = NULL;
		infop->mri_stop = NULL;
		infop->mri_tx = myri10ge_send_wrapper;
		infop->mri_stat = myri10ge_tx_ring_stat;
		break;
	default:
		break;
	}
}

static void
myri10ge_nic_stat_destroy(struct myri10ge_priv *mgp)
{
	if (mgp->ksp_stat == NULL)
		return;

	kstat_delete(mgp->ksp_stat);
	mgp->ksp_stat = NULL;
}

static void
myri10ge_slice_stat_destroy(struct myri10ge_slice_state *ss)
{
	if (ss->ksp_stat == NULL)
		return;

	kstat_delete(ss->ksp_stat);
	ss->ksp_stat = NULL;
}

static void
myri10ge_info_destroy(struct myri10ge_priv *mgp)
{
	if (mgp->ksp_info == NULL)
		return;

	kstat_delete(mgp->ksp_info);
	mgp->ksp_info = NULL;
}

static int
myri10ge_nic_stat_kstat_update(kstat_t *ksp, int rw)
{
	struct myri10ge_nic_stat *ethstat;
	struct myri10ge_priv *mgp;
	mcp_irq_data_t *fw_stats;


	if (rw == KSTAT_WRITE)
		return (EACCES);

	ethstat = (struct myri10ge_nic_stat *)ksp->ks_data;
	mgp = (struct myri10ge_priv *)ksp->ks_private;
	fw_stats = mgp->ss[0].fw_stats;

	ethstat->dma_read_bw_MBs.value.ul = mgp->read_dma;
	ethstat->dma_write_bw_MBs.value.ul = mgp->write_dma;
	ethstat->dma_read_write_bw_MBs.value.ul = mgp->read_write_dma;
	if (myri10ge_tx_dma_attr.dma_attr_flags & DDI_DMA_FORCE_PHYSICAL)
		ethstat->dma_force_physical.value.ul = 1;
	else
		ethstat->dma_force_physical.value.ul = 0;
	ethstat->lanes.value.ul = mgp->pcie_link_width;
	ethstat->dropped_bad_crc32.value.ul =
	    ntohl(fw_stats->dropped_bad_crc32);
	ethstat->dropped_bad_phy.value.ul =
	    ntohl(fw_stats->dropped_bad_phy);
	ethstat->dropped_link_error_or_filtered.value.ul =
	    ntohl(fw_stats->dropped_link_error_or_filtered);
	ethstat->dropped_link_overflow.value.ul =
	    ntohl(fw_stats->dropped_link_overflow);
	ethstat->dropped_multicast_filtered.value.ul =
	    ntohl(fw_stats->dropped_multicast_filtered);
	ethstat->dropped_no_big_buffer.value.ul =
	    ntohl(fw_stats->dropped_no_big_buffer);
	ethstat->dropped_no_small_buffer.value.ul =
	    ntohl(fw_stats->dropped_no_small_buffer);
	ethstat->dropped_overrun.value.ul =
	    ntohl(fw_stats->dropped_overrun);
	ethstat->dropped_pause.value.ul =
	    ntohl(fw_stats->dropped_pause);
	ethstat->dropped_runt.value.ul =
	    ntohl(fw_stats->dropped_runt);
	ethstat->link_up.value.ul =
	    ntohl(fw_stats->link_up);
	ethstat->dropped_unicast_filtered.value.ul =
	    ntohl(fw_stats->dropped_unicast_filtered);
	return (0);
}

static int
myri10ge_slice_stat_kstat_update(kstat_t *ksp, int rw)
{
	struct myri10ge_slice_stat *ethstat;
	struct myri10ge_slice_state *ss;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ethstat = (struct myri10ge_slice_stat *)ksp->ks_data;
	ss = (struct myri10ge_slice_state *)ksp->ks_private;

	ethstat->rx_big.value.ul = ss->j_rx_cnt;
	ethstat->rx_bigbuf_firmware.value.ul = ss->rx_big.cnt - ss->j_rx_cnt;
	ethstat->rx_bigbuf_pool.value.ul =
	    ss->jpool.num_alloc - ss->jbufs_for_smalls;
	ethstat->rx_bigbuf_smalls.value.ul = ss->jbufs_for_smalls;
	ethstat->rx_small.value.ul = ss->rx_small.cnt -
	    (ss->rx_small.mask + 1);
	ethstat->tx_done.value.ul = ss->tx.done;
	ethstat->tx_req.value.ul = ss->tx.req;
	ethstat->tx_activate.value.ul = ss->tx.activate;
	ethstat->xmit_sched.value.ul = ss->tx.sched;
	ethstat->xmit_stall.value.ul = ss->tx.stall;
	ethstat->xmit_stall_early.value.ul = ss->tx.stall_early;
	ethstat->xmit_stall_late.value.ul = ss->tx.stall_late;
	ethstat->xmit_err.value.ul =  MYRI10GE_SLICE_STAT(xmit_err);
	return (0);
}

static int
myri10ge_info_kstat_update(kstat_t *ksp, int rw)
{
	struct myri10ge_info *info;
	struct myri10ge_priv *mgp;


	if (rw == KSTAT_WRITE)
		return (EACCES);

	info = (struct myri10ge_info *)ksp->ks_data;
	mgp = (struct myri10ge_priv *)ksp->ks_private;
	kstat_named_setstr(&info->driver_version, MYRI10GE_VERSION_STR);
	kstat_named_setstr(&info->firmware_version, mgp->fw_version);
	kstat_named_setstr(&info->firmware_name, mgp->fw_name);
	kstat_named_setstr(&info->interrupt_type, mgp->intr_type);
	kstat_named_setstr(&info->product_code, mgp->pc_str);
	kstat_named_setstr(&info->serial_number, mgp->sn_str);
	return (0);
}

static struct myri10ge_info myri10ge_info_template = {
	{ "driver_version",	KSTAT_DATA_STRING },
	{ "firmware_version",	KSTAT_DATA_STRING },
	{ "firmware_name",	KSTAT_DATA_STRING },
	{ "interrupt_type",	KSTAT_DATA_STRING },
	{ "product_code",	KSTAT_DATA_STRING },
	{ "serial_number",	KSTAT_DATA_STRING },
};
static kmutex_t myri10ge_info_template_lock;


static int
myri10ge_info_init(struct myri10ge_priv *mgp)
{
	struct kstat *ksp;

	ksp = kstat_create("myri10ge", ddi_get_instance(mgp->dip),
	    "myri10ge_info", "net", KSTAT_TYPE_NAMED,
	    sizeof (myri10ge_info_template) /
	    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (ksp == NULL) {
		cmn_err(CE_WARN,
		    "%s: myri10ge_info_init: kstat_create failed", mgp->name);
		return (DDI_FAILURE);
	}
	mgp->ksp_info = ksp;
	ksp->ks_update = myri10ge_info_kstat_update;
	ksp->ks_private = (void *) mgp;
	ksp->ks_data = &myri10ge_info_template;
	ksp->ks_lock = &myri10ge_info_template_lock;
	if (MYRI10GE_VERSION_STR != NULL)
		ksp->ks_data_size += strlen(MYRI10GE_VERSION_STR) + 1;
	if (mgp->fw_version != NULL)
		ksp->ks_data_size += strlen(mgp->fw_version) + 1;
	ksp->ks_data_size += strlen(mgp->fw_name) + 1;
	ksp->ks_data_size += strlen(mgp->intr_type) + 1;
	if (mgp->pc_str != NULL)
		ksp->ks_data_size += strlen(mgp->pc_str) + 1;
	if (mgp->sn_str != NULL)
		ksp->ks_data_size += strlen(mgp->sn_str) + 1;

	kstat_install(ksp);
	return (DDI_SUCCESS);
}


static int
myri10ge_nic_stat_init(struct myri10ge_priv *mgp)
{
	struct kstat *ksp;
	struct myri10ge_nic_stat *ethstat;

	ksp = kstat_create("myri10ge", ddi_get_instance(mgp->dip),
	    "myri10ge_nic_stats", "net", KSTAT_TYPE_NAMED,
	    sizeof (*ethstat) / sizeof (kstat_named_t), 0);
	if (ksp == NULL) {
		cmn_err(CE_WARN,
		    "%s: myri10ge_stat_init: kstat_create failed", mgp->name);
		return (DDI_FAILURE);
	}
	mgp->ksp_stat = ksp;
	ethstat = (struct myri10ge_nic_stat *)(ksp->ks_data);

	kstat_named_init(&ethstat->dma_read_bw_MBs,
	    "dma_read_bw_MBs", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dma_write_bw_MBs,
	    "dma_write_bw_MBs", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dma_read_write_bw_MBs,
	    "dma_read_write_bw_MBs", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dma_force_physical,
	    "dma_force_physical", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->lanes,
	    "lanes", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_bad_crc32,
	    "dropped_bad_crc32", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_bad_phy,
	    "dropped_bad_phy", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_link_error_or_filtered,
	    "dropped_link_error_or_filtered", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_link_overflow,
	    "dropped_link_overflow", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_multicast_filtered,
	    "dropped_multicast_filtered", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_no_big_buffer,
	    "dropped_no_big_buffer", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_no_small_buffer,
	    "dropped_no_small_buffer", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_overrun,
	    "dropped_overrun", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_pause,
	    "dropped_pause", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_runt,
	    "dropped_runt", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_unicast_filtered,
	    "dropped_unicast_filtered", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->dropped_runt, "dropped_runt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->link_up, "link_up", KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->link_changes, "link_changes",
	    KSTAT_DATA_ULONG);
	ksp->ks_update = myri10ge_nic_stat_kstat_update;
	ksp->ks_private = (void *) mgp;
	kstat_install(ksp);
	return (DDI_SUCCESS);
}

static int
myri10ge_slice_stat_init(struct myri10ge_slice_state *ss)
{
	struct myri10ge_priv *mgp = ss->mgp;
	struct kstat *ksp;
	struct myri10ge_slice_stat *ethstat;
	int instance;

	/*
	 * fake an instance so that the same slice numbers from
	 * different instances do not collide
	 */
	instance = (ddi_get_instance(mgp->dip) * 1000) +  (int)(ss - mgp->ss);
	ksp = kstat_create("myri10ge", instance,
	    "myri10ge_slice_stats", "net", KSTAT_TYPE_NAMED,
	    sizeof (*ethstat) / sizeof (kstat_named_t), 0);
	if (ksp == NULL) {
		cmn_err(CE_WARN,
		    "%s: myri10ge_stat_init: kstat_create failed", mgp->name);
		return (DDI_FAILURE);
	}
	ss->ksp_stat = ksp;
	ethstat = (struct myri10ge_slice_stat *)(ksp->ks_data);
	kstat_named_init(&ethstat->lro_bad_csum, "lro_bad_csum",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->lro_flushed, "lro_flushed",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->lro_queued, "lro_queued",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->rx_bigbuf_firmware, "rx_bigbuf_firmware",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->rx_bigbuf_pool, "rx_bigbuf_pool",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->rx_bigbuf_smalls, "rx_bigbuf_smalls",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->rx_copy, "rx_copy",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->rx_big_nobuf, "rx_big_nobuf",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->rx_small_nobuf, "rx_small_nobuf",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_zero_len, "xmit_zero_len",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_pullup, "xmit_pullup",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_pullup_first, "xmit_pullup_first",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_lowbuf, "xmit_lowbuf",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_lsobadflags, "xmit_lsobadflags",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_sched, "xmit_sched",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_stall, "xmit_stall",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_stall_early, "xmit_stall_early",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_stall_late, "xmit_stall_late",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->xmit_err, "xmit_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->tx_req, "tx_req",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->tx_activate, "tx_activate",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->tx_done, "tx_done",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->tx_handles_alloced, "tx_handles_alloced",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->rx_big, "rx_big",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ethstat->rx_small, "rx_small",
	    KSTAT_DATA_ULONG);
	ksp->ks_update = myri10ge_slice_stat_kstat_update;
	ksp->ks_private = (void *) ss;
	kstat_install(ksp);
	return (DDI_SUCCESS);
}



#if defined __i386 || defined i386 || defined __i386__ || defined __x86_64__

#include <vm/hat.h>
#include <sys/ddi_isa.h>
void *device_arena_alloc(size_t size, int vm_flag);
void device_arena_free(void *vaddr, size_t size);

static void
myri10ge_enable_nvidia_ecrc(struct myri10ge_priv *mgp)
{
	dev_info_t *parent_dip;
	ddi_acc_handle_t handle;
	unsigned long bus_number, dev_number, func_number;
	unsigned long cfg_pa, paddr, base, pgoffset;
	char 		*cvaddr, *ptr;
	uint32_t	*ptr32;
	int 		retval = DDI_FAILURE;
	int dontcare;
	uint16_t read_vid, read_did, vendor_id, device_id;

	if (!myri10ge_nvidia_ecrc_enable)
		return;

	parent_dip = ddi_get_parent(mgp->dip);
	if (parent_dip == NULL) {
		cmn_err(CE_WARN, "%s: I'm an orphan?", mgp->name);
		return;
	}

	if (pci_config_setup(parent_dip, &handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s: Could not access my parent's registers", mgp->name);
		return;
	}

	vendor_id = pci_config_get16(handle, PCI_CONF_VENID);
	device_id = pci_config_get16(handle, PCI_CONF_DEVID);
	pci_config_teardown(&handle);

	if (myri10ge_verbose) {
		unsigned long 	bus_number, dev_number, func_number;
		int 		reg_set, span;
		(void) myri10ge_reg_set(parent_dip, &reg_set, &span,
		    &bus_number, &dev_number, &func_number);
		if (myri10ge_verbose)
			printf("%s: parent at %ld:%ld:%ld\n", mgp->name,
			    bus_number, dev_number, func_number);
	}

	if (vendor_id !=  0x10de)
		return;

	if (device_id != 0x005d /* CK804 */ &&
	    (device_id < 0x374 || device_id > 0x378) /* MCP55 */) {
		return;
	}
	(void) myri10ge_reg_set(parent_dip, &dontcare, &dontcare,
	    &bus_number, &dev_number, &func_number);

	for (cfg_pa = 0xf0000000UL;
	    retval != DDI_SUCCESS && cfg_pa >= 0xe0000000UL;
	    cfg_pa -= 0x10000000UL) {
		/* find the config space address for the nvidia bridge */
		paddr = (cfg_pa + bus_number * 0x00100000UL +
		    (dev_number * 8 + func_number) * 0x00001000UL);

		base = paddr & (~MMU_PAGEOFFSET);
		pgoffset = paddr & MMU_PAGEOFFSET;

		/* map it into the kernel */
		cvaddr =  device_arena_alloc(ptob(1), VM_NOSLEEP);
		if (cvaddr == NULL)
			cmn_err(CE_WARN, "%s: failed to map nf4: cvaddr\n",
			    mgp->name);

		hat_devload(kas.a_hat, cvaddr, mmu_ptob(1),
		    i_ddi_paddr_to_pfn(base),
		    PROT_WRITE|HAT_STRICTORDER, HAT_LOAD_LOCK);

		ptr = cvaddr + pgoffset;
		read_vid = *(uint16_t *)(void *)(ptr + PCI_CONF_VENID);
		read_did = *(uint16_t *)(void *)(ptr + PCI_CONF_DEVID);
		if (vendor_id ==  read_did || device_id == read_did) {
			ptr32 = (uint32_t *)(void *)(ptr + 0x178);
			if (myri10ge_verbose)
				printf("%s: Enabling ECRC on upstream "
				    "Nvidia bridge (0x%x:0x%x) "
				    "at %ld:%ld:%ld\n", mgp->name,
				    read_vid, read_did, bus_number,
				    dev_number, func_number);
			*ptr32 |= 0x40;
			retval = DDI_SUCCESS;
		}
		hat_unload(kas.a_hat, cvaddr, ptob(1), HAT_UNLOAD_UNLOCK);
		device_arena_free(cvaddr, ptob(1));
	}
}

#else
/*ARGSUSED*/
static void
myri10ge_enable_nvidia_ecrc(struct myri10ge_priv *mgp)
{
}
#endif /* i386 */


/*
 * The Lanai Z8E PCI-E interface achieves higher Read-DMA throughput
 * when the PCI-E Completion packets are aligned on an 8-byte
 * boundary.  Some PCI-E chip sets always align Completion packets; on
 * the ones that do not, the alignment can be enforced by enabling
 * ECRC generation (if supported).
 *
 * When PCI-E Completion packets are not aligned, it is actually more
 * efficient to limit Read-DMA transactions to 2KB, rather than 4KB.
 *
 * If the driver can neither enable ECRC nor verify that it has
 * already been enabled, then it must use a firmware image which works
 * around unaligned completion packets (ethp_z8e.dat), and it should
 * also ensure that it never gives the device a Read-DMA which is
 * larger than 2KB by setting the tx.boundary to 2KB.  If ECRC is
 * enabled, then the driver should use the aligned (eth_z8e.dat)
 * firmware image, and set tx.boundary to 4KB.
 */


static int
myri10ge_firmware_probe(struct myri10ge_priv *mgp)
{
	int status;

	mgp->tx_boundary = 4096;
	/*
	 * Verify the max read request size was set to 4KB
	 * before trying the test with 4KB.
	 */
	if (mgp->max_read_request_4k == 0)
		mgp->tx_boundary = 2048;
	/*
	 * load the optimized firmware which assumes aligned PCIe
	 * completions in order to see if it works on this host.
	 */

	mgp->fw_name = "rss_eth_z8e";
	mgp->eth_z8e = (unsigned char *)rss_eth_z8e;
	mgp->eth_z8e_length = rss_eth_z8e_length;

	status = myri10ge_load_firmware(mgp);
	if (status != 0) {
		return (status);
	}
	/*
	 * Enable ECRC if possible
	 */
	myri10ge_enable_nvidia_ecrc(mgp);

	/*
	 * Run a DMA test which watches for unaligned completions and
	 * aborts on the first one seen.
	 */
	status = myri10ge_dma_test(mgp, MXGEFW_CMD_UNALIGNED_TEST);
	if (status == 0)
		return (0); /* keep the aligned firmware */

	if (status != E2BIG)
		cmn_err(CE_WARN, "%s: DMA test failed: %d\n",
		    mgp->name, status);
	if (status == ENOSYS)
		cmn_err(CE_WARN, "%s: Falling back to ethp! "
		    "Please install up to date fw\n", mgp->name);
	return (status);
}

static int
myri10ge_select_firmware(struct myri10ge_priv *mgp)
{
	int aligned;

	aligned = 0;

	if (myri10ge_force_firmware == 1) {
		if (myri10ge_verbose)
			printf("%s: Assuming aligned completions (forced)\n",
			    mgp->name);
		aligned = 1;
		goto done;
	}

	if (myri10ge_force_firmware == 2) {
		if (myri10ge_verbose)
			printf("%s: Assuming unaligned completions (forced)\n",
			    mgp->name);
		aligned = 0;
		goto done;
	}

	/* If the width is less than 8, we may used the aligned firmware */
	if (mgp->pcie_link_width != 0 && mgp->pcie_link_width < 8) {
		cmn_err(CE_WARN, "!%s: PCIe link running at x%d\n",
		    mgp->name, mgp->pcie_link_width);
		aligned = 1;
		goto done;
	}

	if (0 == myri10ge_firmware_probe(mgp))
		return (0);  /* keep optimized firmware */

done:
	if (aligned) {
		mgp->fw_name = "rss_eth_z8e";
		mgp->eth_z8e = (unsigned char *)rss_eth_z8e;
		mgp->eth_z8e_length = rss_eth_z8e_length;
		mgp->tx_boundary = 4096;
	} else {
		mgp->fw_name = "rss_ethp_z8e";
		mgp->eth_z8e = (unsigned char *)rss_ethp_z8e;
		mgp->eth_z8e_length = rss_ethp_z8e_length;
		mgp->tx_boundary = 2048;
	}

	return (myri10ge_load_firmware(mgp));
}

static int
myri10ge_add_intrs(struct myri10ge_priv *mgp, int add_handler)
{
	dev_info_t *devinfo = mgp->dip;
	int count, avail, actual, intr_types;
	int x, y, rc, inum = 0;


	rc = ddi_intr_get_supported_types(devinfo, &intr_types);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "!%s: ddi_intr_get_nintrs() failure, rc = %d\n", mgp->name,
		    rc);
		return (DDI_FAILURE);
	}

	if (!myri10ge_use_msi)
		intr_types &= ~DDI_INTR_TYPE_MSI;
	if (!myri10ge_use_msix)
		intr_types &= ~DDI_INTR_TYPE_MSIX;

	if (intr_types & DDI_INTR_TYPE_MSIX) {
		mgp->ddi_intr_type = DDI_INTR_TYPE_MSIX;
		mgp->intr_type = "MSI-X";
	} else if (intr_types & DDI_INTR_TYPE_MSI) {
		mgp->ddi_intr_type = DDI_INTR_TYPE_MSI;
		mgp->intr_type = "MSI";
	} else {
		mgp->ddi_intr_type = DDI_INTR_TYPE_FIXED;
		mgp->intr_type = "Legacy";
	}
	/* Get number of interrupts */
	rc = ddi_intr_get_nintrs(devinfo, mgp->ddi_intr_type, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		cmn_err(CE_WARN, "%s: ddi_intr_get_nintrs() failure, rc: %d, "
		    "count: %d", mgp->name, rc, count);

		return (DDI_FAILURE);
	}

	/* Get number of available interrupts */
	rc = ddi_intr_get_navail(devinfo, mgp->ddi_intr_type, &avail);
	if ((rc != DDI_SUCCESS) || (avail == 0)) {
		cmn_err(CE_WARN, "%s: ddi_intr_get_navail() failure, "
		    "rc: %d, avail: %d\n", mgp->name, rc, avail);
		return (DDI_FAILURE);
	}
	if (avail < count) {
		cmn_err(CE_NOTE,
		    "!%s: nintrs() returned %d, navail returned %d",
		    mgp->name, count, avail);
		count = avail;
	}

	if (count < mgp->num_slices)
		return (DDI_FAILURE);

	if (count > mgp->num_slices)
		count = mgp->num_slices;

	/* Allocate memory for MSI interrupts */
	mgp->intr_size = count * sizeof (ddi_intr_handle_t);
	mgp->htable = kmem_alloc(mgp->intr_size, KM_SLEEP);

	rc = ddi_intr_alloc(devinfo, mgp->htable, mgp->ddi_intr_type, inum,
	    count, &actual, DDI_INTR_ALLOC_NORMAL);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		cmn_err(CE_WARN, "%s: ddi_intr_alloc() failed: %d",
		    mgp->name, rc);

		kmem_free(mgp->htable, mgp->intr_size);
		mgp->htable = NULL;
		return (DDI_FAILURE);
	}

	if ((actual < count) && myri10ge_verbose) {
		cmn_err(CE_NOTE, "%s: got %d/%d slices",
		    mgp->name, actual, count);
	}

	mgp->intr_cnt = actual;

	/*
	 * Get priority for first irq, assume remaining are all the same
	 */
	if (ddi_intr_get_pri(mgp->htable[0], &mgp->intr_pri)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: ddi_intr_get_pri() failed", mgp->name);

		/* Free already allocated intr */
		for (y = 0; y < actual; y++) {
			(void) ddi_intr_free(mgp->htable[y]);
		}

		kmem_free(mgp->htable, mgp->intr_size);
		mgp->htable = NULL;
		return (DDI_FAILURE);
	}

	mgp->icookie = (void *)(uintptr_t)mgp->intr_pri;

	if (!add_handler)
		return (DDI_SUCCESS);

	/* Call ddi_intr_add_handler() */
	for (x = 0; x < actual; x++) {
		if (ddi_intr_add_handler(mgp->htable[x], myri10ge_intr,
		    (caddr_t)&mgp->ss[x], NULL) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: ddi_intr_add_handler() failed",
			    mgp->name);

			/* Free already allocated intr */
			for (y = 0; y < actual; y++) {
				(void) ddi_intr_free(mgp->htable[y]);
			}

			kmem_free(mgp->htable, mgp->intr_size);
			mgp->htable = NULL;
			return (DDI_FAILURE);
		}
	}

	(void) ddi_intr_get_cap(mgp->htable[0], &mgp->intr_cap);
	if (mgp->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI */
		(void) ddi_intr_block_enable(mgp->htable, mgp->intr_cnt);
	} else {
		/* Call ddi_intr_enable() for MSI non block enable */
		for (x = 0; x < mgp->intr_cnt; x++) {
			(void) ddi_intr_enable(mgp->htable[x]);
		}
	}

	return (DDI_SUCCESS);
}

static void
myri10ge_rem_intrs(struct myri10ge_priv *mgp, int handler_installed)
{
	int x, err;

	/* Disable all interrupts */
	if (handler_installed) {
		if (mgp->intr_cap & DDI_INTR_FLAG_BLOCK) {
			/* Call ddi_intr_block_disable() */
			(void) ddi_intr_block_disable(mgp->htable,
			    mgp->intr_cnt);
		} else {
			for (x = 0; x < mgp->intr_cnt; x++) {
				(void) ddi_intr_disable(mgp->htable[x]);
			}
		}
	}

	for (x = 0; x < mgp->intr_cnt; x++) {
		if (handler_installed) {
		/* Call ddi_intr_remove_handler() */
			err = ddi_intr_remove_handler(mgp->htable[x]);
			if (err != DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "%s: ddi_intr_remove_handler for"
				    "vec %d returned %d\n", mgp->name,
				    x, err);
			}
		}
		err = ddi_intr_free(mgp->htable[x]);
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s: ddi_intr_free for vec %d returned %d\n",
			    mgp->name, x, err);
		}
	}
	kmem_free(mgp->htable, mgp->intr_size);
	mgp->htable = NULL;
}

static void
myri10ge_test_physical(dev_info_t *dip)
{
	ddi_dma_handle_t	handle;
	struct myri10ge_dma_stuff dma;
	void *addr;
	int err;

	/* test #1, sufficient for older sparc systems */
	myri10ge_tx_dma_attr.dma_attr_flags = DDI_DMA_FORCE_PHYSICAL;
	err = ddi_dma_alloc_handle(dip, &myri10ge_tx_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &handle);
	if (err == DDI_DMA_BADATTR)
		goto fail;
	ddi_dma_free_handle(&handle);

	/* test #2, required on Olympis where the bind is what fails */
	addr = myri10ge_dma_alloc(dip, 128, &myri10ge_tx_dma_attr,
	    &myri10ge_dev_access_attr, DDI_DMA_STREAMING,
	    DDI_DMA_WRITE|DDI_DMA_STREAMING, &dma, 0, DDI_DMA_DONTWAIT);
	if (addr == NULL)
		goto fail;
	myri10ge_dma_free(&dma);
	return;

fail:
	if (myri10ge_verbose)
		printf("myri10ge%d: DDI_DMA_FORCE_PHYSICAL failed, "
		    "using IOMMU\n", ddi_get_instance(dip));

	myri10ge_tx_dma_attr.dma_attr_flags &= ~DDI_DMA_FORCE_PHYSICAL;
}

static void
myri10ge_get_props(dev_info_t *dip)
{

	myri10ge_flow_control =  ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_flow_control", myri10ge_flow_control);

	myri10ge_intr_coal_delay = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_intr_coal_delay", myri10ge_intr_coal_delay);

#if defined __i386 || defined i386 || defined __i386__ || defined __x86_64__
	myri10ge_nvidia_ecrc_enable = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_nvidia_ecrc_enable", 1);
#endif


	myri10ge_use_msi = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_use_msi", myri10ge_use_msi);

	myri10ge_deassert_wait = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_deassert_wait",  myri10ge_deassert_wait);

	myri10ge_verbose = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_verbose", myri10ge_verbose);

	myri10ge_tx_copylen = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_tx_copylen", myri10ge_tx_copylen);

	if (myri10ge_tx_copylen < 60) {
		cmn_err(CE_WARN,
		    "myri10ge_tx_copylen must be >= 60 bytes\n");
		myri10ge_tx_copylen = 60;
	}

	myri10ge_mtu_override = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_mtu_override", myri10ge_mtu_override);

	if (myri10ge_mtu_override >= MYRI10GE_MIN_GLD_MTU &&
	    myri10ge_mtu_override <= MYRI10GE_MAX_GLD_MTU)
		myri10ge_mtu = myri10ge_mtu_override +
		    sizeof (struct ether_header) + MXGEFW_PAD + VLAN_TAGSZ;
	else if (myri10ge_mtu_override != 0) {
		cmn_err(CE_WARN,
		    "myri10ge_mtu_override must be between 1500 and "
		    "9000 bytes\n");
	}

	myri10ge_bigbufs_initial = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_bigbufs_initial", myri10ge_bigbufs_initial);
	myri10ge_bigbufs_max = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_bigbufs_max", myri10ge_bigbufs_max);

	myri10ge_watchdog_reset = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_watchdog_reset", myri10ge_watchdog_reset);

	if (myri10ge_bigbufs_initial < 128) {
		cmn_err(CE_WARN,
		    "myri10ge_bigbufs_initial be at least 128\n");
		myri10ge_bigbufs_initial = 128;
	}
	if (myri10ge_bigbufs_max < 128) {
		cmn_err(CE_WARN,
		    "myri10ge_bigbufs_max be at least 128\n");
		myri10ge_bigbufs_max = 128;
	}

	if (myri10ge_bigbufs_max < myri10ge_bigbufs_initial) {
		cmn_err(CE_WARN,
		    "myri10ge_bigbufs_max must be >=  "
		    "myri10ge_bigbufs_initial\n");
		myri10ge_bigbufs_max = myri10ge_bigbufs_initial;
	}

	myri10ge_force_firmware = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_force_firmware", myri10ge_force_firmware);

	myri10ge_max_slices = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_max_slices", myri10ge_max_slices);

	myri10ge_use_msix = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_use_msix", myri10ge_use_msix);

	myri10ge_rss_hash = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_rss_hash", myri10ge_rss_hash);

	if (myri10ge_rss_hash > MXGEFW_RSS_HASH_TYPE_MAX ||
	    myri10ge_rss_hash < MXGEFW_RSS_HASH_TYPE_IPV4) {
		cmn_err(CE_WARN, "myri10ge: Illegal rssh hash type %d\n",
		    myri10ge_rss_hash);
		myri10ge_rss_hash = MXGEFW_RSS_HASH_TYPE_SRC_DST_PORT;
	}
	myri10ge_lro = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_lro", myri10ge_lro);
	myri10ge_lro_cnt = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_lro_cnt", myri10ge_lro_cnt);
	myri10ge_lro_max_aggr = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_lro_max_aggr", myri10ge_lro_max_aggr);
	myri10ge_tx_hash = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_tx_hash", myri10ge_tx_hash);
	myri10ge_use_lso = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_use_lso", myri10ge_use_lso);
	myri10ge_lso_copy = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_lso_copy", myri10ge_lso_copy);
	myri10ge_tx_handles_initial = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_tx_handles_initial", myri10ge_tx_handles_initial);
	myri10ge_small_bytes = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "myri10ge_small_bytes", myri10ge_small_bytes);
	if ((myri10ge_small_bytes + MXGEFW_PAD) & (128 -1)) {
		cmn_err(CE_WARN, "myri10ge: myri10ge_small_bytes (%d)\n",
		    myri10ge_small_bytes);
		cmn_err(CE_WARN, "must be aligned on 128b bndry -2\n");
		myri10ge_small_bytes += 128;
		myri10ge_small_bytes &= ~(128 -1);
		myri10ge_small_bytes -= MXGEFW_PAD;
		cmn_err(CE_WARN, "rounded up to %d\n",
		    myri10ge_small_bytes);

		myri10ge_rss_hash = MXGEFW_RSS_HASH_TYPE_SRC_DST_PORT;
	}
}

#ifndef	PCI_EXP_LNKSTA
#define	PCI_EXP_LNKSTA 18
#endif

static int
myri10ge_find_cap(ddi_acc_handle_t handle, uint8_t *capptr, uint8_t capid)
{
	uint16_t	status;
	uint8_t 	ptr;

	/* check to see if we have capabilities */
	status = pci_config_get16(handle, PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP)) {
		cmn_err(CE_WARN, "PCI_STAT_CAP not found\n");
		return (ENXIO);
	}

	ptr = pci_config_get8(handle, PCI_CONF_CAP_PTR);

	/* Walk the capabilities list, looking for a PCI Express cap */
	while (ptr != PCI_CAP_NEXT_PTR_NULL) {
		if (pci_config_get8(handle, ptr + PCI_CAP_ID) == capid)
			break;
		ptr = pci_config_get8(handle, ptr + PCI_CAP_NEXT_PTR);
	}
	if (ptr < 64) {
		cmn_err(CE_WARN, "Bad capability offset %d\n", ptr);
		return (ENXIO);
	}
	*capptr = ptr;
	return (0);
}

static int
myri10ge_set_max_readreq(ddi_acc_handle_t handle)
{
	int err;
	uint16_t	val;
	uint8_t		ptr;

	err = myri10ge_find_cap(handle, &ptr, PCI_CAP_ID_PCI_E);
	if (err != 0) {
		cmn_err(CE_WARN, "could not find PCIe cap\n");
		return (ENXIO);
	}

	/* set max read req to 4096 */
	val = pci_config_get16(handle, ptr + PCIE_DEVCTL);
	val = (val & ~PCIE_DEVCTL_MAX_READ_REQ_MASK) |
	    PCIE_DEVCTL_MAX_READ_REQ_4096;
	pci_config_put16(handle, ptr + PCIE_DEVCTL, val);
	val = pci_config_get16(handle, ptr + PCIE_DEVCTL);
	if ((val & (PCIE_DEVCTL_MAX_READ_REQ_4096)) !=
	    PCIE_DEVCTL_MAX_READ_REQ_4096) {
		cmn_err(CE_WARN, "could not set max read req (%x)\n", val);
		return (EINVAL);
	}
	return (0);
}

static int
myri10ge_read_pcie_link_width(ddi_acc_handle_t handle, int *link)
{
	int err;
	uint16_t	val;
	uint8_t		ptr;

	err = myri10ge_find_cap(handle, &ptr, PCI_CAP_ID_PCI_E);
	if (err != 0) {
		cmn_err(CE_WARN, "could not set max read req\n");
		return (ENXIO);
	}

	/* read link width */
	val = pci_config_get16(handle, ptr + PCIE_LINKSTS);
	val &= PCIE_LINKSTS_NEG_WIDTH_MASK;
	*link = (val >> 4);
	return (0);
}

static int
myri10ge_reset_nic(struct myri10ge_priv *mgp)
{
	ddi_acc_handle_t handle = mgp->cfg_hdl;
	uint32_t reboot;
	uint16_t cmd;
	int err;

	cmd = pci_config_get16(handle, PCI_CONF_COMM);
	if ((cmd & PCI_COMM_ME) == 0) {
		/*
		 * Bus master DMA disabled?  Check to see if the card
		 * rebooted due to a parity error For now, just report
		 * it
		 */

		/* enter read32 mode */
		pci_config_put8(handle, mgp->vso + 0x10, 0x3);
		/* read REBOOT_STATUS (0xfffffff0) */
		pci_config_put32(handle, mgp->vso + 0x18, 0xfffffff0);
		reboot = pci_config_get16(handle, mgp->vso + 0x14);
		cmn_err(CE_WARN, "%s NIC rebooted 0x%x\n", mgp->name, reboot);
		return (0);
	}
	if (!myri10ge_watchdog_reset) {
		cmn_err(CE_WARN, "%s: not resetting\n", mgp->name);
		return (1);
	}

	myri10ge_stop_locked(mgp);
	err = myri10ge_start_locked(mgp);
	if (err == DDI_FAILURE) {
		return (0);
	}
	mac_tx_update(mgp->mh);
	return (1);
}

static inline int
myri10ge_ring_stalled(myri10ge_tx_ring_t *tx)
{
	if (tx->sched != tx->stall &&
	    tx->done == tx->watchdog_done &&
	    tx->watchdog_req != tx->watchdog_done)
		return (1);
	return (0);
}

static void
myri10ge_watchdog(void *arg)
{
	struct myri10ge_priv *mgp;
	struct myri10ge_slice_state *ss;
	myri10ge_tx_ring_t *tx;
	int nic_ok = 1;
	int slices_stalled, rx_pause, i;
	int add_rx;

	mgp = arg;
	mutex_enter(&mgp->intrlock);
	if (mgp->running != MYRI10GE_ETH_RUNNING) {
		cmn_err(CE_WARN,
		    "%s not running, not rearming watchdog (%d)\n",
		    mgp->name, mgp->running);
		mutex_exit(&mgp->intrlock);
		return;
	}

	rx_pause = ntohl(mgp->ss[0].fw_stats->dropped_pause);

	/*
	 * make sure nic is stalled before we reset the nic, so as to
	 * ensure we don't rip the transmit data structures out from
	 * under a pending transmit
	 */

	for (slices_stalled = 0, i = 0; i < mgp->num_slices; i++) {
		tx = &mgp->ss[i].tx;
		slices_stalled = myri10ge_ring_stalled(tx);
		if (slices_stalled)
			break;
	}

	if (slices_stalled) {
		if (mgp->watchdog_rx_pause == rx_pause) {
			cmn_err(CE_WARN,
			    "%s slice %d stalled:(%d, %d, %d, %d, %d %d %d\n)",
			    mgp->name, i, tx->sched, tx->stall,
			    tx->done, tx->watchdog_done, tx->req, tx->pkt_done,
			    (int)ntohl(mgp->ss[i].fw_stats->send_done_count));
			nic_ok = myri10ge_reset_nic(mgp);
		} else {
			cmn_err(CE_WARN,
			    "%s Flow controlled, check link partner\n",
			    mgp->name);
		}
	}

	if (!nic_ok) {
		cmn_err(CE_WARN,
		    "%s Nic dead, not rearming watchdog\n", mgp->name);
		mutex_exit(&mgp->intrlock);
		return;
	}
	for (i = 0; i < mgp->num_slices; i++) {
		ss = &mgp->ss[i];
		tx = &ss->tx;
		tx->watchdog_done = tx->done;
		tx->watchdog_req = tx->req;
		if (ss->watchdog_rx_copy != MYRI10GE_SLICE_STAT(rx_copy)) {
			ss->watchdog_rx_copy = MYRI10GE_SLICE_STAT(rx_copy);
			add_rx =
			    min(ss->jpool.num_alloc,
			    myri10ge_bigbufs_max -
			    (ss->jpool.num_alloc -
			    ss->jbufs_for_smalls));
			if (add_rx != 0) {
				(void) myri10ge_add_jbufs(ss, add_rx, 0);
				/* now feed them to the firmware */
				mutex_enter(&ss->jpool.mtx);
				myri10ge_restock_jumbos(ss);
				mutex_exit(&ss->jpool.mtx);
			}
		}
	}
	mgp->watchdog_rx_pause = rx_pause;

	mgp->timer_id = timeout(myri10ge_watchdog, mgp,
	    mgp->timer_ticks);
	mutex_exit(&mgp->intrlock);
}

/*ARGSUSED*/
static int
myri10ge_get_coalesce(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)

{
	struct myri10ge_priv *mgp = (struct myri10ge_priv *)(void *)cp;
	(void) mi_mpprintf(mp, "%d", mgp->intr_coal_delay);
	return (0);
}

/*ARGSUSED*/
static int
myri10ge_set_coalesce(queue_t *q, mblk_t *mp, char *value,
    caddr_t cp, cred_t *credp)

{
	struct myri10ge_priv *mgp = (struct myri10ge_priv *)(void *)cp;
	char *end;
	size_t new_value;

	new_value = mi_strtol(value, &end, 10);
	if (end == value)
		return (EINVAL);

	mutex_enter(&myri10ge_param_lock);
	mgp->intr_coal_delay = (int)new_value;
	*mgp->intr_coal_delay_ptr = htonl(mgp->intr_coal_delay);
	mutex_exit(&myri10ge_param_lock);
	return (0);
}

/*ARGSUSED*/
static int
myri10ge_get_pauseparam(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)

{
	struct myri10ge_priv *mgp = (struct myri10ge_priv *)(void *)cp;
	(void) mi_mpprintf(mp, "%d", mgp->pause);
	return (0);
}

/*ARGSUSED*/
static int
myri10ge_set_pauseparam(queue_t *q, mblk_t *mp, char *value,
			caddr_t cp, cred_t *credp)

{
	struct myri10ge_priv *mgp = (struct myri10ge_priv *)(void *)cp;
	char *end;
	size_t new_value;
	int err = 0;

	new_value = mi_strtol(value, &end, 10);
	if (end == value)
		return (EINVAL);
	if (new_value != 0)
		new_value = 1;

	mutex_enter(&myri10ge_param_lock);
	if (new_value != mgp->pause)
		err = myri10ge_change_pause(mgp, new_value);
	mutex_exit(&myri10ge_param_lock);
	return (err);
}

/*ARGSUSED*/
static int
myri10ge_get_int(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)

{
	(void) mi_mpprintf(mp, "%d", *(int *)(void *)cp);
	return (0);
}

/*ARGSUSED*/
static int
myri10ge_set_int(queue_t *q, mblk_t *mp, char *value,
    caddr_t cp, cred_t *credp)

{
	char *end;
	size_t new_value;

	new_value = mi_strtol(value, &end, 10);
	if (end == value)
		return (EINVAL);
	*(int *)(void *)cp = new_value;

	return (0);
}

static void
myri10ge_ndd_init(struct myri10ge_priv *mgp)
{
	mgp->nd_head = NULL;

	(void) nd_load(&mgp->nd_head, "myri10ge_intr_coal_delay",
	    myri10ge_get_coalesce, myri10ge_set_coalesce, (caddr_t)mgp);
	(void) nd_load(&mgp->nd_head, "myri10ge_flow_control",
	    myri10ge_get_pauseparam, myri10ge_set_pauseparam, (caddr_t)mgp);
	(void) nd_load(&mgp->nd_head, "myri10ge_verbose",
	    myri10ge_get_int, myri10ge_set_int, (caddr_t)&myri10ge_verbose);
	(void) nd_load(&mgp->nd_head, "myri10ge_deassert_wait",
	    myri10ge_get_int, myri10ge_set_int,
	    (caddr_t)&myri10ge_deassert_wait);
	(void) nd_load(&mgp->nd_head, "myri10ge_bigbufs_max",
	    myri10ge_get_int, myri10ge_set_int,
	    (caddr_t)&myri10ge_bigbufs_max);
	(void) nd_load(&mgp->nd_head, "myri10ge_lro",
	    myri10ge_get_int, myri10ge_set_int,
	    (caddr_t)&myri10ge_lro);
	(void) nd_load(&mgp->nd_head, "myri10ge_lro_max_aggr",
	    myri10ge_get_int, myri10ge_set_int,
	    (caddr_t)&myri10ge_lro_max_aggr);
	(void) nd_load(&mgp->nd_head, "myri10ge_tx_hash",
	    myri10ge_get_int, myri10ge_set_int,
	    (caddr_t)&myri10ge_tx_hash);
	(void) nd_load(&mgp->nd_head, "myri10ge_lso_copy",
	    myri10ge_get_int, myri10ge_set_int,
	    (caddr_t)&myri10ge_lso_copy);
}

static void
myri10ge_ndd_fini(struct myri10ge_priv *mgp)
{
	nd_free(&mgp->nd_head);
}

static void
myri10ge_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp;
	struct myri10ge_priv *mgp = arg;
	int cmd, ok, err;

	iocp = (struct iocblk *)(void *)mp->b_rptr;
	cmd = iocp->ioc_cmd;

	ok = 0;
	err = 0;

	switch (cmd) {
	case ND_GET:
	case ND_SET:
		ok = nd_getset(wq, mgp->nd_head, mp);
		break;
	default:
		break;
	}
	if (!ok)
		err = EINVAL;
	else
		err = iocp->ioc_error;

	if (!err)
		miocack(wq, mp, iocp->ioc_count, err);
	else
		miocnak(wq, mp, 0, err);
}

static struct myri10ge_priv *mgp_list;

struct myri10ge_priv *
myri10ge_get_instance(uint_t unit)
{
	struct myri10ge_priv *mgp;

	mutex_enter(&myri10ge_param_lock);
	for (mgp = mgp_list; mgp != NULL; mgp = mgp->next) {
		if (unit == ddi_get_instance(mgp->dip)) {
			mgp->refcnt++;
			break;
		}
	}
	mutex_exit(&myri10ge_param_lock);
	return (mgp);
}

void
myri10ge_put_instance(struct myri10ge_priv *mgp)
{
	mutex_enter(&myri10ge_param_lock);
	mgp->refcnt--;
	mutex_exit(&myri10ge_param_lock);
}

static boolean_t
myri10ge_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	struct myri10ge_priv *mgp = arg;
	uint32_t *cap_hcksum;
	mac_capab_lso_t *cap_lso;
	mac_capab_rings_t *cap_rings;

	switch (cap) {
	case MAC_CAPAB_HCKSUM:
		cap_hcksum = cap_data;
		*cap_hcksum = HCKSUM_INET_PARTIAL;
		break;
	case MAC_CAPAB_RINGS:
		cap_rings = cap_data;
		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_RX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = mgp->num_slices;
			cap_rings->mr_gnum = 1;
			cap_rings->mr_rget = myri10ge_fill_ring;
			cap_rings->mr_gget = myri10ge_fill_group;
			break;
		case MAC_RING_TYPE_TX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = mgp->num_slices;
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rget = myri10ge_fill_ring;
			cap_rings->mr_gget = NULL;
			break;
		default:
			return (B_FALSE);
		}
		break;
	case MAC_CAPAB_LSO:
		cap_lso = cap_data;
		if (!myri10ge_use_lso)
			return (B_FALSE);
		if (!(mgp->features & MYRI10GE_TSO))
			return (B_FALSE);
		cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
		cap_lso->lso_basic_tcp_ipv4.lso_max = (uint16_t)-1;
		break;

	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}


static int
myri10ge_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct myri10ge_priv *mgp = arg;
	struct myri10ge_rx_ring_stats *rstat;
	struct myri10ge_tx_ring_stats *tstat;
	mcp_irq_data_t *fw_stats = mgp->ss[0].fw_stats;
	struct myri10ge_slice_state *ss;
	uint64_t tmp = 0;
	int i;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = 10ull * 1000ull * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		for (i = 0; i < mgp->num_slices; i++) {
			rstat = &mgp->ss[i].rx_stats;
			tmp += rstat->multircv;
		}
		*val = tmp;
		break;

	case MAC_STAT_BRDCSTRCV:
		for (i = 0; i < mgp->num_slices; i++) {
			rstat = &mgp->ss[i].rx_stats;
			tmp += rstat->brdcstrcv;
		}
		*val = tmp;
		break;

	case MAC_STAT_MULTIXMT:
		for (i = 0; i < mgp->num_slices; i++) {
			tstat = &mgp->ss[i].tx.stats;
			tmp += tstat->multixmt;
		}
		*val = tmp;
		break;

	case MAC_STAT_BRDCSTXMT:
		for (i = 0; i < mgp->num_slices; i++) {
			tstat = &mgp->ss[i].tx.stats;
			tmp += tstat->brdcstxmt;
		}
		*val = tmp;
		break;

	case MAC_STAT_NORCVBUF:
		tmp = ntohl(fw_stats->dropped_no_big_buffer);
		tmp += ntohl(fw_stats->dropped_no_small_buffer);
		tmp += ntohl(fw_stats->dropped_link_overflow);
		for (i = 0; i < mgp->num_slices; i++) {
			ss = &mgp->ss[i];
			tmp += MYRI10GE_SLICE_STAT(rx_big_nobuf);
			tmp += MYRI10GE_SLICE_STAT(rx_small_nobuf);
		}
		*val = tmp;
		break;

	case MAC_STAT_IERRORS:
		tmp += ntohl(fw_stats->dropped_bad_crc32);
		tmp += ntohl(fw_stats->dropped_bad_phy);
		tmp += ntohl(fw_stats->dropped_runt);
		tmp += ntohl(fw_stats->dropped_overrun);
		*val = tmp;
		break;

	case MAC_STAT_OERRORS:
		for (i = 0; i < mgp->num_slices; i++) {
			ss = &mgp->ss[i];
			tmp += MYRI10GE_SLICE_STAT(xmit_lsobadflags);
			tmp += MYRI10GE_SLICE_STAT(xmit_err);
		}
		*val = tmp;
		break;

	case MAC_STAT_RBYTES:
		for (i = 0; i < mgp->num_slices; i++) {
			rstat = &mgp->ss[i].rx_stats;
			tmp += rstat->ibytes;
		}
		*val = tmp;
		break;

	case MAC_STAT_IPACKETS:
		for (i = 0; i < mgp->num_slices; i++) {
			rstat = &mgp->ss[i].rx_stats;
			tmp += rstat->ipackets;
		}
		*val = tmp;
		break;

	case MAC_STAT_OBYTES:
		for (i = 0; i < mgp->num_slices; i++) {
			tstat = &mgp->ss[i].tx.stats;
			tmp += tstat->obytes;
		}
		*val = tmp;
		break;

	case MAC_STAT_OPACKETS:
		for (i = 0; i < mgp->num_slices; i++) {
			tstat = &mgp->ss[i].tx.stats;
			tmp += tstat->opackets;
		}
		*val = tmp;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = ntohl(fw_stats->dropped_overrun);
		break;

#ifdef SOLARIS_S11
	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = ntohl(fw_stats->dropped_runt);
		break;
#endif

	case ETHER_STAT_LINK_PAUSE:
		*val = mgp->pause;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = 1;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}

/* ARGSUSED */
static void
myri10ge_m_propinfo(void *arg, const char *pr_name,
    mac_prop_id_t pr_num, mac_prop_info_handle_t prh)
{
	switch (pr_num) {
	case MAC_PROP_MTU:
		mac_prop_info_set_default_uint32(prh, MYRI10GE_DEFAULT_GLD_MTU);
		mac_prop_info_set_range_uint32(prh, MYRI10GE_MIN_GLD_MTU,
		    MYRI10GE_MAX_GLD_MTU);
		break;
	default:
		break;
	}
}

/*ARGSUSED*/
static int
myri10ge_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	int err = 0;
	struct myri10ge_priv *mgp = arg;

	switch (pr_num) {
	case MAC_PROP_MTU: {
		uint32_t mtu;
		if (pr_valsize < sizeof (mtu)) {
			err = EINVAL;
			break;
		}
		bcopy(pr_val, &mtu, sizeof (mtu));
		if (mtu > MYRI10GE_MAX_GLD_MTU ||
		    mtu < MYRI10GE_MIN_GLD_MTU) {
			err = EINVAL;
			break;
		}

		mutex_enter(&mgp->intrlock);
		if (mgp->running != MYRI10GE_ETH_STOPPED) {
			err = EBUSY;
			mutex_exit(&mgp->intrlock);
			break;
		}

		myri10ge_mtu = mtu + sizeof (struct ether_header) +
		    MXGEFW_PAD + VLAN_TAGSZ;
		mutex_exit(&mgp->intrlock);
		break;
	}
	default:
		err = ENOTSUP;
		break;
	}

	return (err);
}

static mac_callbacks_t myri10ge_m_callbacks = {
	(MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_PROPINFO),
	myri10ge_m_stat,
	myri10ge_m_start,
	myri10ge_m_stop,
	myri10ge_m_promisc,
	myri10ge_m_multicst,
	NULL,
	NULL,
	NULL,
	myri10ge_m_ioctl,
	myri10ge_m_getcapab,
	NULL,
	NULL,
	myri10ge_m_setprop,
	NULL,
	myri10ge_m_propinfo
};


static int
myri10ge_probe_slices(struct myri10ge_priv *mgp)
{
	myri10ge_cmd_t cmd;
	int status;

	mgp->num_slices = 1;

	/* hit the board with a reset to ensure it is alive */
	(void) memset(&cmd, 0, sizeof (cmd));
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_RESET, &cmd);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed reset\n", mgp->name);
		return (ENXIO);
	}

	if (myri10ge_use_msix == 0)
		return (0);

	/* tell it the size of the interrupt queues */
	cmd.data0 = mgp->max_intr_slots * sizeof (struct mcp_slot);
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_SET_INTRQ_SIZE, &cmd);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed MXGEFW_CMD_SET_INTRQ_SIZE\n",
		    mgp->name);
		return (ENXIO);
	}

	/* ask the maximum number of slices it supports */
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_GET_MAX_RSS_QUEUES,
	    &cmd);
	if (status != 0)
		return (0);

	mgp->num_slices = cmd.data0;

	/*
	 * if the admin did not specify a limit to how many
	 * slices we should use, cap it automatically to the
	 * number of CPUs currently online
	 */
	if (myri10ge_max_slices == -1)
		myri10ge_max_slices = ncpus;

	if (mgp->num_slices > myri10ge_max_slices)
		mgp->num_slices = myri10ge_max_slices;


	/*
	 * Now try to allocate as many MSI-X vectors as we have
	 * slices. We give up on MSI-X if we can only get a single
	 * vector.
	 */
	while (mgp->num_slices > 1) {
		/* make sure it is a power of two */
		while (!ISP2(mgp->num_slices))
			mgp->num_slices--;
		if (mgp->num_slices == 1)
			return (0);

		status = myri10ge_add_intrs(mgp, 0);
		if (status == 0) {
			myri10ge_rem_intrs(mgp, 0);
			if (mgp->intr_cnt == mgp->num_slices) {
				if (myri10ge_verbose)
					printf("Got %d slices!\n",
					    mgp->num_slices);
				return (0);
			}
			mgp->num_slices = mgp->intr_cnt;
		} else {
			mgp->num_slices = mgp->num_slices / 2;
		}
	}

	if (myri10ge_verbose)
		printf("Got %d slices\n", mgp->num_slices);
	return (0);
}

static void
myri10ge_lro_free(struct myri10ge_slice_state *ss)
{
	struct lro_entry *lro;

	while (ss->lro_free != NULL) {
		lro = ss->lro_free;
		ss->lro_free = lro->next;
		kmem_free(lro, sizeof (*lro));
	}
}

static void
myri10ge_lro_alloc(struct myri10ge_slice_state *ss)
{
	struct lro_entry *lro;
	int idx;

	ss->lro_free = NULL;
	ss->lro_active = NULL;

	for (idx = 0; idx < myri10ge_lro_cnt; idx++) {
		lro = kmem_zalloc(sizeof (*lro), KM_SLEEP);
		if (lro == NULL)
			continue;
		lro->next = ss->lro_free;
		ss->lro_free = lro;
	}
}

static void
myri10ge_free_slices(struct myri10ge_priv *mgp)
{
	struct myri10ge_slice_state *ss;
	size_t bytes;
	int i;

	if (mgp->ss == NULL)
		return;

	for (i = 0; i < mgp->num_slices; i++) {
		ss = &mgp->ss[i];
		if (ss->rx_done.entry == NULL)
			continue;
		myri10ge_dma_free(&ss->rx_done.dma);
		ss->rx_done.entry = NULL;
		if (ss->fw_stats == NULL)
			continue;
		myri10ge_dma_free(&ss->fw_stats_dma);
		ss->fw_stats = NULL;
		mutex_destroy(&ss->rx_lock);
		mutex_destroy(&ss->tx.lock);
		mutex_destroy(&ss->tx.handle_lock);
		mutex_destroy(&ss->poll_lock);
		myri10ge_jpool_fini(ss);
		myri10ge_slice_stat_destroy(ss);
		myri10ge_lro_free(ss);
	}
	bytes = sizeof (*mgp->ss) * mgp->num_slices;
	kmem_free(mgp->ss, bytes);
	mgp->ss = NULL;
}


static int
myri10ge_alloc_slices(struct myri10ge_priv *mgp)
{
	struct myri10ge_slice_state *ss;
	size_t bytes;
	int i;

	bytes = sizeof (*mgp->ss) * mgp->num_slices;
	mgp->ss = kmem_zalloc(bytes, KM_SLEEP);
	if (mgp->ss == NULL)
		return (ENOMEM);
	for (i = 0; i < mgp->num_slices; i++) {
		ss = &mgp->ss[i];

		ss->mgp = mgp;

		/* allocate the per-slice firmware stats */
		bytes = sizeof (*ss->fw_stats);
		ss->fw_stats = (mcp_irq_data_t *)(void *)
		    myri10ge_dma_alloc(mgp->dip, bytes,
		    &myri10ge_misc_dma_attr, &myri10ge_dev_access_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_READ|DDI_DMA_CONSISTENT,
		    &ss->fw_stats_dma, 1, DDI_DMA_DONTWAIT);
		if (ss->fw_stats == NULL)
			goto abort;
		(void) memset(ss->fw_stats, 0, bytes);

		/* allocate rx done ring */
		bytes = mgp->max_intr_slots *
		    sizeof (*ss->rx_done.entry);
		ss->rx_done.entry = (mcp_slot_t *)(void *)
		    myri10ge_dma_alloc(mgp->dip, bytes,
		    &myri10ge_misc_dma_attr, &myri10ge_dev_access_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_READ|DDI_DMA_CONSISTENT,
		    &ss->rx_done.dma, 1, DDI_DMA_DONTWAIT);
		if (ss->rx_done.entry == NULL) {
			goto abort;
		}
		(void) memset(ss->rx_done.entry, 0, bytes);
		mutex_init(&ss->rx_lock,   NULL, MUTEX_DEFAULT, mgp->icookie);
		mutex_init(&ss->tx.lock,   NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&ss->tx.handle_lock,   NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&ss->poll_lock,   NULL, MUTEX_DEFAULT, NULL);
		myri10ge_jpool_init(ss);
		(void) myri10ge_slice_stat_init(ss);
		myri10ge_lro_alloc(ss);
	}

	return (0);

abort:
	myri10ge_free_slices(mgp);
	return (ENOMEM);
}

static int
myri10ge_save_msi_state(struct myri10ge_priv *mgp,
    ddi_acc_handle_t handle)
{
	uint8_t ptr;
	int err;

	err = myri10ge_find_cap(handle, &ptr, PCI_CAP_ID_MSI);
	if (err != 0) {
		cmn_err(CE_WARN, "%s: could not find MSI cap\n",
		    mgp->name);
		return (DDI_FAILURE);
	}
	mgp->pci_saved_state.msi_ctrl =
	    pci_config_get16(handle, ptr + PCI_MSI_CTRL);
	mgp->pci_saved_state.msi_addr_low =
	    pci_config_get32(handle, ptr + PCI_MSI_ADDR_OFFSET);
	mgp->pci_saved_state.msi_addr_high =
	    pci_config_get32(handle, ptr + PCI_MSI_ADDR_OFFSET + 4);
	mgp->pci_saved_state.msi_data_32 =
	    pci_config_get16(handle, ptr + PCI_MSI_32BIT_DATA);
	mgp->pci_saved_state.msi_data_64 =
	    pci_config_get16(handle, ptr + PCI_MSI_64BIT_DATA);
	return (DDI_SUCCESS);
}

static int
myri10ge_restore_msi_state(struct myri10ge_priv *mgp,
    ddi_acc_handle_t handle)
{
	uint8_t ptr;
	int err;

	err = myri10ge_find_cap(handle, &ptr, PCI_CAP_ID_MSI);
	if (err != 0) {
		cmn_err(CE_WARN, "%s: could not find MSI cap\n",
		    mgp->name);
		return (DDI_FAILURE);
	}

	pci_config_put16(handle, ptr + PCI_MSI_CTRL,
	    mgp->pci_saved_state.msi_ctrl);
	pci_config_put32(handle, ptr + PCI_MSI_ADDR_OFFSET,
	    mgp->pci_saved_state.msi_addr_low);
	pci_config_put32(handle, ptr + PCI_MSI_ADDR_OFFSET + 4,
	    mgp->pci_saved_state.msi_addr_high);
	pci_config_put16(handle, ptr + PCI_MSI_32BIT_DATA,
	    mgp->pci_saved_state.msi_data_32);
	pci_config_put16(handle, ptr + PCI_MSI_64BIT_DATA,
	    mgp->pci_saved_state.msi_data_64);

	return (DDI_SUCCESS);
}

static int
myri10ge_save_pci_state(struct myri10ge_priv *mgp)
{
	ddi_acc_handle_t handle = mgp->cfg_hdl;
	int i;
	int err = DDI_SUCCESS;


	/* Save the non-extended PCI config space 32-bits at a time */
	for (i = 0; i < 16; i++)
		mgp->pci_saved_state.base[i] =
		    pci_config_get32(handle, i*4);

	/* now save MSI interrupt state *, if needed */
	if (mgp->ddi_intr_type == DDI_INTR_TYPE_MSI)
		err = myri10ge_save_msi_state(mgp, handle);

	return (err);
}

static int
myri10ge_restore_pci_state(struct myri10ge_priv *mgp)
{
	ddi_acc_handle_t handle = mgp->cfg_hdl;
	int i;
	int err = DDI_SUCCESS;


	/* Restore the non-extended PCI config space 32-bits at a time */
	for (i = 15; i >= 0; i--)
		pci_config_put32(handle, i*4, mgp->pci_saved_state.base[i]);

	/* now restore MSI interrupt state *, if needed */
	if (mgp->ddi_intr_type == DDI_INTR_TYPE_MSI)
		err = myri10ge_restore_msi_state(mgp, handle);

	if (mgp->max_read_request_4k)
		(void) myri10ge_set_max_readreq(handle);
	return (err);
}


static int
myri10ge_suspend(dev_info_t *dip)
{
	struct myri10ge_priv *mgp = ddi_get_driver_private(dip);
	int status;

	if (mgp == NULL) {
		cmn_err(CE_WARN, "null dip in myri10ge_suspend\n");
		return (DDI_FAILURE);
	}
	if (mgp->dip != dip) {
		cmn_err(CE_WARN, "bad dip in myri10ge_suspend\n");
		return (DDI_FAILURE);
	}
	mutex_enter(&mgp->intrlock);
	if (mgp->running == MYRI10GE_ETH_RUNNING) {
		mgp->running = MYRI10GE_ETH_STOPPING;
		mutex_exit(&mgp->intrlock);
		(void) untimeout(mgp->timer_id);
		mutex_enter(&mgp->intrlock);
		myri10ge_stop_locked(mgp);
		mgp->running = MYRI10GE_ETH_SUSPENDED_RUNNING;
	}
	status = myri10ge_save_pci_state(mgp);
	mutex_exit(&mgp->intrlock);
	return (status);
}

static int
myri10ge_resume(dev_info_t *dip)
{
	struct myri10ge_priv *mgp = ddi_get_driver_private(dip);
	int status = DDI_SUCCESS;

	if (mgp == NULL) {
		cmn_err(CE_WARN, "null dip in myri10ge_resume\n");
		return (DDI_FAILURE);
	}
	if (mgp->dip != dip) {
		cmn_err(CE_WARN, "bad dip in myri10ge_resume\n");
		return (DDI_FAILURE);
	}

	mutex_enter(&mgp->intrlock);
	status = myri10ge_restore_pci_state(mgp);
	if (status == DDI_SUCCESS &&
	    mgp->running == MYRI10GE_ETH_SUSPENDED_RUNNING) {
		status = myri10ge_start_locked(mgp);
	}
	mutex_exit(&mgp->intrlock);
	if (status != DDI_SUCCESS)
		return (status);

	/* start the watchdog timer */
	mgp->timer_id = timeout(myri10ge_watchdog, mgp,
	    mgp->timer_ticks);
	return (DDI_SUCCESS);
}

static int
myri10ge_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{

	struct myri10ge_priv *mgp;
	mac_register_t *macp, *omacp;
	ddi_acc_handle_t handle;
	uint32_t csr, hdr_offset;
	int status, span, link_width, max_read_request_4k;
	unsigned long bus_number, dev_number, func_number;
	size_t bytes;
	offset_t ss_offset;
	uint8_t vso;

	if (cmd == DDI_RESUME) {
		return (myri10ge_resume(dip));
	}

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	if (pci_config_setup(dip, &handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* enable busmater and io space access */
	csr = pci_config_get32(handle, PCI_CONF_COMM);
	pci_config_put32(handle, PCI_CONF_COMM,
	    (csr |PCI_COMM_ME|PCI_COMM_MAE));
	status = myri10ge_read_pcie_link_width(handle, &link_width);
	if (status != 0) {
		cmn_err(CE_WARN, "could not read link width!\n");
		link_width = 0;
	}
	max_read_request_4k = !myri10ge_set_max_readreq(handle);
	status = myri10ge_find_cap(handle, &vso, PCI_CAP_ID_VS);
	if (status != 0)
		goto abort_with_cfg_hdl;
	if ((omacp = mac_alloc(MAC_VERSION)) == NULL)
		goto abort_with_cfg_hdl;
	/*
	 * XXXX Hack: mac_register_t grows in newer kernels.  To be
	 * able to write newer fields, such as m_margin, without
	 * writing outside allocated memory, we allocate our own macp
	 * and pass that to mac_register()
	 */
	macp = kmem_zalloc(sizeof (*macp) * 8, KM_SLEEP);
	macp->m_version = omacp->m_version;

	if ((mgp = (struct myri10ge_priv *)
	    kmem_zalloc(sizeof (*mgp), KM_SLEEP)) == NULL) {
		goto abort_with_macinfo;
	}
	ddi_set_driver_private(dip, mgp);

	/* setup device name for log messages */
	(void) sprintf(mgp->name, "myri10ge%d", ddi_get_instance(dip));

	mutex_enter(&myri10ge_param_lock);
	myri10ge_get_props(dip);
	mgp->intr_coal_delay = myri10ge_intr_coal_delay;
	mgp->pause = myri10ge_flow_control;
	mutex_exit(&myri10ge_param_lock);

	mgp->max_read_request_4k = max_read_request_4k;
	mgp->pcie_link_width = link_width;
	mgp->running = MYRI10GE_ETH_STOPPED;
	mgp->vso = vso;
	mgp->dip = dip;
	mgp->cfg_hdl = handle;

	mgp->timer_ticks = 5 * drv_usectohz(1000000); /* 5 seconds */
	myri10ge_test_physical(dip);

	/* allocate command page */
	bytes = sizeof (*mgp->cmd);
	mgp->cmd = (mcp_cmd_response_t *)
	    (void *)myri10ge_dma_alloc(dip, bytes,
	    &myri10ge_misc_dma_attr, &myri10ge_dev_access_attr,
	    DDI_DMA_CONSISTENT,	DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
	    &mgp->cmd_dma, 1, DDI_DMA_DONTWAIT);
	if (mgp->cmd == NULL)
		goto abort_with_mgp;

	(void) myri10ge_reg_set(dip, &mgp->reg_set, &span, &bus_number,
	    &dev_number, &func_number);
	if (myri10ge_verbose)
		printf("%s at %ld:%ld:%ld attaching\n", mgp->name,
		    bus_number, dev_number, func_number);
	status = ddi_regs_map_setup(dip, mgp->reg_set, (caddr_t *)&mgp->sram,
	    (offset_t)0, (offset_t)span,  &myri10ge_dev_access_attr,
	    &mgp->io_handle);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: couldn't map memory space", mgp->name);
		printf("%s: reg_set = %d, span = %d, status = %d",
		    mgp->name, mgp->reg_set, span, status);
		goto abort_with_mgp;
	}

	hdr_offset = *(uint32_t *)(void*)(mgp->sram +  MCP_HEADER_PTR_OFFSET);
	hdr_offset = ntohl(hdr_offset) & 0xffffc;
	ss_offset = hdr_offset +
	    offsetof(struct mcp_gen_header, string_specs);
	mgp->sram_size = ntohl(*(uint32_t *)(void*)(mgp->sram + ss_offset));
	myri10ge_pio_copy32(mgp->eeprom_strings,
	    (uint32_t *)(void*)((char *)mgp->sram + mgp->sram_size),
	    MYRI10GE_EEPROM_STRINGS_SIZE);
	(void) memset(mgp->eeprom_strings +
	    MYRI10GE_EEPROM_STRINGS_SIZE - 2, 0, 2);

	status = myri10ge_read_mac_addr(mgp);
	if (status) {
		goto abort_with_mapped;
	}

	status = myri10ge_select_firmware(mgp);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed to load firmware\n", mgp->name);
		goto abort_with_mapped;
	}

	status = myri10ge_probe_slices(mgp);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed to probe slices\n", mgp->name);
		goto abort_with_dummy_rdma;
	}

	status = myri10ge_alloc_slices(mgp);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: failed to alloc slices\n", mgp->name);
		goto abort_with_dummy_rdma;
	}

	/* add the interrupt handler */
	status = myri10ge_add_intrs(mgp, 1);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: Failed to add interrupt\n",
		    mgp->name);
		goto abort_with_slices;
	}

	/* now that we have an iblock_cookie, init the mutexes */
	mutex_init(&mgp->cmd_lock, NULL, MUTEX_DRIVER, mgp->icookie);
	mutex_init(&mgp->intrlock, NULL, MUTEX_DRIVER, mgp->icookie);


	status = myri10ge_nic_stat_init(mgp);
	if (status != DDI_SUCCESS)
		goto abort_with_interrupts;
	status = myri10ge_info_init(mgp);
	if (status != DDI_SUCCESS)
		goto abort_with_stats;

	/*
	 *	Initialize  GLD state
	 */

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = mgp;
	macp->m_dip = dip;
	macp->m_src_addr = mgp->mac_addr;
	macp->m_callbacks = &myri10ge_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = myri10ge_mtu -
	    (sizeof (struct ether_header) + MXGEFW_PAD + VLAN_TAGSZ);
#ifdef SOLARIS_S11
	macp->m_margin = VLAN_TAGSZ;
#endif
	macp->m_v12n = MAC_VIRT_LEVEL1;
	status = mac_register(macp, &mgp->mh);
	if (status != 0) {
		cmn_err(CE_WARN, "%s: mac_register failed with %d\n",
		    mgp->name, status);
		goto abort_with_info;
	}
	myri10ge_ndd_init(mgp);
	if (myri10ge_verbose)
		printf("%s: %s, tx bndry %d, fw %s\n", mgp->name,
		    mgp->intr_type, mgp->tx_boundary, mgp->fw_name);
	mutex_enter(&myri10ge_param_lock);
	mgp->next = mgp_list;
	mgp_list = mgp;
	mutex_exit(&myri10ge_param_lock);
	kmem_free(macp, sizeof (*macp) * 8);
	mac_free(omacp);
	return (DDI_SUCCESS);

abort_with_info:
	myri10ge_info_destroy(mgp);

abort_with_stats:
	myri10ge_nic_stat_destroy(mgp);

abort_with_interrupts:
	mutex_destroy(&mgp->cmd_lock);
	mutex_destroy(&mgp->intrlock);
	myri10ge_rem_intrs(mgp, 1);

abort_with_slices:
	myri10ge_free_slices(mgp);

abort_with_dummy_rdma:
	myri10ge_dummy_rdma(mgp, 0);

abort_with_mapped:
	ddi_regs_map_free(&mgp->io_handle);

	myri10ge_dma_free(&mgp->cmd_dma);

abort_with_mgp:
	kmem_free(mgp, sizeof (*mgp));

abort_with_macinfo:
	kmem_free(macp, sizeof (*macp) * 8);
	mac_free(omacp);

abort_with_cfg_hdl:
	pci_config_teardown(&handle);
	return (DDI_FAILURE);

}


static int
myri10ge_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct myri10ge_priv	*mgp, *tmp;
	int 			status, i, jbufs_alloced;

	if (cmd == DDI_SUSPEND) {
		status = myri10ge_suspend(dip);
		return (status);
	}

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}
	/* Get the driver private (gld_mac_info_t) structure */
	mgp = ddi_get_driver_private(dip);

	mutex_enter(&mgp->intrlock);
	jbufs_alloced = 0;
	for (i = 0; i < mgp->num_slices; i++) {
		myri10ge_remove_jbufs(&mgp->ss[i]);
		jbufs_alloced += mgp->ss[i].jpool.num_alloc;
	}
	mutex_exit(&mgp->intrlock);
	if (jbufs_alloced != 0) {
		cmn_err(CE_NOTE, "%s: %d loaned rx buffers remain\n",
		    mgp->name, jbufs_alloced);
		return (DDI_FAILURE);
	}

	mutex_enter(&myri10ge_param_lock);
	if (mgp->refcnt != 0) {
		mutex_exit(&myri10ge_param_lock);
		cmn_err(CE_NOTE, "%s: %d external refs remain\n",
		    mgp->name, mgp->refcnt);
		return (DDI_FAILURE);
	}
	mutex_exit(&myri10ge_param_lock);

	status = mac_unregister(mgp->mh);
	if (status != DDI_SUCCESS)
		return (status);

	myri10ge_ndd_fini(mgp);
	myri10ge_dummy_rdma(mgp, 0);
	myri10ge_nic_stat_destroy(mgp);
	myri10ge_info_destroy(mgp);

	mutex_destroy(&mgp->cmd_lock);
	mutex_destroy(&mgp->intrlock);

	myri10ge_rem_intrs(mgp, 1);

	myri10ge_free_slices(mgp);
	ddi_regs_map_free(&mgp->io_handle);
	myri10ge_dma_free(&mgp->cmd_dma);
	pci_config_teardown(&mgp->cfg_hdl);

	mutex_enter(&myri10ge_param_lock);
	if (mgp_list == mgp) {
		mgp_list = mgp->next;
	} else {
		tmp = mgp_list;
		while (tmp->next != mgp && tmp->next != NULL)
			tmp = tmp->next;
		if (tmp->next != NULL)
			tmp->next = tmp->next->next;
	}
	kmem_free(mgp, sizeof (*mgp));
	mutex_exit(&myri10ge_param_lock);
	return (DDI_SUCCESS);
}

/*
 * Helper for quiesce entry point: Interrupt threads are not being
 * scheduled, so we must poll for the confirmation DMA to arrive in
 * the firmware stats block for slice 0.  We're essentially running
 * the guts of the interrupt handler, and just cherry picking the
 * confirmation that the NIC is queuesced (stats->link_down)
 */

static int
myri10ge_poll_down(struct myri10ge_priv *mgp)
{
	struct myri10ge_slice_state *ss = mgp->ss;
	mcp_irq_data_t *stats = ss->fw_stats;
	int valid;
	int found_down = 0;


	/* check for a pending IRQ */

	if (! *((volatile uint8_t *)& stats->valid))
		return (0);
	valid = stats->valid;

	/*
	 * Make sure to tell the NIC to lower a legacy IRQ, else
	 * it may have corrupt state after restarting
	 */

	if (mgp->ddi_intr_type == DDI_INTR_TYPE_FIXED) {
		/* lower legacy IRQ  */
		*mgp->irq_deassert = 0;
		mb();
		/* wait for irq conf DMA */
		while (*((volatile uint8_t *)& stats->valid))
			;
	}
	if (stats->stats_updated && stats->link_down)
		found_down = 1;

	if (valid & 0x1)
		*ss->irq_claim = BE_32(3);
	*(ss->irq_claim + 1) = BE_32(3);

	return (found_down);
}

static int
myri10ge_quiesce(dev_info_t *dip)
{
	struct myri10ge_priv *mgp;
	myri10ge_cmd_t cmd;
	int status, down, i;

	mgp = ddi_get_driver_private(dip);
	if (mgp == NULL)
		return (DDI_FAILURE);

	/* if devices was unplumbed, it is guaranteed to be quiescent */
	if (mgp->running == MYRI10GE_ETH_STOPPED)
		return (DDI_SUCCESS);

	/* send a down CMD to queuesce NIC */
	status = myri10ge_send_cmd(mgp, MXGEFW_CMD_ETHERNET_DOWN, &cmd);
	if (status) {
		cmn_err(CE_WARN, "%s: Couldn't bring down link\n", mgp->name);
		return (DDI_FAILURE);
	}

	for (i = 0; i < 20; i++) {
		down = myri10ge_poll_down(mgp);
		if (down)
			break;
		delay(drv_usectohz(100000));
		mb();
	}
	if (down)
		return (DDI_SUCCESS);
	return (DDI_FAILURE);
}

/*
 * Distinguish between allocb'ed blocks, and gesballoc'ed attached
 * storage.
 */
static void
myri10ge_find_lastfree(void)
{
	mblk_t *mp = allocb(1024, 0);
	dblk_t *dbp;

	if (mp == NULL) {
		cmn_err(CE_WARN, "myri10ge_find_lastfree failed\n");
		return;
	}
	dbp = mp->b_datap;
	myri10ge_db_lastfree = (void *)dbp->db_lastfree;
}

int
_init(void)
{
	int i;

	if (myri10ge_verbose)
		cmn_err(CE_NOTE,
		    "Myricom 10G driver (10GbE) version %s loading\n",
		    MYRI10GE_VERSION_STR);
	myri10ge_find_lastfree();
	mac_init_ops(&myri10ge_ops, "myri10ge");
	mutex_init(&myri10ge_param_lock, NULL, MUTEX_DEFAULT, NULL);
	if ((i = mod_install(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "mod_install returned %d\n", i);
		mac_fini_ops(&myri10ge_ops);
		mutex_destroy(&myri10ge_param_lock);
	}
	return (i);
}

int
_fini(void)
{
	int i;
	i = mod_remove(&modlinkage);
	if (i != 0) {
		return (i);
	}
	mac_fini_ops(&myri10ge_ops);
	mutex_destroy(&myri10ge_param_lock);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 *  This file uses MyriGE driver indentation.
 *
 * Local Variables:
 * c-file-style:"sun"
 * tab-width:8
 * End:
 */
