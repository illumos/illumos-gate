/*
 * sfe_util.c: general ethernet mac driver framework version 2.6
 *
 * Copyright (c) 2002-2008 Masayuki Murayama.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * System Header files.
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/vtrace.h>
#include <sys/ethernet.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stream.h>		/* required for MBLK* */
#include <sys/strsun.h>		/* required for mionack() */
#include <sys/byteorder.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>
#include <inet/common.h>
#include <inet/led.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/crc32.h>

#include <sys/note.h>

#include "sfe_mii.h"
#include "sfe_util.h"



extern char ident[];

/* Debugging support */
#ifdef GEM_DEBUG_LEVEL
static int gem_debug = GEM_DEBUG_LEVEL;
#define	DPRINTF(n, args)	if (gem_debug > (n)) cmn_err args
#else
#define	DPRINTF(n, args)
#undef ASSERT
#define	ASSERT(x)
#endif

#define	IOC_LINESIZE	0x40	/* Is it right for amd64? */

/*
 * Useful macros and typedefs
 */
#define	ROUNDUP(x, a)	(((x) + (a) - 1) & ~((a) - 1))

#define	GET_NET16(p)	((((uint8_t *)(p))[0] << 8)| ((uint8_t *)(p))[1])
#define	GET_ETHERTYPE(p)	GET_NET16(((uint8_t *)(p)) + ETHERADDRL*2)

#define	GET_IPTYPEv4(p)	(((uint8_t *)(p))[sizeof (struct ether_header) + 9])
#define	GET_IPTYPEv6(p)	(((uint8_t *)(p))[sizeof (struct ether_header) + 6])


#ifndef INT32_MAX
#define	INT32_MAX	0x7fffffff
#endif

#define	VTAG_OFF	(ETHERADDRL*2)
#ifndef VTAG_SIZE
#define	VTAG_SIZE	4
#endif
#ifndef VTAG_TPID
#define	VTAG_TPID	0x8100U
#endif

#define	GET_TXBUF(dp, sn)	\
	&(dp)->tx_buf[SLOT((dp)->tx_slots_base + (sn), (dp)->gc.gc_tx_buf_size)]

#define	TXFLAG_VTAG(flag)	\
	(((flag) & GEM_TXFLAG_VTAG) >> GEM_TXFLAG_VTAG_SHIFT)

#define	MAXPKTBUF(dp)	\
	((dp)->mtu + sizeof (struct ether_header) + VTAG_SIZE + ETHERFCSL)

#define	WATCH_INTERVAL_FAST	drv_usectohz(100*1000)	/* 100mS */
#define	BOOLEAN(x)	((x) != 0)

/*
 * Macros to distinct chip generation.
 */

/*
 * Private functions
 */
static void gem_mii_start(struct gem_dev *);
static void gem_mii_stop(struct gem_dev *);

/* local buffer management */
static void gem_nd_setup(struct gem_dev *dp);
static void gem_nd_cleanup(struct gem_dev *dp);
static int gem_alloc_memory(struct gem_dev *);
static void gem_free_memory(struct gem_dev *);
static void gem_init_rx_ring(struct gem_dev *);
static void gem_init_tx_ring(struct gem_dev *);
__INLINE__ static void gem_append_rxbuf(struct gem_dev *, struct rxbuf *);

static void gem_tx_timeout(struct gem_dev *);
static void gem_mii_link_watcher(struct gem_dev *dp);
static int gem_mac_init(struct gem_dev *dp);
static int gem_mac_start(struct gem_dev *dp);
static int gem_mac_stop(struct gem_dev *dp, uint_t flags);
static void gem_mac_ioctl(struct gem_dev *dp, queue_t *wq, mblk_t *mp);

static	struct ether_addr	gem_etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

int gem_speed_value[] = {10, 100, 1000};

/* ============================================================== */
/*
 * Misc runtime routines
 */
/* ============================================================== */
/*
 * Ether CRC calculation according to 21143 data sheet
 */
uint32_t
gem_ether_crc_le(const uint8_t *addr, int len)
{
	uint32_t	crc;

	CRC32(crc, addr, ETHERADDRL, 0xffffffffU, crc32_table);
	return (crc);
}

uint32_t
gem_ether_crc_be(const uint8_t *addr, int len)
{
	int		idx;
	int		bit;
	uint_t		data;
	uint32_t	crc;
#define	CRC32_POLY_BE	0x04c11db7

	crc = 0xffffffff;
	for (idx = 0; idx < len; idx++) {
		for (data = *addr++, bit = 0; bit < 8; bit++, data >>= 1) {
			crc = (crc << 1)
			    ^ ((((crc >> 31) ^ data) & 1) ? CRC32_POLY_BE : 0);
		}
	}
	return (crc);
#undef	CRC32_POLY_BE
}

int
gem_prop_get_int(struct gem_dev *dp, char *prop_template, int def_val)
{
	char	propname[32];

	(void) sprintf(propname, prop_template, dp->name);

	return (ddi_prop_get_int(DDI_DEV_T_ANY, dp->dip,
	    DDI_PROP_DONTPASS, propname, def_val));
}

static int
gem_population(uint32_t x)
{
	int	i;
	int	cnt;

	cnt = 0;
	for (i = 0; i < 32; i++) {
		if (x & (1 << i)) {
			cnt++;
		}
	}
	return (cnt);
}

#ifdef GEM_DEBUG_LEVEL
#ifdef GEM_DEBUG_VLAN
static void
gem_dump_packet(struct gem_dev *dp, char *title, mblk_t *mp,
    boolean_t check_cksum)
{
	char	msg[180];
	uint8_t	buf[18+20+20];
	uint8_t	*p;
	size_t	offset;
	uint_t	ethertype;
	uint_t	proto;
	uint_t	ipproto = 0;
	uint_t	iplen;
	uint_t	iphlen;
	uint_t	tcplen;
	uint_t	udplen;
	uint_t	cksum;
	int	rest;
	int	len;
	char	*bp;
	mblk_t	*tp;
	extern uint_t	ip_cksum(mblk_t *, int, uint32_t);

	msg[0] = 0;
	bp = msg;

	rest = sizeof (buf);
	offset = 0;
	for (tp = mp; tp; tp = tp->b_cont) {
		len = tp->b_wptr - tp->b_rptr;
		len = min(rest, len);
		bcopy(tp->b_rptr, &buf[offset], len);
		rest -= len;
		offset += len;
		if (rest == 0) {
			break;
		}
	}

	offset = 0;
	p = &buf[offset];

	/* ethernet address */
	sprintf(bp,
	    "ether: %02x:%02x:%02x:%02x:%02x:%02x"
	    " -> %02x:%02x:%02x:%02x:%02x:%02x",
	    p[6], p[7], p[8], p[9], p[10], p[11],
	    p[0], p[1], p[2], p[3], p[4], p[5]);
	bp = &msg[strlen(msg)];

	/* vlag tag and etherrtype */
	ethertype = GET_ETHERTYPE(p);
	if (ethertype == VTAG_TPID) {
		sprintf(bp, " vtag:0x%04x", GET_NET16(&p[14]));
		bp = &msg[strlen(msg)];

		offset += VTAG_SIZE;
		p = &buf[offset];
		ethertype = GET_ETHERTYPE(p);
	}
	sprintf(bp, " type:%04x", ethertype);
	bp = &msg[strlen(msg)];

	/* ethernet packet length */
	sprintf(bp, " mblklen:%d", msgdsize(mp));
	bp = &msg[strlen(msg)];
	if (mp->b_cont) {
		sprintf(bp, "(");
		bp = &msg[strlen(msg)];
		for (tp = mp; tp; tp = tp->b_cont) {
			if (tp == mp) {
				sprintf(bp, "%d", tp->b_wptr - tp->b_rptr);
			} else {
				sprintf(bp, "+%d", tp->b_wptr - tp->b_rptr);
			}
			bp = &msg[strlen(msg)];
		}
		sprintf(bp, ")");
		bp = &msg[strlen(msg)];
	}

	if (ethertype != ETHERTYPE_IP) {
		goto x;
	}

	/* ip address */
	offset += sizeof (struct ether_header);
	p = &buf[offset];
	ipproto = p[9];
	iplen = GET_NET16(&p[2]);
	sprintf(bp, ", ip: %d.%d.%d.%d -> %d.%d.%d.%d proto:%d iplen:%d",
	    p[12], p[13], p[14], p[15],
	    p[16], p[17], p[18], p[19],
	    ipproto, iplen);
	bp = (void *)&msg[strlen(msg)];

	iphlen = (p[0] & 0xf) * 4;

	/* cksum for psuedo header */
	cksum = *(uint16_t *)&p[12];
	cksum += *(uint16_t *)&p[14];
	cksum += *(uint16_t *)&p[16];
	cksum += *(uint16_t *)&p[18];
	cksum += BE_16(ipproto);

	/* tcp or udp protocol header */
	offset += iphlen;
	p = &buf[offset];
	if (ipproto == IPPROTO_TCP) {
		tcplen = iplen - iphlen;
		sprintf(bp, ", tcp: len:%d cksum:%x",
		    tcplen, GET_NET16(&p[16]));
		bp = (void *)&msg[strlen(msg)];

		if (check_cksum) {
			cksum += BE_16(tcplen);
			cksum = (uint16_t)ip_cksum(mp, offset, cksum);
			sprintf(bp, " (%s)",
			    (cksum == 0 || cksum == 0xffff) ? "ok" : "ng");
			bp = (void *)&msg[strlen(msg)];
		}
	} else if (ipproto == IPPROTO_UDP) {
		udplen = GET_NET16(&p[4]);
		sprintf(bp, ", udp: len:%d cksum:%x",
		    udplen, GET_NET16(&p[6]));
		bp = (void *)&msg[strlen(msg)];

		if (GET_NET16(&p[6]) && check_cksum) {
			cksum += *(uint16_t *)&p[4];
			cksum = (uint16_t)ip_cksum(mp, offset, cksum);
			sprintf(bp, " (%s)",
			    (cksum == 0 || cksum == 0xffff) ? "ok" : "ng");
			bp = (void *)&msg[strlen(msg)];
		}
	}
x:
	cmn_err(CE_CONT, "!%s: %s: %s", dp->name, title, msg);
}
#endif /* GEM_DEBUG_VLAN */
#endif /* GEM_DEBUG_LEVEL */

/* ============================================================== */
/*
 * IO cache flush
 */
/* ============================================================== */
__INLINE__ void
gem_rx_desc_dma_sync(struct gem_dev *dp, int head, int nslot, int how)
{
	int	n;
	int	m;
	int	rx_desc_unit_shift = dp->gc.gc_rx_desc_unit_shift;

	/* sync active descriptors */
	if (rx_desc_unit_shift < 0 || nslot == 0) {
		/* no rx descriptor ring */
		return;
	}

	n = dp->gc.gc_rx_ring_size - head;
	if ((m = nslot - n) > 0) {
		(void) ddi_dma_sync(dp->desc_dma_handle,
		    (off_t)0,
		    (size_t)(m << rx_desc_unit_shift),
		    how);
		nslot = n;
	}

	(void) ddi_dma_sync(dp->desc_dma_handle,
	    (off_t)(head << rx_desc_unit_shift),
	    (size_t)(nslot << rx_desc_unit_shift),
	    how);
}

__INLINE__ void
gem_tx_desc_dma_sync(struct gem_dev *dp, int head, int nslot, int how)
{
	int	n;
	int	m;
	int	tx_desc_unit_shift = dp->gc.gc_tx_desc_unit_shift;

	/* sync active descriptors */
	if (tx_desc_unit_shift < 0 || nslot == 0) {
		/* no tx descriptor ring */
		return;
	}

	n = dp->gc.gc_tx_ring_size - head;
	if ((m = nslot - n) > 0) {
		(void) ddi_dma_sync(dp->desc_dma_handle,
		    (off_t)(dp->tx_ring_dma - dp->rx_ring_dma),
		    (size_t)(m << tx_desc_unit_shift),
		    how);
		nslot = n;
	}

	(void) ddi_dma_sync(dp->desc_dma_handle,
	    (off_t)((head << tx_desc_unit_shift)
	    + (dp->tx_ring_dma - dp->rx_ring_dma)),
	    (size_t)(nslot << tx_desc_unit_shift),
	    how);
}

static void
gem_rx_start_default(struct gem_dev *dp, int head, int nslot)
{
	gem_rx_desc_dma_sync(dp,
	    SLOT(head, dp->gc.gc_rx_ring_size), nslot,
	    DDI_DMA_SYNC_FORDEV);
}

/* ============================================================== */
/*
 * Buffer management
 */
/* ============================================================== */
static void
gem_dump_txbuf(struct gem_dev *dp, int level, const char *title)
{
	cmn_err(level,
	    "!%s: %s: tx_active: %d[%d] %d[%d] (+%d), "
	    "tx_softq: %d[%d] %d[%d] (+%d), "
	    "tx_free: %d[%d] %d[%d] (+%d), "
	    "tx_desc: %d[%d] %d[%d] (+%d), "
	    "intr: %d[%d] (+%d), ",
	    dp->name, title,
	    dp->tx_active_head,
	    SLOT(dp->tx_active_head, dp->gc.gc_tx_buf_size),
	    dp->tx_active_tail,
	    SLOT(dp->tx_active_tail, dp->gc.gc_tx_buf_size),
	    dp->tx_active_tail - dp->tx_active_head,
	    dp->tx_softq_head,
	    SLOT(dp->tx_softq_head, dp->gc.gc_tx_buf_size),
	    dp->tx_softq_tail,
	    SLOT(dp->tx_softq_tail, dp->gc.gc_tx_buf_size),
	    dp->tx_softq_tail - dp->tx_softq_head,
	    dp->tx_free_head,
	    SLOT(dp->tx_free_head, dp->gc.gc_tx_buf_size),
	    dp->tx_free_tail,
	    SLOT(dp->tx_free_tail, dp->gc.gc_tx_buf_size),
	    dp->tx_free_tail - dp->tx_free_head,
	    dp->tx_desc_head,
	    SLOT(dp->tx_desc_head, dp->gc.gc_tx_ring_size),
	    dp->tx_desc_tail,
	    SLOT(dp->tx_desc_tail, dp->gc.gc_tx_ring_size),
	    dp->tx_desc_tail - dp->tx_desc_head,
	    dp->tx_desc_intr,
	    SLOT(dp->tx_desc_intr, dp->gc.gc_tx_ring_size),
	    dp->tx_desc_intr - dp->tx_desc_head);
}

static void
gem_free_rxbuf(struct rxbuf *rbp)
{
	struct gem_dev	*dp;

	dp = rbp->rxb_devp;
	ASSERT(mutex_owned(&dp->intrlock));
	rbp->rxb_next = dp->rx_buf_freelist;
	dp->rx_buf_freelist = rbp;
	dp->rx_buf_freecnt++;
}

/*
 * gem_get_rxbuf: supply a receive buffer which have been mapped into
 * DMA space.
 */
struct rxbuf *
gem_get_rxbuf(struct gem_dev *dp, int cansleep)
{
	struct rxbuf		*rbp;
	uint_t			count = 0;
	int			i;
	int			err;

	ASSERT(mutex_owned(&dp->intrlock));

	DPRINTF(3, (CE_CONT, "!gem_get_rxbuf: called freecnt:%d",
	    dp->rx_buf_freecnt));
	/*
	 * Get rx buffer management structure
	 */
	rbp = dp->rx_buf_freelist;
	if (rbp) {
		/* get one from the recycle list */
		ASSERT(dp->rx_buf_freecnt > 0);

		dp->rx_buf_freelist = rbp->rxb_next;
		dp->rx_buf_freecnt--;
		rbp->rxb_next = NULL;
		return (rbp);
	}

	/*
	 * Allocate a rx buffer management structure
	 */
	rbp = kmem_zalloc(sizeof (*rbp), cansleep ? KM_SLEEP : KM_NOSLEEP);
	if (rbp == NULL) {
		/* no memory */
		return (NULL);
	}

	/*
	 * Prepare a back pointer to the device structure which will be
	 * refered on freeing the buffer later.
	 */
	rbp->rxb_devp = dp;

	/* allocate a dma handle for rx data buffer */
	if ((err = ddi_dma_alloc_handle(dp->dip,
	    &dp->gc.gc_dma_attr_rxbuf,
	    (cansleep ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT),
	    NULL, &rbp->rxb_dh)) != DDI_SUCCESS) {

		cmn_err(CE_WARN,
		    "!%s: %s: ddi_dma_alloc_handle:1 failed, err=%d",
		    dp->name, __func__, err);

		kmem_free(rbp, sizeof (struct rxbuf));
		return (NULL);
	}

	/* allocate a bounce buffer for rx */
	if ((err = ddi_dma_mem_alloc(rbp->rxb_dh,
	    ROUNDUP(dp->rx_buf_len, IOC_LINESIZE),
	    &dp->gc.gc_buf_attr,
		/*
		 * if the nic requires a header at the top of receive buffers,
		 * it may access the rx buffer randomly.
		 */
	    (dp->gc.gc_rx_header_len > 0)
	    ? DDI_DMA_CONSISTENT : DDI_DMA_STREAMING,
	    cansleep ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT,
	    NULL,
	    &rbp->rxb_buf, &rbp->rxb_buf_len,
	    &rbp->rxb_bah)) != DDI_SUCCESS) {

		cmn_err(CE_WARN,
		    "!%s: %s: ddi_dma_mem_alloc: failed, err=%d",
		    dp->name, __func__, err);

		ddi_dma_free_handle(&rbp->rxb_dh);
		kmem_free(rbp, sizeof (struct rxbuf));
		return (NULL);
	}

	/* Mapin the bounce buffer into the DMA space */
	if ((err = ddi_dma_addr_bind_handle(rbp->rxb_dh,
	    NULL, rbp->rxb_buf, dp->rx_buf_len,
	    ((dp->gc.gc_rx_header_len > 0)
	    ?(DDI_DMA_RDWR | DDI_DMA_CONSISTENT)
	    :(DDI_DMA_READ | DDI_DMA_STREAMING)),
	    cansleep ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT,
	    NULL,
	    rbp->rxb_dmacookie,
	    &count)) != DDI_DMA_MAPPED) {

		ASSERT(err != DDI_DMA_INUSE);
		DPRINTF(0, (CE_WARN,
		    "!%s: ddi_dma_addr_bind_handle: failed, err=%d",
		    dp->name, __func__, err));

		/*
		 * we failed to allocate a dma resource
		 * for the rx bounce buffer.
		 */
		ddi_dma_mem_free(&rbp->rxb_bah);
		ddi_dma_free_handle(&rbp->rxb_dh);
		kmem_free(rbp, sizeof (struct rxbuf));
		return (NULL);
	}

	/* correct the rest of the DMA mapping */
	for (i = 1; i < count; i++) {
		ddi_dma_nextcookie(rbp->rxb_dh, &rbp->rxb_dmacookie[i]);
	}
	rbp->rxb_nfrags = count;

	/* Now we successfully prepared an rx buffer */
	dp->rx_buf_allocated++;

	return (rbp);
}

/* ============================================================== */
/*
 * memory resource management
 */
/* ============================================================== */
static int
gem_alloc_memory(struct gem_dev *dp)
{
	caddr_t			ring;
	caddr_t			buf;
	size_t			req_size;
	size_t			ring_len;
	size_t			buf_len;
	ddi_dma_cookie_t	ring_cookie;
	ddi_dma_cookie_t	buf_cookie;
	uint_t			count;
	int			i;
	int			err;
	struct txbuf		*tbp;
	int			tx_buf_len;
	ddi_dma_attr_t		dma_attr_txbounce;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	dp->desc_dma_handle = NULL;
	req_size = dp->rx_desc_size + dp->tx_desc_size + dp->gc.gc_io_area_size;

	if (req_size > 0) {
		/*
		 * Alloc RX/TX descriptors and a io area.
		 */
		if ((err = ddi_dma_alloc_handle(dp->dip,
		    &dp->gc.gc_dma_attr_desc,
		    DDI_DMA_SLEEP, NULL,
		    &dp->desc_dma_handle)) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "!%s: %s: ddi_dma_alloc_handle failed: %d",
			    dp->name, __func__, err);
			return (ENOMEM);
		}

		if ((err = ddi_dma_mem_alloc(dp->desc_dma_handle,
		    req_size, &dp->gc.gc_desc_attr,
		    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
		    &ring, &ring_len,
		    &dp->desc_acc_handle)) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "!%s: %s: ddi_dma_mem_alloc failed: "
			    "ret %d, request size: %d",
			    dp->name, __func__, err, (int)req_size);
			ddi_dma_free_handle(&dp->desc_dma_handle);
			return (ENOMEM);
		}

		if ((err = ddi_dma_addr_bind_handle(dp->desc_dma_handle,
		    NULL, ring, ring_len,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL,
		    &ring_cookie, &count)) != DDI_SUCCESS) {
			ASSERT(err != DDI_DMA_INUSE);
			cmn_err(CE_WARN,
			    "!%s: %s: ddi_dma_addr_bind_handle failed: %d",
			    dp->name, __func__, err);
			ddi_dma_mem_free(&dp->desc_acc_handle);
			ddi_dma_free_handle(&dp->desc_dma_handle);
			return (ENOMEM);
		}
		ASSERT(count == 1);

		/* set base of rx descriptor ring */
		dp->rx_ring = ring;
		dp->rx_ring_dma = ring_cookie.dmac_laddress;

		/* set base of tx descriptor ring */
		dp->tx_ring = dp->rx_ring + dp->rx_desc_size;
		dp->tx_ring_dma = dp->rx_ring_dma + dp->rx_desc_size;

		/* set base of io area */
		dp->io_area = dp->tx_ring + dp->tx_desc_size;
		dp->io_area_dma = dp->tx_ring_dma + dp->tx_desc_size;
	}

	/*
	 * Prepare DMA resources for tx packets
	 */
	ASSERT(dp->gc.gc_tx_buf_size > 0);

	/* Special dma attribute for tx bounce buffers */
	dma_attr_txbounce = dp->gc.gc_dma_attr_txbuf;
	dma_attr_txbounce.dma_attr_sgllen = 1;
	dma_attr_txbounce.dma_attr_align =
	    max(dma_attr_txbounce.dma_attr_align, IOC_LINESIZE);

	/* Size for tx bounce buffers must be max tx packet size. */
	tx_buf_len = MAXPKTBUF(dp);
	tx_buf_len = ROUNDUP(tx_buf_len, IOC_LINESIZE);

	ASSERT(tx_buf_len >= ETHERMAX+ETHERFCSL);

	for (i = 0, tbp = dp->tx_buf;
	    i < dp->gc.gc_tx_buf_size; i++, tbp++) {

		/* setup bounce buffers for tx packets */
		if ((err = ddi_dma_alloc_handle(dp->dip,
		    &dma_attr_txbounce,
		    DDI_DMA_SLEEP, NULL,
		    &tbp->txb_bdh)) != DDI_SUCCESS) {

			cmn_err(CE_WARN,
		    "!%s: %s ddi_dma_alloc_handle for bounce buffer failed:"
			    " err=%d, i=%d",
			    dp->name, __func__, err, i);
			goto err_alloc_dh;
		}

		if ((err = ddi_dma_mem_alloc(tbp->txb_bdh,
		    tx_buf_len,
		    &dp->gc.gc_buf_attr,
		    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
		    &buf, &buf_len,
		    &tbp->txb_bah)) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
		    "!%s: %s: ddi_dma_mem_alloc for bounce buffer failed"
			    "ret %d, request size %d",
			    dp->name, __func__, err, tx_buf_len);
			ddi_dma_free_handle(&tbp->txb_bdh);
			goto err_alloc_dh;
		}

		if ((err = ddi_dma_addr_bind_handle(tbp->txb_bdh,
		    NULL, buf, buf_len,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    DDI_DMA_SLEEP, NULL,
		    &buf_cookie, &count)) != DDI_SUCCESS) {
				ASSERT(err != DDI_DMA_INUSE);
				cmn_err(CE_WARN,
	"!%s: %s: ddi_dma_addr_bind_handle for bounce buffer failed: %d",
				    dp->name, __func__, err);
				ddi_dma_mem_free(&tbp->txb_bah);
				ddi_dma_free_handle(&tbp->txb_bdh);
				goto err_alloc_dh;
		}
		ASSERT(count == 1);
		tbp->txb_buf = buf;
		tbp->txb_buf_dma = buf_cookie.dmac_laddress;
	}

	return (0);

err_alloc_dh:
	if (dp->gc.gc_tx_buf_size > 0) {
		while (i-- > 0) {
			(void) ddi_dma_unbind_handle(dp->tx_buf[i].txb_bdh);
			ddi_dma_mem_free(&dp->tx_buf[i].txb_bah);
			ddi_dma_free_handle(&dp->tx_buf[i].txb_bdh);
		}
	}

	if (dp->desc_dma_handle) {
		(void) ddi_dma_unbind_handle(dp->desc_dma_handle);
		ddi_dma_mem_free(&dp->desc_acc_handle);
		ddi_dma_free_handle(&dp->desc_dma_handle);
		dp->desc_dma_handle = NULL;
	}

	return (ENOMEM);
}

static void
gem_free_memory(struct gem_dev *dp)
{
	int		i;
	struct rxbuf	*rbp;
	struct txbuf	*tbp;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* Free TX/RX descriptors and tx padding buffer */
	if (dp->desc_dma_handle) {
		(void) ddi_dma_unbind_handle(dp->desc_dma_handle);
		ddi_dma_mem_free(&dp->desc_acc_handle);
		ddi_dma_free_handle(&dp->desc_dma_handle);
		dp->desc_dma_handle = NULL;
	}

	/* Free dma handles for Tx */
	for (i = dp->gc.gc_tx_buf_size, tbp = dp->tx_buf; i--; tbp++) {
		/* Free bounce buffer associated to each txbuf */
		(void) ddi_dma_unbind_handle(tbp->txb_bdh);
		ddi_dma_mem_free(&tbp->txb_bah);
		ddi_dma_free_handle(&tbp->txb_bdh);
	}

	/* Free rx buffer */
	while ((rbp = dp->rx_buf_freelist) != NULL) {

		ASSERT(dp->rx_buf_freecnt > 0);

		dp->rx_buf_freelist = rbp->rxb_next;
		dp->rx_buf_freecnt--;

		/* release DMA mapping */
		ASSERT(rbp->rxb_dh != NULL);

		/* free dma handles for rx bbuf */
		/* it has dma mapping always */
		ASSERT(rbp->rxb_nfrags > 0);
		(void) ddi_dma_unbind_handle(rbp->rxb_dh);

		/* free the associated bounce buffer and dma handle */
		ASSERT(rbp->rxb_bah != NULL);
		ddi_dma_mem_free(&rbp->rxb_bah);
		/* free the associated dma handle */
		ddi_dma_free_handle(&rbp->rxb_dh);

		/* free the base memory of rx buffer management */
		kmem_free(rbp, sizeof (struct rxbuf));
	}
}

/* ============================================================== */
/*
 * Rx/Tx descriptor slot management
 */
/* ============================================================== */
/*
 * Initialize an empty rx ring.
 */
static void
gem_init_rx_ring(struct gem_dev *dp)
{
	int		i;
	int		rx_ring_size = dp->gc.gc_rx_ring_size;

	DPRINTF(1, (CE_CONT, "!%s: %s ring_size:%d, buf_max:%d",
	    dp->name, __func__,
	    rx_ring_size, dp->gc.gc_rx_buf_max));

	/* make a physical chain of rx descriptors */
	for (i = 0; i < rx_ring_size; i++) {
		(*dp->gc.gc_rx_desc_init)(dp, i);
	}
	gem_rx_desc_dma_sync(dp, 0, rx_ring_size, DDI_DMA_SYNC_FORDEV);

	dp->rx_active_head = (seqnum_t)0;
	dp->rx_active_tail = (seqnum_t)0;

	ASSERT(dp->rx_buf_head == (struct rxbuf *)NULL);
	ASSERT(dp->rx_buf_tail == (struct rxbuf *)NULL);
}

/*
 * Prepare rx buffers and put them into the rx buffer/descriptor ring.
 */
static void
gem_prepare_rx_buf(struct gem_dev *dp)
{
	int		i;
	int		nrbuf;
	struct rxbuf	*rbp;

	ASSERT(mutex_owned(&dp->intrlock));

	/* Now we have no active buffers in rx ring */

	nrbuf = min(dp->gc.gc_rx_ring_size, dp->gc.gc_rx_buf_max);
	for (i = 0; i < nrbuf; i++) {
		if ((rbp = gem_get_rxbuf(dp, B_TRUE)) == NULL) {
			break;
		}
		gem_append_rxbuf(dp, rbp);
	}

	gem_rx_desc_dma_sync(dp,
	    0, dp->gc.gc_rx_ring_size, DDI_DMA_SYNC_FORDEV);
}

/*
 * Reclaim active rx buffers in rx buffer ring.
 */
static void
gem_clean_rx_buf(struct gem_dev *dp)
{
	int		i;
	struct rxbuf	*rbp;
	int		rx_ring_size = dp->gc.gc_rx_ring_size;
#ifdef GEM_DEBUG_LEVEL
	int		total;
#endif
	ASSERT(mutex_owned(&dp->intrlock));

	DPRINTF(2, (CE_CONT, "!%s: %s: %d buffers are free",
	    dp->name, __func__, dp->rx_buf_freecnt));
	/*
	 * clean up HW descriptors
	 */
	for (i = 0; i < rx_ring_size; i++) {
		(*dp->gc.gc_rx_desc_clean)(dp, i);
	}
	gem_rx_desc_dma_sync(dp, 0, rx_ring_size, DDI_DMA_SYNC_FORDEV);

#ifdef GEM_DEBUG_LEVEL
	total = 0;
#endif
	/*
	 * Reclaim allocated rx buffers
	 */
	while ((rbp = dp->rx_buf_head) != NULL) {
#ifdef GEM_DEBUG_LEVEL
		total++;
#endif
		/* remove the first one from rx buffer list */
		dp->rx_buf_head = rbp->rxb_next;

		/* recycle the rxbuf */
		gem_free_rxbuf(rbp);
	}
	dp->rx_buf_tail = (struct rxbuf *)NULL;

	DPRINTF(2, (CE_CONT,
	    "!%s: %s: %d buffers freeed, total: %d free",
	    dp->name, __func__, total, dp->rx_buf_freecnt));
}

/*
 * Initialize an empty transmit buffer/descriptor ring
 */
static void
gem_init_tx_ring(struct gem_dev *dp)
{
	int		i;
	int		tx_buf_size = dp->gc.gc_tx_buf_size;
	int		tx_ring_size = dp->gc.gc_tx_ring_size;

	DPRINTF(2, (CE_CONT, "!%s: %s: ring_size:%d, buf_size:%d",
	    dp->name, __func__,
	    dp->gc.gc_tx_ring_size, dp->gc.gc_tx_buf_size));

	ASSERT(!dp->mac_active);

	/* initialize active list and free list */
	dp->tx_slots_base =
	    SLOT(dp->tx_slots_base + dp->tx_softq_head, tx_buf_size);
	dp->tx_softq_tail -= dp->tx_softq_head;
	dp->tx_softq_head = (seqnum_t)0;

	dp->tx_active_head = dp->tx_softq_head;
	dp->tx_active_tail = dp->tx_softq_head;

	dp->tx_free_head   = dp->tx_softq_tail;
	dp->tx_free_tail   = dp->gc.gc_tx_buf_limit;

	dp->tx_desc_head = (seqnum_t)0;
	dp->tx_desc_tail = (seqnum_t)0;
	dp->tx_desc_intr = (seqnum_t)0;

	for (i = 0; i < tx_ring_size; i++) {
		(*dp->gc.gc_tx_desc_init)(dp, i);
	}
	gem_tx_desc_dma_sync(dp, 0, tx_ring_size, DDI_DMA_SYNC_FORDEV);
}

__INLINE__
static void
gem_txbuf_free_dma_resources(struct txbuf *tbp)
{
	if (tbp->txb_mp) {
		freemsg(tbp->txb_mp);
		tbp->txb_mp = NULL;
	}
	tbp->txb_nfrags = 0;
	tbp->txb_flag = 0;
}
#pragma inline(gem_txbuf_free_dma_resources)

/*
 * reclaim active tx buffers and reset positions in tx rings.
 */
static void
gem_clean_tx_buf(struct gem_dev *dp)
{
	int		i;
	seqnum_t	head;
	seqnum_t	tail;
	seqnum_t	sn;
	struct txbuf	*tbp;
	int		tx_ring_size = dp->gc.gc_tx_ring_size;
#ifdef GEM_DEBUG_LEVEL
	int		err;
#endif

	ASSERT(!dp->mac_active);
	ASSERT(dp->tx_busy == 0);
	ASSERT(dp->tx_softq_tail == dp->tx_free_head);

	/*
	 * clean up all HW descriptors
	 */
	for (i = 0; i < tx_ring_size; i++) {
		(*dp->gc.gc_tx_desc_clean)(dp, i);
	}
	gem_tx_desc_dma_sync(dp, 0, tx_ring_size, DDI_DMA_SYNC_FORDEV);

	/* dequeue all active and loaded buffers */
	head = dp->tx_active_head;
	tail = dp->tx_softq_tail;

	ASSERT(dp->tx_free_head - head >= 0);
	tbp = GET_TXBUF(dp, head);
	for (sn = head; sn != tail; sn++) {
		gem_txbuf_free_dma_resources(tbp);
		ASSERT(tbp->txb_mp == NULL);
		dp->stats.errxmt++;
		tbp = tbp->txb_next;
	}

#ifdef GEM_DEBUG_LEVEL
	/* ensure no dma resources for tx are not in use now */
	err = 0;
	while (sn != head + dp->gc.gc_tx_buf_size) {
		if (tbp->txb_mp || tbp->txb_nfrags) {
			DPRINTF(0, (CE_CONT,
			    "%s: %s: sn:%d[%d] mp:%p nfrags:%d",
			    dp->name, __func__,
			    sn, SLOT(sn, dp->gc.gc_tx_buf_size),
			    tbp->txb_mp, tbp->txb_nfrags));
			err = 1;
		}
		sn++;
		tbp = tbp->txb_next;
	}

	if (err) {
		gem_dump_txbuf(dp, CE_WARN,
		    "gem_clean_tx_buf: tbp->txb_mp != NULL");
	}
#endif
	/* recycle buffers, now no active tx buffers in the ring */
	dp->tx_free_tail += tail - head;
	ASSERT(dp->tx_free_tail == dp->tx_free_head + dp->gc.gc_tx_buf_limit);

	/* fix positions in tx buffer rings */
	dp->tx_active_head = dp->tx_free_head;
	dp->tx_active_tail = dp->tx_free_head;
	dp->tx_softq_head  = dp->tx_free_head;
	dp->tx_softq_tail  = dp->tx_free_head;
}

/*
 * Reclaim transmitted buffers from tx buffer/descriptor ring.
 */
__INLINE__ int
gem_reclaim_txbuf(struct gem_dev *dp)
{
	struct txbuf	*tbp;
	uint_t		txstat;
	int		err = GEM_SUCCESS;
	seqnum_t	head;
	seqnum_t	tail;
	seqnum_t	sn;
	seqnum_t	desc_head;
	int		tx_ring_size = dp->gc.gc_tx_ring_size;
	uint_t (*tx_desc_stat)(struct gem_dev *dp,
	    int slot, int ndesc) = dp->gc.gc_tx_desc_stat;
	clock_t		now;

	now = ddi_get_lbolt();
	if (now == (clock_t)0) {
		/* make non-zero timestamp */
		now--;
	}

	mutex_enter(&dp->xmitlock);

	head = dp->tx_active_head;
	tail = dp->tx_active_tail;

#if GEM_DEBUG_LEVEL > 2
	if (head != tail) {
		cmn_err(CE_CONT, "!%s: %s: "
		    "testing active_head:%d[%d], active_tail:%d[%d]",
		    dp->name, __func__,
		    head, SLOT(head, dp->gc.gc_tx_buf_size),
		    tail, SLOT(tail, dp->gc.gc_tx_buf_size));
	}
#endif
#ifdef DEBUG
	if (dp->tx_reclaim_busy == 0) {
		/* check tx buffer management consistency */
		ASSERT(dp->tx_free_tail - dp->tx_active_head
		    == dp->gc.gc_tx_buf_limit);
		/* EMPTY */
	}
#endif
	dp->tx_reclaim_busy++;

	/* sync all active HW descriptors */
	gem_tx_desc_dma_sync(dp,
	    SLOT(dp->tx_desc_head, tx_ring_size),
	    dp->tx_desc_tail - dp->tx_desc_head,
	    DDI_DMA_SYNC_FORKERNEL);

	tbp = GET_TXBUF(dp, head);
	desc_head = dp->tx_desc_head;
	for (sn = head; sn != tail;
	    dp->tx_active_head = (++sn), tbp = tbp->txb_next) {
		int	ndescs;

		ASSERT(tbp->txb_desc == desc_head);

		ndescs = tbp->txb_ndescs;
		if (ndescs == 0) {
			/* skip errored descriptors */
			continue;
		}
		txstat = (*tx_desc_stat)(dp,
		    SLOT(tbp->txb_desc, tx_ring_size), ndescs);

		if (txstat == 0) {
			/* not transmitted yet */
			break;
		}

		if (!dp->tx_blocked && (tbp->txb_flag & GEM_TXFLAG_INTR)) {
			dp->tx_blocked = now;
		}

		ASSERT(txstat & (GEM_TX_DONE | GEM_TX_ERR));

		if (txstat & GEM_TX_ERR) {
			err = GEM_FAILURE;
			cmn_err(CE_WARN, "!%s: tx error at desc %d[%d]",
			    dp->name, sn, SLOT(sn, tx_ring_size));
		}
#if GEM_DEBUG_LEVEL > 4
		if (now - tbp->txb_stime >= 50) {
			cmn_err(CE_WARN, "!%s: tx delay while %d mS",
			    dp->name, (now - tbp->txb_stime)*10);
		}
#endif
		/* free transmitted descriptors */
		desc_head += ndescs;
	}

	if (dp->tx_desc_head != desc_head) {
		/* we have reclaimed one or more tx buffers */
		dp->tx_desc_head = desc_head;

		/* If we passed the next interrupt position, update it */
		if (desc_head - dp->tx_desc_intr > 0) {
			dp->tx_desc_intr = desc_head;
		}
	}
	mutex_exit(&dp->xmitlock);

	/* free dma mapping resources associated with transmitted tx buffers */
	tbp = GET_TXBUF(dp, head);
	tail = sn;
#if GEM_DEBUG_LEVEL > 2
	if (head != tail) {
		cmn_err(CE_CONT, "%s: freeing head:%d[%d], tail:%d[%d]",
		    __func__,
		    head, SLOT(head, dp->gc.gc_tx_buf_size),
		    tail, SLOT(tail, dp->gc.gc_tx_buf_size));
	}
#endif
	for (sn = head; sn != tail; sn++, tbp = tbp->txb_next) {
		gem_txbuf_free_dma_resources(tbp);
	}

	/* recycle the tx buffers */
	mutex_enter(&dp->xmitlock);
	if (--dp->tx_reclaim_busy == 0) {
		/* we are the last thread who can update free tail */
#if GEM_DEBUG_LEVEL > 4
		/* check all resouces have been deallocated */
		sn = dp->tx_free_tail;
		tbp = GET_TXBUF(dp, new_tail);
		while (sn != dp->tx_active_head + dp->gc.gc_tx_buf_limit) {
			if (tbp->txb_nfrags) {
				/* in use */
				break;
			}
			ASSERT(tbp->txb_mp == NULL);
			tbp = tbp->txb_next;
			sn++;
		}
		ASSERT(dp->tx_active_head + dp->gc.gc_tx_buf_limit == sn);
#endif
		dp->tx_free_tail =
		    dp->tx_active_head + dp->gc.gc_tx_buf_limit;
	}
	if (!dp->mac_active) {
		/* someone may be waiting for me. */
		cv_broadcast(&dp->tx_drain_cv);
	}
#if GEM_DEBUG_LEVEL > 2
	cmn_err(CE_CONT, "!%s: %s: called, "
	    "free_head:%d free_tail:%d(+%d) added:%d",
	    dp->name, __func__,
	    dp->tx_free_head, dp->tx_free_tail,
	    dp->tx_free_tail - dp->tx_free_head, tail - head);
#endif
	mutex_exit(&dp->xmitlock);

	return (err);
}
#pragma inline(gem_reclaim_txbuf)


/*
 * Make tx descriptors in out-of-order manner
 */
static void
gem_tx_load_descs_oo(struct gem_dev *dp,
	seqnum_t start_slot, seqnum_t end_slot, uint64_t flags)
{
	seqnum_t	sn;
	struct txbuf	*tbp;
	int	tx_ring_size = dp->gc.gc_tx_ring_size;
	int	(*tx_desc_write)
	    (struct gem_dev *dp, int slot,
	    ddi_dma_cookie_t *dmacookie,
	    int frags, uint64_t flag) = dp->gc.gc_tx_desc_write;
	clock_t	now = ddi_get_lbolt();

	sn = start_slot;
	tbp = GET_TXBUF(dp, sn);
	do {
#if GEM_DEBUG_LEVEL > 1
		if (dp->tx_cnt < 100) {
			dp->tx_cnt++;
			flags |= GEM_TXFLAG_INTR;
		}
#endif
		/* write a tx descriptor */
		tbp->txb_desc = sn;
		tbp->txb_ndescs = (*tx_desc_write)(dp,
		    SLOT(sn, tx_ring_size),
		    tbp->txb_dmacookie,
		    tbp->txb_nfrags, flags | tbp->txb_flag);
		tbp->txb_stime = now;
		ASSERT(tbp->txb_ndescs == 1);

		flags = 0;
		sn++;
		tbp = tbp->txb_next;
	} while (sn != end_slot);
}

__INLINE__
static size_t
gem_setup_txbuf_copy(struct gem_dev *dp, mblk_t *mp, struct txbuf *tbp)
{
	size_t			min_pkt;
	caddr_t			bp;
	size_t			off;
	mblk_t			*tp;
	size_t			len;
	uint64_t		flag;

	ASSERT(tbp->txb_mp == NULL);

	/* we use bounce buffer for the packet */
	min_pkt = ETHERMIN;
	bp = tbp->txb_buf;
	off = 0;
	tp = mp;

	flag = tbp->txb_flag;
	if (flag & GEM_TXFLAG_SWVTAG) {
		/* need to increase min packet size */
		min_pkt += VTAG_SIZE;
		ASSERT((flag & GEM_TXFLAG_VTAG) == 0);
	}

	/* copy the rest */
	for (; tp; tp = tp->b_cont) {
		if ((len = (long)tp->b_wptr - (long)tp->b_rptr) > 0) {
			bcopy(tp->b_rptr, &bp[off], len);
			off += len;
		}
	}

	if (off < min_pkt &&
	    (min_pkt > ETHERMIN || !dp->gc.gc_tx_auto_pad)) {
		/*
		 * Extend the packet to minimum packet size explicitly.
		 * For software vlan packets, we shouldn't use tx autopad
		 * function because nics may not be aware of vlan.
		 * we must keep 46 octet of payload even if we use vlan.
		 */
		bzero(&bp[off], min_pkt - off);
		off = min_pkt;
	}

	(void) ddi_dma_sync(tbp->txb_bdh, (off_t)0, off, DDI_DMA_SYNC_FORDEV);

	tbp->txb_dmacookie[0].dmac_laddress = tbp->txb_buf_dma;
	tbp->txb_dmacookie[0].dmac_size = off;

	DPRINTF(2, (CE_CONT,
	    "!%s: %s: copy: addr:0x%llx len:0x%x, vtag:0x%04x, min_pkt:%d",
	    dp->name, __func__,
	    tbp->txb_dmacookie[0].dmac_laddress,
	    tbp->txb_dmacookie[0].dmac_size,
	    (flag & GEM_TXFLAG_VTAG) >> GEM_TXFLAG_VTAG_SHIFT,
	    min_pkt));

	/* save misc info */
	tbp->txb_mp = mp;
	tbp->txb_nfrags = 1;
#ifdef DEBUG_MULTIFRAGS
	if (dp->gc.gc_tx_max_frags >= 3 &&
	    tbp->txb_dmacookie[0].dmac_size > 16*3) {
		tbp->txb_dmacookie[1].dmac_laddress =
		    tbp->txb_dmacookie[0].dmac_laddress + 16;
		tbp->txb_dmacookie[2].dmac_laddress =
		    tbp->txb_dmacookie[1].dmac_laddress + 16;

		tbp->txb_dmacookie[2].dmac_size =
		    tbp->txb_dmacookie[0].dmac_size - 16*2;
		tbp->txb_dmacookie[1].dmac_size = 16;
		tbp->txb_dmacookie[0].dmac_size = 16;
		tbp->txb_nfrags  = 3;
	}
#endif
	return (off);
}
#pragma inline(gem_setup_txbuf_copy)

__INLINE__
static void
gem_tx_start_unit(struct gem_dev *dp)
{
	seqnum_t	head;
	seqnum_t	tail;
	struct txbuf	*tbp_head;
	struct txbuf	*tbp_tail;

	/* update HW descriptors from soft queue */
	ASSERT(mutex_owned(&dp->xmitlock));
	ASSERT(dp->tx_softq_head == dp->tx_active_tail);

	head = dp->tx_softq_head;
	tail = dp->tx_softq_tail;

	DPRINTF(1, (CE_CONT,
	    "%s: %s: called, softq %d %d[+%d], desc %d %d[+%d]",
	    dp->name, __func__, head, tail, tail - head,
	    dp->tx_desc_head, dp->tx_desc_tail,
	    dp->tx_desc_tail - dp->tx_desc_head));

	ASSERT(tail - head > 0);

	dp->tx_desc_tail = tail;

	tbp_head = GET_TXBUF(dp, head);
	tbp_tail = GET_TXBUF(dp, tail - 1);

	ASSERT(tbp_tail->txb_desc + tbp_tail->txb_ndescs == dp->tx_desc_tail);

	dp->gc.gc_tx_start(dp,
	    SLOT(tbp_head->txb_desc, dp->gc.gc_tx_ring_size),
	    tbp_tail->txb_desc + tbp_tail->txb_ndescs - tbp_head->txb_desc);

	/* advance softq head and active tail */
	dp->tx_softq_head = dp->tx_active_tail = tail;
}
#pragma inline(gem_tx_start_unit)

#ifdef GEM_DEBUG_LEVEL
static int gem_send_cnt[10];
#endif
#define	PKT_MIN_SIZE	(sizeof (struct ether_header) + 10 + VTAG_SIZE)
#define	EHLEN	(sizeof (struct ether_header))
/*
 * check ether packet type and ip protocol
 */
static uint64_t
gem_txbuf_options(struct gem_dev *dp, mblk_t *mp, uint8_t *bp)
{
	mblk_t		*tp;
	ssize_t		len;
	uint_t		vtag;
	int		off;
	uint64_t	flag;

	flag = 0ULL;

	/*
	 * prepare continuous header of the packet for protocol analysis
	 */
	if ((long)mp->b_wptr - (long)mp->b_rptr < PKT_MIN_SIZE) {
		/* we use work buffer to copy mblk */
		for (tp = mp, off = 0;
		    tp && (off < PKT_MIN_SIZE);
		    tp = tp->b_cont, off += len) {
			len = (long)tp->b_wptr - (long)tp->b_rptr;
			len = min(len, PKT_MIN_SIZE - off);
			bcopy(tp->b_rptr, &bp[off], len);
		}
	} else {
		/* we can use mblk without copy */
		bp = mp->b_rptr;
	}

	/* process vlan tag for GLD v3 */
	if (GET_NET16(&bp[VTAG_OFF]) == VTAG_TPID) {
		if (dp->misc_flag & GEM_VLAN_HARD) {
			vtag = GET_NET16(&bp[VTAG_OFF + 2]);
			ASSERT(vtag);
			flag |= vtag << GEM_TXFLAG_VTAG_SHIFT;
		} else {
			flag |= GEM_TXFLAG_SWVTAG;
		}
	}
	return (flag);
}
#undef EHLEN
#undef PKT_MIN_SIZE
/*
 * gem_send_common is an exported function because hw depend routines may
 * use it for sending control frames like setup frames for 2114x chipset.
 */
mblk_t *
gem_send_common(struct gem_dev *dp, mblk_t *mp_head, uint32_t flags)
{
	int			nmblk;
	int			avail;
	mblk_t			*tp;
	mblk_t			*mp;
	int			i;
	struct txbuf		*tbp;
	seqnum_t		head;
	uint64_t		load_flags;
	uint64_t		len_total = 0;
	uint32_t		bcast = 0;
	uint32_t		mcast = 0;

	ASSERT(mp_head != NULL);

	mp = mp_head;
	nmblk = 1;
	while ((mp = mp->b_next) != NULL) {
		nmblk++;
	}
#ifdef GEM_DEBUG_LEVEL
	gem_send_cnt[0]++;
	gem_send_cnt[min(nmblk, 9)]++;
#endif
	/*
	 * Aquire resources
	 */
	mutex_enter(&dp->xmitlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->xmitlock);
		mp = mp_head;
		while (mp) {
			tp = mp->b_next;
			freemsg(mp);
			mp = tp;
		}
		return (NULL);
	}

	if (!dp->mac_active && (flags & GEM_SEND_CTRL) == 0) {
		/* don't send data packets while mac isn't active */
		/* XXX - should we discard packets? */
		mutex_exit(&dp->xmitlock);
		return (mp_head);
	}

	/* allocate free slots */
	head = dp->tx_free_head;
	avail = dp->tx_free_tail - head;

	DPRINTF(2, (CE_CONT,
	    "!%s: %s: called, free_head:%d free_tail:%d(+%d) req:%d",
	    dp->name, __func__,
	    dp->tx_free_head, dp->tx_free_tail, avail, nmblk));

	avail = min(avail, dp->tx_max_packets);

	if (nmblk > avail) {
		if (avail == 0) {
			/* no resources; short cut */
			DPRINTF(2, (CE_CONT, "!%s: no resources", __func__));
			dp->tx_max_packets = max(dp->tx_max_packets - 1, 1);
			goto done;
		}
		nmblk = avail;
	}

	dp->tx_free_head = head + nmblk;
	load_flags = ((dp->tx_busy++) == 0) ? GEM_TXFLAG_HEAD : 0;

	/* update last interrupt position if tx buffers exhaust.  */
	if (nmblk == avail) {
		tbp = GET_TXBUF(dp, head + avail - 1);
		tbp->txb_flag = GEM_TXFLAG_INTR;
		dp->tx_desc_intr = head + avail;
	}
	mutex_exit(&dp->xmitlock);

	tbp = GET_TXBUF(dp, head);

	for (i = nmblk; i > 0; i--, tbp = tbp->txb_next) {
		uint8_t		*bp;
		uint64_t	txflag;

		/* remove one from the mblk list */
		ASSERT(mp_head != NULL);
		mp = mp_head;
		mp_head = mp_head->b_next;
		mp->b_next = NULL;

		/* statistics for non-unicast packets */
		bp = mp->b_rptr;
		if ((bp[0] & 1) && (flags & GEM_SEND_CTRL) == 0) {
			if (bcmp(bp, gem_etherbroadcastaddr.ether_addr_octet,
			    ETHERADDRL) == 0) {
				bcast++;
			} else {
				mcast++;
			}
		}

		/* save misc info */
		txflag = tbp->txb_flag;
		txflag |= (flags & GEM_SEND_CTRL) << GEM_TXFLAG_PRIVATE_SHIFT;
		txflag |= gem_txbuf_options(dp, mp, (uint8_t *)tbp->txb_buf);
		tbp->txb_flag = txflag;

		len_total += gem_setup_txbuf_copy(dp, mp, tbp);
	}

	(void) gem_tx_load_descs_oo(dp, head, head + nmblk, load_flags);

	/* Append the tbp at the tail of the active tx buffer list */
	mutex_enter(&dp->xmitlock);

	if ((--dp->tx_busy) == 0) {
		/* extend the tail of softq, as new packets have been ready. */
		dp->tx_softq_tail = dp->tx_free_head;

		if (!dp->mac_active && (flags & GEM_SEND_CTRL) == 0) {
			/*
			 * The device status has changed while we are
			 * preparing tx buf.
			 * As we are the last one that make tx non-busy.
			 * wake up someone who may wait for us.
			 */
			cv_broadcast(&dp->tx_drain_cv);
		} else {
			ASSERT(dp->tx_softq_tail - dp->tx_softq_head > 0);
			gem_tx_start_unit(dp);
		}
	}
	dp->stats.obytes += len_total;
	dp->stats.opackets += nmblk;
	dp->stats.obcast += bcast;
	dp->stats.omcast += mcast;
done:
	mutex_exit(&dp->xmitlock);

	return (mp_head);
}

/* ========================================================== */
/*
 * error detection and restart routines
 */
/* ========================================================== */
int
gem_restart_nic(struct gem_dev *dp, uint_t flags)
{
	ASSERT(mutex_owned(&dp->intrlock));

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));
#ifdef GEM_DEBUG_LEVEL
#if GEM_DEBUG_LEVEL > 1
	gem_dump_txbuf(dp, CE_CONT, "gem_restart_nic");
#endif
#endif

	if (dp->mac_suspended) {
		/* should we return GEM_FAILURE ? */
		return (GEM_FAILURE);
	}

	/*
	 * We should avoid calling any routines except xxx_chip_reset
	 * when we are resuming the system.
	 */
	if (dp->mac_active) {
		if (flags & GEM_RESTART_KEEP_BUF) {
			/* stop rx gracefully */
			dp->rxmode &= ~RXMODE_ENABLE;
			(void) (*dp->gc.gc_set_rx_filter)(dp);
		}
		(void) gem_mac_stop(dp, flags);
	}

	/* reset the chip. */
	if ((*dp->gc.gc_reset_chip)(dp) != GEM_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s: failed to reset chip",
		    dp->name, __func__);
		goto err;
	}

	if (gem_mac_init(dp) != GEM_SUCCESS) {
		goto err;
	}

	/* setup media mode if the link have been up */
	if (dp->mii_state == MII_STATE_LINKUP) {
		if ((dp->gc.gc_set_media)(dp) != GEM_SUCCESS) {
			goto err;
		}
	}

	/* setup mac address and enable rx filter */
	dp->rxmode |= RXMODE_ENABLE;
	if ((*dp->gc.gc_set_rx_filter)(dp) != GEM_SUCCESS) {
		goto err;
	}

	/*
	 * XXX - a panic happened because of linkdown.
	 * We must check mii_state here, because the link can be down just
	 * before the restart event happen. If the link is down now,
	 * gem_mac_start() will be called from gem_mii_link_check() when
	 * the link become up later.
	 */
	if (dp->mii_state == MII_STATE_LINKUP) {
		/* restart the nic */
		ASSERT(!dp->mac_active);
		(void) gem_mac_start(dp);
	}
	return (GEM_SUCCESS);
err:
	return (GEM_FAILURE);
}


static void
gem_tx_timeout(struct gem_dev *dp)
{
	clock_t		now;
	boolean_t	tx_sched;
	struct txbuf	*tbp;

	mutex_enter(&dp->intrlock);

	tx_sched = B_FALSE;
	now = ddi_get_lbolt();

	mutex_enter(&dp->xmitlock);
	if (!dp->mac_active || dp->mii_state != MII_STATE_LINKUP) {
		mutex_exit(&dp->xmitlock);
		goto schedule_next;
	}
	mutex_exit(&dp->xmitlock);

	/* reclaim transmitted buffers to check the trasmitter hangs or not. */
	if (gem_reclaim_txbuf(dp) != GEM_SUCCESS) {
		/* tx error happened, reset transmitter in the chip */
		(void) gem_restart_nic(dp, 0);
		tx_sched = B_TRUE;
		dp->tx_blocked = (clock_t)0;

		goto schedule_next;
	}

	mutex_enter(&dp->xmitlock);
	/* check if the transmitter thread is stuck */
	if (dp->tx_active_head == dp->tx_active_tail) {
		/* no tx buffer is loaded to the nic */
		if (dp->tx_blocked &&
		    now - dp->tx_blocked > dp->gc.gc_tx_timeout_interval) {
			gem_dump_txbuf(dp, CE_WARN,
			    "gem_tx_timeout: tx blocked");
			tx_sched = B_TRUE;
			dp->tx_blocked = (clock_t)0;
		}
		mutex_exit(&dp->xmitlock);
		goto schedule_next;
	}

	tbp = GET_TXBUF(dp, dp->tx_active_head);
	if (now - tbp->txb_stime < dp->gc.gc_tx_timeout) {
		mutex_exit(&dp->xmitlock);
		goto schedule_next;
	}
	mutex_exit(&dp->xmitlock);

	gem_dump_txbuf(dp, CE_WARN, "gem_tx_timeout: tx timeout");

	/* discard untransmitted packet and restart tx.  */
	(void) gem_restart_nic(dp, GEM_RESTART_NOWAIT);
	tx_sched = B_TRUE;
	dp->tx_blocked = (clock_t)0;

schedule_next:
	mutex_exit(&dp->intrlock);

	/* restart the downstream if needed */
	if (tx_sched) {
		mac_tx_update(dp->mh);
	}

	DPRINTF(4, (CE_CONT,
	    "!%s: blocked:%d active_head:%d active_tail:%d desc_intr:%d",
	    dp->name, BOOLEAN(dp->tx_blocked),
	    dp->tx_active_head, dp->tx_active_tail, dp->tx_desc_intr));
	dp->timeout_id =
	    timeout((void (*)(void *))gem_tx_timeout,
	    (void *)dp, dp->gc.gc_tx_timeout_interval);
}

/* ================================================================== */
/*
 * Interrupt handler
 */
/* ================================================================== */
__INLINE__
static void
gem_append_rxbuf(struct gem_dev *dp, struct rxbuf *rbp_head)
{
	struct rxbuf	*rbp;
	seqnum_t	tail;
	int		rx_ring_size = dp->gc.gc_rx_ring_size;

	ASSERT(rbp_head != NULL);
	ASSERT(mutex_owned(&dp->intrlock));

	DPRINTF(3, (CE_CONT, "!%s: %s: slot_head:%d, slot_tail:%d",
	    dp->name, __func__, dp->rx_active_head, dp->rx_active_tail));

	/*
	 * Add new buffers into active rx buffer list
	 */
	if (dp->rx_buf_head == NULL) {
		dp->rx_buf_head = rbp_head;
		ASSERT(dp->rx_buf_tail == NULL);
	} else {
		dp->rx_buf_tail->rxb_next = rbp_head;
	}

	tail = dp->rx_active_tail;
	for (rbp = rbp_head; rbp; rbp = rbp->rxb_next) {
		/* need to notify the tail for the lower layer */
		dp->rx_buf_tail = rbp;

		dp->gc.gc_rx_desc_write(dp,
		    SLOT(tail, rx_ring_size),
		    rbp->rxb_dmacookie,
		    rbp->rxb_nfrags);

		dp->rx_active_tail = tail = tail + 1;
	}
}
#pragma inline(gem_append_rxbuf)

mblk_t *
gem_get_packet_default(struct gem_dev *dp, struct rxbuf *rbp, size_t len)
{
	int		rx_header_len = dp->gc.gc_rx_header_len;
	uint8_t		*bp;
	mblk_t		*mp;

	/* allocate a new mblk */
	if (mp = allocb(len + VTAG_SIZE, BPRI_MED)) {
		ASSERT(mp->b_next == NULL);
		ASSERT(mp->b_cont == NULL);

		mp->b_rptr += VTAG_SIZE;
		bp = mp->b_rptr;
		mp->b_wptr = bp + len;

		/*
		 * flush the range of the entire buffer to invalidate
		 * all of corresponding dirty entries in iocache.
		 */
		(void) ddi_dma_sync(rbp->rxb_dh, rx_header_len,
		    0, DDI_DMA_SYNC_FORKERNEL);

		bcopy(rbp->rxb_buf + rx_header_len, bp, len);
	}
	return (mp);
}

#ifdef GEM_DEBUG_LEVEL
uint_t	gem_rx_pkts[17];
#endif


int
gem_receive(struct gem_dev *dp)
{
	uint64_t	len_total = 0;
	struct rxbuf	*rbp;
	mblk_t		*mp;
	int		cnt = 0;
	uint64_t	rxstat;
	struct rxbuf	*newbufs;
	struct rxbuf	**newbufs_tailp;
	mblk_t		*rx_head;
	mblk_t 		**rx_tailp;
	int		rx_ring_size = dp->gc.gc_rx_ring_size;
	seqnum_t	active_head;
	uint64_t	(*rx_desc_stat)(struct gem_dev *dp,
	    int slot, int ndesc);
	int		ethermin = ETHERMIN;
	int		ethermax = dp->mtu + sizeof (struct ether_header);
	int		rx_header_len = dp->gc.gc_rx_header_len;

	ASSERT(mutex_owned(&dp->intrlock));

	DPRINTF(3, (CE_CONT, "!%s: gem_receive: rx_buf_head:%p",
	    dp->name, dp->rx_buf_head));

	rx_desc_stat  = dp->gc.gc_rx_desc_stat;
	newbufs_tailp = &newbufs;
	rx_tailp = &rx_head;
	for (active_head = dp->rx_active_head;
	    (rbp = dp->rx_buf_head) != NULL; active_head++) {
		int		len;
		if (cnt == 0) {
			cnt = max(dp->poll_pkt_delay*2, 10);
			cnt = min(cnt,
			    dp->rx_active_tail - active_head);
			gem_rx_desc_dma_sync(dp,
			    SLOT(active_head, rx_ring_size),
			    cnt,
			    DDI_DMA_SYNC_FORKERNEL);
		}

		if (rx_header_len > 0) {
			(void) ddi_dma_sync(rbp->rxb_dh, 0,
			    rx_header_len, DDI_DMA_SYNC_FORKERNEL);
		}

		if (((rxstat = (*rx_desc_stat)(dp,
		    SLOT(active_head, rx_ring_size),
		    rbp->rxb_nfrags))
		    & (GEM_RX_DONE | GEM_RX_ERR)) == 0) {
			/* not received yet */
			break;
		}

		/* Remove the head of the rx buffer list */
		dp->rx_buf_head = rbp->rxb_next;
		cnt--;


		if (rxstat & GEM_RX_ERR) {
			goto next;
		}

		len = rxstat & GEM_RX_LEN;
		DPRINTF(3, (CE_CONT, "!%s: %s: rxstat:0x%llx, len:0x%x",
		    dp->name, __func__, rxstat, len));

		/*
		 * Copy the packet
		 */
		if ((mp = dp->gc.gc_get_packet(dp, rbp, len)) == NULL) {
			/* no memory, discard the packet */
			dp->stats.norcvbuf++;
			goto next;
		}

		/*
		 * Process VLAN tag
		 */
		ethermin = ETHERMIN;
		ethermax = dp->mtu + sizeof (struct ether_header);
		if (GET_NET16(mp->b_rptr + VTAG_OFF) == VTAG_TPID) {
			ethermax += VTAG_SIZE;
		}

		/* check packet size */
		if (len < ethermin) {
			dp->stats.errrcv++;
			dp->stats.runt++;
			freemsg(mp);
			goto next;
		}

		if (len > ethermax) {
			dp->stats.errrcv++;
			dp->stats.frame_too_long++;
			freemsg(mp);
			goto next;
		}

		len_total += len;

#ifdef GEM_DEBUG_VLAN
		if (GET_ETHERTYPE(mp->b_rptr) == VTAG_TPID) {
			gem_dump_packet(dp, (char *)__func__, mp, B_TRUE);
		}
#endif
		/* append received packet to temporaly rx buffer list */
		*rx_tailp = mp;
		rx_tailp  = &mp->b_next;

		if (mp->b_rptr[0] & 1) {
			if (bcmp(mp->b_rptr,
			    gem_etherbroadcastaddr.ether_addr_octet,
			    ETHERADDRL) == 0) {
				dp->stats.rbcast++;
			} else {
				dp->stats.rmcast++;
			}
		}
next:
		ASSERT(rbp != NULL);

		/* append new one to temporal new buffer list */
		*newbufs_tailp = rbp;
		newbufs_tailp  = &rbp->rxb_next;
	}

	/* advance rx_active_head */
	if ((cnt = active_head - dp->rx_active_head) > 0) {
		dp->stats.rbytes += len_total;
		dp->stats.rpackets += cnt;
	}
	dp->rx_active_head = active_head;

	/* terminate the working list */
	*newbufs_tailp = NULL;
	*rx_tailp = NULL;

	if (dp->rx_buf_head == NULL) {
		dp->rx_buf_tail = NULL;
	}

	DPRINTF(4, (CE_CONT, "%s: %s: cnt:%d, rx_head:%p",
	    dp->name, __func__, cnt, rx_head));

	if (newbufs) {
		/*
		 * fillfull rx list with new buffers
		 */
		seqnum_t	head;

		/* save current tail */
		head = dp->rx_active_tail;
		gem_append_rxbuf(dp, newbufs);

		/* call hw depend start routine if we have. */
		dp->gc.gc_rx_start(dp,
		    SLOT(head, rx_ring_size), dp->rx_active_tail - head);
	}

	if (rx_head) {
		/*
		 * send up received packets
		 */
		mutex_exit(&dp->intrlock);
		mac_rx(dp->mh, NULL, rx_head);
		mutex_enter(&dp->intrlock);
	}

#ifdef GEM_DEBUG_LEVEL
	gem_rx_pkts[min(cnt, sizeof (gem_rx_pkts)/sizeof (uint_t)-1)]++;
#endif
	return (cnt);
}

boolean_t
gem_tx_done(struct gem_dev *dp)
{
	boolean_t	tx_sched = B_FALSE;

	if (gem_reclaim_txbuf(dp) != GEM_SUCCESS) {
		(void) gem_restart_nic(dp, GEM_RESTART_KEEP_BUF);
		DPRINTF(2, (CE_CONT, "!%s: gem_tx_done: tx_desc: %d %d",
		    dp->name, dp->tx_active_head, dp->tx_active_tail));
		tx_sched = B_TRUE;
		goto x;
	}

	mutex_enter(&dp->xmitlock);

	/* XXX - we must not have any packets in soft queue */
	ASSERT(dp->tx_softq_head == dp->tx_softq_tail);
	/*
	 * If we won't have chance to get more free tx buffers, and blocked,
	 * it is worth to reschedule the downstream i.e. tx side.
	 */
	ASSERT(dp->tx_desc_intr - dp->tx_desc_head >= 0);
	if (dp->tx_blocked && dp->tx_desc_intr == dp->tx_desc_head) {
		/*
		 * As no further tx-done interrupts are scheduled, this
		 * is the last chance to kick tx side, which may be
		 * blocked now, otherwise the tx side never works again.
		 */
		tx_sched = B_TRUE;
		dp->tx_blocked = (clock_t)0;
		dp->tx_max_packets =
		    min(dp->tx_max_packets + 2, dp->gc.gc_tx_buf_limit);
	}

	mutex_exit(&dp->xmitlock);

	DPRINTF(3, (CE_CONT, "!%s: %s: ret: blocked:%d",
	    dp->name, __func__, BOOLEAN(dp->tx_blocked)));
x:
	return (tx_sched);
}

static uint_t
gem_intr(struct gem_dev	*dp)
{
	uint_t		ret;

	mutex_enter(&dp->intrlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->intrlock);
		return (DDI_INTR_UNCLAIMED);
	}
	dp->intr_busy = B_TRUE;

	ret = (*dp->gc.gc_interrupt)(dp);

	if (ret == DDI_INTR_UNCLAIMED) {
		dp->intr_busy = B_FALSE;
		mutex_exit(&dp->intrlock);
		return (ret);
	}

	if (!dp->mac_active) {
		cv_broadcast(&dp->tx_drain_cv);
	}


	dp->stats.intr++;
	dp->intr_busy = B_FALSE;

	mutex_exit(&dp->intrlock);

	if (ret & INTR_RESTART_TX) {
		DPRINTF(4, (CE_CONT, "!%s: calling mac_tx_update", dp->name));
		mac_tx_update(dp->mh);
		ret &= ~INTR_RESTART_TX;
	}
	return (ret);
}

static void
gem_intr_watcher(struct gem_dev *dp)
{
	(void) gem_intr(dp);

	/* schedule next call of tu_intr_watcher */
	dp->intr_watcher_id =
	    timeout((void (*)(void *))gem_intr_watcher, (void *)dp, 1);
}

/* ======================================================================== */
/*
 * MII support routines
 */
/* ======================================================================== */
static void
gem_choose_forcedmode(struct gem_dev *dp)
{
	/* choose media mode */
	if (dp->anadv_1000fdx || dp->anadv_1000hdx) {
		dp->speed = GEM_SPD_1000;
		dp->full_duplex = dp->anadv_1000fdx;
	} else if (dp->anadv_100fdx || dp->anadv_100t4) {
		dp->speed = GEM_SPD_100;
		dp->full_duplex = B_TRUE;
	} else if (dp->anadv_100hdx) {
		dp->speed = GEM_SPD_100;
		dp->full_duplex = B_FALSE;
	} else {
		dp->speed = GEM_SPD_10;
		dp->full_duplex = dp->anadv_10fdx;
	}
}

uint16_t
gem_mii_read(struct gem_dev *dp, uint_t reg)
{
	if ((dp->mii_status & MII_STATUS_MFPRMBLSUPR) == 0) {
		(*dp->gc.gc_mii_sync)(dp);
	}
	return ((*dp->gc.gc_mii_read)(dp, reg));
}

void
gem_mii_write(struct gem_dev *dp, uint_t reg, uint16_t val)
{
	if ((dp->mii_status & MII_STATUS_MFPRMBLSUPR) == 0) {
		(*dp->gc.gc_mii_sync)(dp);
	}
	(*dp->gc.gc_mii_write)(dp, reg, val);
}

#define	fc_cap_decode(x)	\
	((((x) & MII_ABILITY_PAUSE) ? 1 : 0) |	\
	(((x) & MII_ABILITY_ASMPAUSE) ? 2 : 0))

int
gem_mii_config_default(struct gem_dev *dp)
{
	uint16_t	mii_stat;
	uint16_t	val;
	static uint16_t fc_cap_encode[4] = {
		0, /* none */
		MII_ABILITY_PAUSE, /* symmetric */
		MII_ABILITY_ASMPAUSE, /* tx */
		MII_ABILITY_PAUSE | MII_ABILITY_ASMPAUSE, /* rx-symmetric */
	};

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/*
	 * Configure bits in advertisement register
	 */
	mii_stat = dp->mii_status;

	DPRINTF(1, (CE_CONT, "!%s: %s: MII_STATUS reg:%b",
	    dp->name, __func__, mii_stat, MII_STATUS_BITS));

	if ((mii_stat & MII_STATUS_ABILITY_TECH) == 0) {
		/* it's funny */
		cmn_err(CE_WARN, "!%s: wrong ability bits: mii_status:%b",
		    dp->name, mii_stat, MII_STATUS_BITS);
		return (GEM_FAILURE);
	}

	/* Do not change the rest of the ability bits in the advert reg */
	val = gem_mii_read(dp, MII_AN_ADVERT) & ~MII_ABILITY_ALL;

	DPRINTF(0, (CE_CONT,
	    "!%s: %s: 100T4:%d 100F:%d 100H:%d 10F:%d 10H:%d",
	    dp->name, __func__,
	    dp->anadv_100t4, dp->anadv_100fdx, dp->anadv_100hdx,
	    dp->anadv_10fdx, dp->anadv_10hdx));

	if (dp->anadv_100t4) {
		val |= MII_ABILITY_100BASE_T4;
	}
	if (dp->anadv_100fdx) {
		val |= MII_ABILITY_100BASE_TX_FD;
	}
	if (dp->anadv_100hdx) {
		val |= MII_ABILITY_100BASE_TX;
	}
	if (dp->anadv_10fdx) {
		val |= MII_ABILITY_10BASE_T_FD;
	}
	if (dp->anadv_10hdx) {
		val |= MII_ABILITY_10BASE_T;
	}

	/* set flow control capability */
	val |= fc_cap_encode[dp->anadv_flow_control];

	DPRINTF(0, (CE_CONT,
	    "!%s: %s: setting MII_AN_ADVERT reg:%b, mii_mode:%d, fc:%d",
	    dp->name, __func__, val, MII_ABILITY_BITS, dp->gc.gc_mii_mode,
	    dp->anadv_flow_control));

	gem_mii_write(dp, MII_AN_ADVERT, val);

	if (mii_stat & MII_STATUS_XSTATUS) {
		/*
		 * 1000Base-T GMII support
		 */
		if (!dp->anadv_autoneg) {
			/* enable manual configuration */
			val = MII_1000TC_CFG_EN;
		} else {
			val = 0;
			if (dp->anadv_1000fdx) {
				val |= MII_1000TC_ADV_FULL;
			}
			if (dp->anadv_1000hdx) {
				val |= MII_1000TC_ADV_HALF;
			}
		}
		DPRINTF(0, (CE_CONT,
		    "!%s: %s: setting MII_1000TC reg:%b",
		    dp->name, __func__, val, MII_1000TC_BITS));

		gem_mii_write(dp, MII_1000TC, val);
	}

	return (GEM_SUCCESS);
}

#define	GEM_LINKUP(dp)		mac_link_update((dp)->mh, LINK_STATE_UP)
#define	GEM_LINKDOWN(dp)	mac_link_update((dp)->mh, LINK_STATE_DOWN)

static uint8_t gem_fc_result[4 /* my cap */ ][4 /* lp cap */] = {
/*	 none	symm	tx	rx/symm */
/* none */
	{FLOW_CONTROL_NONE,
		FLOW_CONTROL_NONE,
			FLOW_CONTROL_NONE,
				FLOW_CONTROL_NONE},
/* sym */
	{FLOW_CONTROL_NONE,
		FLOW_CONTROL_SYMMETRIC,
			FLOW_CONTROL_NONE,
				FLOW_CONTROL_SYMMETRIC},
/* tx */
	{FLOW_CONTROL_NONE,
		FLOW_CONTROL_NONE,
			FLOW_CONTROL_NONE,
				FLOW_CONTROL_TX_PAUSE},
/* rx/symm */
	{FLOW_CONTROL_NONE,
		FLOW_CONTROL_SYMMETRIC,
			FLOW_CONTROL_RX_PAUSE,
				FLOW_CONTROL_SYMMETRIC},
};

static char *gem_fc_type[] = {
	"without",
	"with symmetric",
	"with tx",
	"with rx",
};

boolean_t
gem_mii_link_check(struct gem_dev *dp)
{
	uint16_t	old_mii_state;
	boolean_t	tx_sched = B_FALSE;
	uint16_t	status;
	uint16_t	advert;
	uint16_t	lpable;
	uint16_t	exp;
	uint16_t	ctl1000;
	uint16_t	stat1000;
	uint16_t	val;
	clock_t		now;
	clock_t		diff;
	int		linkdown_action;
	boolean_t	fix_phy = B_FALSE;

	now = ddi_get_lbolt();
	old_mii_state = dp->mii_state;

	DPRINTF(3, (CE_CONT, "!%s: %s: time:%d state:%d",
	    dp->name, __func__, now, dp->mii_state));

	diff = now - dp->mii_last_check;
	dp->mii_last_check = now;

	/*
	 * For NWAM, don't show linkdown state right
	 * after the system boots
	 */
	if (dp->linkup_delay > 0) {
		if (dp->linkup_delay > diff) {
			dp->linkup_delay -= diff;
		} else {
			/* link up timeout */
			dp->linkup_delay = -1;
		}
	}

next_nowait:
	switch (dp->mii_state) {
	case MII_STATE_UNKNOWN:
		/* power-up, DP83840 requires 32 sync bits */
		(*dp->gc.gc_mii_sync)(dp);
		goto reset_phy;

	case MII_STATE_RESETTING:
		dp->mii_timer -= diff;
		if (dp->mii_timer > 0) {
			/* don't read phy registers in resetting */
			dp->mii_interval = WATCH_INTERVAL_FAST;
			goto next;
		}

		/* Timer expired, ensure reset bit is not set */

		if (dp->mii_status & MII_STATUS_MFPRMBLSUPR) {
			/* some phys need sync bits after reset */
			(*dp->gc.gc_mii_sync)(dp);
		}
		val = gem_mii_read(dp, MII_CONTROL);
		if (val & MII_CONTROL_RESET) {
			cmn_err(CE_NOTE,
			    "!%s: time:%ld resetting phy not complete."
			    " mii_control:0x%b",
			    dp->name, ddi_get_lbolt(),
			    val, MII_CONTROL_BITS);
		}

		/* ensure neither isolated nor pwrdown nor auto-nego mode */
		/* XXX -- this operation is required for NS DP83840A. */
		gem_mii_write(dp, MII_CONTROL, 0);

		/* As resetting PHY has completed, configure PHY registers */
		if ((*dp->gc.gc_mii_config)(dp) != GEM_SUCCESS) {
			/* we failed to configure PHY. */
			goto reset_phy;
		}

		/* mii_config may disable autonegatiation */
		gem_choose_forcedmode(dp);

		dp->mii_lpable = 0;
		dp->mii_advert = 0;
		dp->mii_exp = 0;
		dp->mii_ctl1000 = 0;
		dp->mii_stat1000 = 0;
		dp->flow_control = FLOW_CONTROL_NONE;

		if (!dp->anadv_autoneg) {
			/* skip auto-negotiation phase */
			dp->mii_state = MII_STATE_MEDIA_SETUP;
			dp->mii_timer = 0;
			dp->mii_interval = 0;
			goto next_nowait;
		}

		/* Issue auto-negotiation command */
		goto autonego;

	case MII_STATE_AUTONEGOTIATING:
		/*
		 * Autonegotiation is in progress
		 */
		dp->mii_timer -= diff;
		if (dp->mii_timer -
		    (dp->gc.gc_mii_an_timeout
		    - dp->gc.gc_mii_an_wait) > 0) {
			/*
			 * wait for a while, typically autonegotiation
			 * completes in 2.3 - 2.5 sec.
			 */
			dp->mii_interval = WATCH_INTERVAL_FAST;
			goto next;
		}

		/* read PHY status */
		status = gem_mii_read(dp, MII_STATUS);
		DPRINTF(4, (CE_CONT,
		    "!%s: %s: called: mii_state:%d MII_STATUS reg:%b",
		    dp->name, __func__, dp->mii_state,
		    status, MII_STATUS_BITS));

		if (status & MII_STATUS_REMFAULT) {
			/*
			 * The link parnert told me something wrong happend.
			 * What do we do ?
			 */
			cmn_err(CE_CONT,
			    "!%s: auto-negotiation failed: remote fault",
			    dp->name);
			goto autonego;
		}

		if ((status & MII_STATUS_ANDONE) == 0) {
			if (dp->mii_timer <= 0) {
				/*
				 * Auto-negotiation was timed out,
				 * try again w/o resetting phy.
				 */
				if (!dp->mii_supress_msg) {
					cmn_err(CE_WARN,
				    "!%s: auto-negotiation failed: timeout",
					    dp->name);
					dp->mii_supress_msg = B_TRUE;
				}
				goto autonego;
			}
			/*
			 * Auto-negotiation is in progress. Wait.
			 */
			dp->mii_interval = dp->gc.gc_mii_an_watch_interval;
			goto next;
		}

		/*
		 * Auto-negotiation have completed.
		 * Assume linkdown and fall through.
		 */
		dp->mii_supress_msg = B_FALSE;
		dp->mii_state = MII_STATE_AN_DONE;
		DPRINTF(0, (CE_CONT,
		    "!%s: auto-negotiation completed, MII_STATUS:%b",
		    dp->name, status, MII_STATUS_BITS));

		if (dp->gc.gc_mii_an_delay > 0) {
			dp->mii_timer = dp->gc.gc_mii_an_delay;
			dp->mii_interval = drv_usectohz(20*1000);
			goto next;
		}

		dp->mii_timer = 0;
		diff = 0;
		goto next_nowait;

	case MII_STATE_AN_DONE:
		/*
		 * Auto-negotiation have done. Now we can set up media.
		 */
		dp->mii_timer -= diff;
		if (dp->mii_timer > 0) {
			/* wait for a while */
			dp->mii_interval = WATCH_INTERVAL_FAST;
			goto next;
		}

		/*
		 * set up the result of auto negotiation
		 */

		/*
		 * Read registers required to determin current
		 * duplex mode and media speed.
		 */
		if (dp->gc.gc_mii_an_delay > 0) {
			/*
			 * As the link watcher context has been suspended,
			 * 'status' is invalid. We must status register here
			 */
			status = gem_mii_read(dp, MII_STATUS);
		}
		advert = gem_mii_read(dp, MII_AN_ADVERT);
		lpable = gem_mii_read(dp, MII_AN_LPABLE);
		exp = gem_mii_read(dp, MII_AN_EXPANSION);
		if (exp == 0xffff) {
			/* some phys don't have exp register */
			exp = 0;
		}
		ctl1000  = 0;
		stat1000 = 0;
		if (dp->mii_status & MII_STATUS_XSTATUS) {
			ctl1000  = gem_mii_read(dp, MII_1000TC);
			stat1000 = gem_mii_read(dp, MII_1000TS);
		}
		dp->mii_lpable = lpable;
		dp->mii_advert = advert;
		dp->mii_exp = exp;
		dp->mii_ctl1000  = ctl1000;
		dp->mii_stat1000 = stat1000;

		cmn_err(CE_CONT,
		"!%s: auto-negotiation done, advert:%b, lpable:%b, exp:%b",
		    dp->name,
		    advert, MII_ABILITY_BITS,
		    lpable, MII_ABILITY_BITS,
		    exp, MII_AN_EXP_BITS);

		if (dp->mii_status & MII_STATUS_XSTATUS) {
			cmn_err(CE_CONT,
			    "! MII_1000TC:%b, MII_1000TS:%b",
			    ctl1000, MII_1000TC_BITS,
			    stat1000, MII_1000TS_BITS);
		}

		if (gem_population(lpable) <= 1 &&
		    (exp & MII_AN_EXP_LPCANAN) == 0) {
			if ((advert & MII_ABILITY_TECH) != lpable) {
				cmn_err(CE_WARN,
				    "!%s: but the link partnar doesn't seem"
				    " to have auto-negotiation capability."
				    " please check the link configuration.",
				    dp->name);
			}
			/*
			 * it should be result of parallel detection, which
			 * cannot detect duplex mode.
			 */
			if (lpable & MII_ABILITY_100BASE_TX) {
				/*
				 * we prefer full duplex mode for 100Mbps
				 * connection, if we can.
				 */
				lpable |= advert & MII_ABILITY_100BASE_TX_FD;
			}

			if ((advert & lpable) == 0 &&
			    lpable & MII_ABILITY_10BASE_T) {
				lpable |= advert & MII_ABILITY_10BASE_T_FD;
			}
			/*
			 * as the link partnar isn't auto-negotiatable, use
			 * fixed mode temporally.
			 */
			fix_phy = B_TRUE;
		} else if (lpable == 0) {
			cmn_err(CE_WARN, "!%s: wrong lpable.", dp->name);
			goto reset_phy;
		}
		/*
		 * configure current link mode according to AN priority.
		 */
		val = advert & lpable;
		if ((ctl1000 & MII_1000TC_ADV_FULL) &&
		    (stat1000 & MII_1000TS_LP_FULL)) {
			/* 1000BaseT & full duplex */
			dp->speed	 = GEM_SPD_1000;
			dp->full_duplex  = B_TRUE;
		} else if ((ctl1000 & MII_1000TC_ADV_HALF) &&
		    (stat1000 & MII_1000TS_LP_HALF)) {
			/* 1000BaseT & half duplex */
			dp->speed = GEM_SPD_1000;
			dp->full_duplex = B_FALSE;
		} else if (val & MII_ABILITY_100BASE_TX_FD) {
			/* 100BaseTx & full duplex */
			dp->speed = GEM_SPD_100;
			dp->full_duplex = B_TRUE;
		} else if (val & MII_ABILITY_100BASE_T4) {
			/* 100BaseT4 & full duplex */
			dp->speed = GEM_SPD_100;
			dp->full_duplex = B_TRUE;
		} else if (val & MII_ABILITY_100BASE_TX) {
			/* 100BaseTx & half duplex */
			dp->speed	 = GEM_SPD_100;
			dp->full_duplex  = B_FALSE;
		} else if (val & MII_ABILITY_10BASE_T_FD) {
			/* 10BaseT & full duplex */
			dp->speed	 = GEM_SPD_10;
			dp->full_duplex  = B_TRUE;
		} else if (val & MII_ABILITY_10BASE_T) {
			/* 10BaseT & half duplex */
			dp->speed	 = GEM_SPD_10;
			dp->full_duplex  = B_FALSE;
		} else {
			/*
			 * It seems that the link partnar doesn't have
			 * auto-negotiation capability and our PHY
			 * could not report the correct current mode.
			 * We guess current mode by mii_control register.
			 */
			val = gem_mii_read(dp, MII_CONTROL);

			/* select 100m full or 10m half */
			dp->speed = (val & MII_CONTROL_100MB) ?
			    GEM_SPD_100 : GEM_SPD_10;
			dp->full_duplex = dp->speed != GEM_SPD_10;
			fix_phy = B_TRUE;

			cmn_err(CE_NOTE,
			    "!%s: auto-negotiation done but "
			    "common ability not found.\n"
			    "PHY state: control:%b advert:%b lpable:%b\n"
			    "guessing %d Mbps %s duplex mode",
			    dp->name,
			    val, MII_CONTROL_BITS,
			    advert, MII_ABILITY_BITS,
			    lpable, MII_ABILITY_BITS,
			    gem_speed_value[dp->speed],
			    dp->full_duplex ? "full" : "half");
		}

		if (dp->full_duplex) {
			dp->flow_control =
			    gem_fc_result[fc_cap_decode(advert)]
			    [fc_cap_decode(lpable)];
		} else {
			dp->flow_control = FLOW_CONTROL_NONE;
		}
		dp->mii_state = MII_STATE_MEDIA_SETUP;
		/* FALLTHROUGH */

	case MII_STATE_MEDIA_SETUP:
		dp->mii_state = MII_STATE_LINKDOWN;
		dp->mii_timer = dp->gc.gc_mii_linkdown_timeout;
		DPRINTF(2, (CE_CONT, "!%s: setup midia mode done", dp->name));
		dp->mii_supress_msg = B_FALSE;

		/* use short interval */
		dp->mii_interval = WATCH_INTERVAL_FAST;

		if ((!dp->anadv_autoneg) ||
		    dp->gc.gc_mii_an_oneshot || fix_phy) {

			/*
			 * write specified mode to phy.
			 */
			val = gem_mii_read(dp, MII_CONTROL);
			val &= ~(MII_CONTROL_SPEED | MII_CONTROL_FDUPLEX |
			    MII_CONTROL_ANE | MII_CONTROL_RSAN);

			if (dp->full_duplex) {
				val |= MII_CONTROL_FDUPLEX;
			}

			switch (dp->speed) {
			case GEM_SPD_1000:
				val |= MII_CONTROL_1000MB;
				break;

			case GEM_SPD_100:
				val |= MII_CONTROL_100MB;
				break;

			default:
				cmn_err(CE_WARN, "%s: unknown speed:%d",
				    dp->name, dp->speed);
				/* FALLTHROUGH */
			case GEM_SPD_10:
				/* for GEM_SPD_10, do nothing */
				break;
			}

			if (dp->mii_status & MII_STATUS_XSTATUS) {
				gem_mii_write(dp,
				    MII_1000TC, MII_1000TC_CFG_EN);
			}
			gem_mii_write(dp, MII_CONTROL, val);
		}

		if (dp->nic_state >= NIC_STATE_INITIALIZED) {
			/* notify the result of auto-negotiation to mac */
			(*dp->gc.gc_set_media)(dp);
		}

		if ((void *)dp->gc.gc_mii_tune_phy) {
			/* for built-in sis900 */
			/* XXX - this code should be removed.  */
			(*dp->gc.gc_mii_tune_phy)(dp);
		}

		goto next_nowait;

	case MII_STATE_LINKDOWN:
		status = gem_mii_read(dp, MII_STATUS);
		if (status & MII_STATUS_LINKUP) {
			/*
			 * Link going up
			 */
			dp->mii_state = MII_STATE_LINKUP;
			dp->mii_supress_msg = B_FALSE;

			DPRINTF(0, (CE_CONT,
			    "!%s: link up detected: mii_stat:%b",
			    dp->name, status, MII_STATUS_BITS));

			/*
			 * MII_CONTROL_100MB and  MII_CONTROL_FDUPLEX are
			 * ignored when MII_CONTROL_ANE is set.
			 */
			cmn_err(CE_CONT,
			    "!%s: Link up: %d Mbps %s duplex %s flow control",
			    dp->name,
			    gem_speed_value[dp->speed],
			    dp->full_duplex ? "full" : "half",
			    gem_fc_type[dp->flow_control]);

			dp->mii_interval = dp->gc.gc_mii_link_watch_interval;

			/* XXX - we need other timer to watch statictics */
			if (dp->gc.gc_mii_hw_link_detection &&
			    dp->nic_state == NIC_STATE_ONLINE) {
				dp->mii_interval = 0;
			}

			if (dp->nic_state == NIC_STATE_ONLINE) {
				if (!dp->mac_active) {
					(void) gem_mac_start(dp);
				}
				tx_sched = B_TRUE;
			}
			goto next;
		}

		dp->mii_supress_msg = B_TRUE;
		if (dp->anadv_autoneg) {
			dp->mii_timer -= diff;
			if (dp->mii_timer <= 0) {
				/*
				 * link down timer expired.
				 * need to restart auto-negotiation.
				 */
				linkdown_action =
				    dp->gc.gc_mii_linkdown_timeout_action;
				goto restart_autonego;
			}
		}
		/* don't change mii_state */
		break;

	case MII_STATE_LINKUP:
		status = gem_mii_read(dp, MII_STATUS);
		if ((status & MII_STATUS_LINKUP) == 0) {
			/*
			 * Link going down
			 */
			cmn_err(CE_NOTE,
			    "!%s: link down detected: mii_stat:%b",
			    dp->name, status, MII_STATUS_BITS);

			if (dp->nic_state == NIC_STATE_ONLINE &&
			    dp->mac_active &&
			    dp->gc.gc_mii_stop_mac_on_linkdown) {
				(void) gem_mac_stop(dp, 0);

				if (dp->tx_blocked) {
					/* drain tx */
					tx_sched = B_TRUE;
				}
			}

			if (dp->anadv_autoneg) {
				/* need to restart auto-negotiation */
				linkdown_action = dp->gc.gc_mii_linkdown_action;
				goto restart_autonego;
			}

			dp->mii_state = MII_STATE_LINKDOWN;
			dp->mii_timer = dp->gc.gc_mii_linkdown_timeout;

			if ((void *)dp->gc.gc_mii_tune_phy) {
				/* for built-in sis900 */
				(*dp->gc.gc_mii_tune_phy)(dp);
			}
			dp->mii_interval = dp->gc.gc_mii_link_watch_interval;
			goto next;
		}

		/* don't change mii_state */
		if (dp->gc.gc_mii_hw_link_detection &&
		    dp->nic_state == NIC_STATE_ONLINE) {
			dp->mii_interval = 0;
			goto next;
		}
		break;
	}
	dp->mii_interval = dp->gc.gc_mii_link_watch_interval;
	goto next;

	/* Actions on the end of state routine */

restart_autonego:
	switch (linkdown_action) {
	case MII_ACTION_RESET:
		if (!dp->mii_supress_msg) {
			cmn_err(CE_CONT, "!%s: resetting PHY", dp->name);
		}
		dp->mii_supress_msg = B_TRUE;
		goto reset_phy;

	case MII_ACTION_NONE:
		dp->mii_supress_msg = B_TRUE;
		if (dp->gc.gc_mii_an_oneshot) {
			goto autonego;
		}
		/* PHY will restart autonego automatically */
		dp->mii_state = MII_STATE_AUTONEGOTIATING;
		dp->mii_timer = dp->gc.gc_mii_an_timeout;
		dp->mii_interval = dp->gc.gc_mii_an_watch_interval;
		goto next;

	case MII_ACTION_RSA:
		if (!dp->mii_supress_msg) {
			cmn_err(CE_CONT, "!%s: restarting auto-negotiation",
			    dp->name);
		}
		dp->mii_supress_msg = B_TRUE;
		goto autonego;

	default:
		cmn_err(CE_WARN, "!%s: unknowm linkdown action: %d",
		    dp->name, dp->gc.gc_mii_linkdown_action);
		dp->mii_supress_msg = B_TRUE;
	}
	/* NOTREACHED */

reset_phy:
	if (!dp->mii_supress_msg) {
		cmn_err(CE_CONT, "!%s: resetting PHY", dp->name);
	}
	dp->mii_state = MII_STATE_RESETTING;
	dp->mii_timer = dp->gc.gc_mii_reset_timeout;
	if (!dp->gc.gc_mii_dont_reset) {
		gem_mii_write(dp, MII_CONTROL, MII_CONTROL_RESET);
	}
	dp->mii_interval = WATCH_INTERVAL_FAST;
	goto next;

autonego:
	if (!dp->mii_supress_msg) {
		cmn_err(CE_CONT, "!%s: auto-negotiation started", dp->name);
	}
	dp->mii_state = MII_STATE_AUTONEGOTIATING;
	dp->mii_timer = dp->gc.gc_mii_an_timeout;

	/* start/restart auto nego */
	val = gem_mii_read(dp, MII_CONTROL) &
	    ~(MII_CONTROL_ISOLATE | MII_CONTROL_PWRDN | MII_CONTROL_RESET);

	gem_mii_write(dp, MII_CONTROL,
	    val | MII_CONTROL_RSAN | MII_CONTROL_ANE);

	dp->mii_interval = dp->gc.gc_mii_an_watch_interval;

next:
	if (dp->link_watcher_id == 0 && dp->mii_interval) {
		/* we must schedule next mii_watcher */
		dp->link_watcher_id =
		    timeout((void (*)(void *))&gem_mii_link_watcher,
		    (void *)dp, dp->mii_interval);
	}

	if (old_mii_state != dp->mii_state) {
		/* notify new mii link state */
		if (dp->mii_state == MII_STATE_LINKUP) {
			dp->linkup_delay = 0;
			GEM_LINKUP(dp);
		} else if (dp->linkup_delay <= 0) {
			GEM_LINKDOWN(dp);
		}
	} else if (dp->linkup_delay < 0) {
		/* first linkup timeout */
		dp->linkup_delay = 0;
		GEM_LINKDOWN(dp);
	}

	return (tx_sched);
}

static void
gem_mii_link_watcher(struct gem_dev *dp)
{
	boolean_t	tx_sched;

	mutex_enter(&dp->intrlock);

	dp->link_watcher_id = 0;
	tx_sched = gem_mii_link_check(dp);
#if GEM_DEBUG_LEVEL > 2
	if (dp->link_watcher_id == 0) {
		cmn_err(CE_CONT, "%s: link watcher stopped", dp->name);
	}
#endif
	mutex_exit(&dp->intrlock);

	if (tx_sched) {
		/* kick potentially stopped downstream */
		mac_tx_update(dp->mh);
	}
}

int
gem_mii_probe_default(struct gem_dev *dp)
{
	int8_t		phy;
	uint16_t	status;
	uint16_t	adv;
	uint16_t	adv_org;

	DPRINTF(3, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/*
	 * Scan PHY
	 */
	/* ensure to send sync bits */
	dp->mii_status = 0;

	/* Try default phy first */
	if (dp->mii_phy_addr) {
		status = gem_mii_read(dp, MII_STATUS);
		if (status != 0xffff && status != 0) {
			gem_mii_write(dp, MII_CONTROL, 0);
			goto PHY_found;
		}

		if (dp->mii_phy_addr < 0) {
			cmn_err(CE_NOTE,
	    "!%s: failed to probe default internal and/or non-MII PHY",
			    dp->name);
			return (GEM_FAILURE);
		}

		cmn_err(CE_NOTE,
		    "!%s: failed to probe default MII PHY at %d",
		    dp->name, dp->mii_phy_addr);
	}

	/* Try all possible address */
	for (phy = dp->gc.gc_mii_addr_min; phy < 32; phy++) {
		dp->mii_phy_addr = phy;
		status = gem_mii_read(dp, MII_STATUS);

		if (status != 0xffff && status != 0) {
			gem_mii_write(dp, MII_CONTROL, 0);
			goto PHY_found;
		}
	}

	for (phy = dp->gc.gc_mii_addr_min; phy < 32; phy++) {
		dp->mii_phy_addr = phy;
		gem_mii_write(dp, MII_CONTROL, 0);
		status = gem_mii_read(dp, MII_STATUS);

		if (status != 0xffff && status != 0) {
			goto PHY_found;
		}
	}

	cmn_err(CE_NOTE, "!%s: no MII PHY found", dp->name);
	dp->mii_phy_addr = -1;

	return (GEM_FAILURE);

PHY_found:
	dp->mii_status = status;
	dp->mii_phy_id  = (gem_mii_read(dp, MII_PHYIDH) << 16) |
	    gem_mii_read(dp, MII_PHYIDL);

	if (dp->mii_phy_addr < 0) {
		cmn_err(CE_CONT, "!%s: using internal/non-MII PHY(0x%08x)",
		    dp->name, dp->mii_phy_id);
	} else {
		cmn_err(CE_CONT, "!%s: MII PHY (0x%08x) found at %d",
		    dp->name, dp->mii_phy_id, dp->mii_phy_addr);
	}

	cmn_err(CE_CONT, "!%s: PHY control:%b, status:%b, advert:%b, lpar:%b",
	    dp->name,
	    gem_mii_read(dp, MII_CONTROL), MII_CONTROL_BITS,
	    status, MII_STATUS_BITS,
	    gem_mii_read(dp, MII_AN_ADVERT), MII_ABILITY_BITS,
	    gem_mii_read(dp, MII_AN_LPABLE), MII_ABILITY_BITS);

	dp->mii_xstatus = 0;
	if (status & MII_STATUS_XSTATUS) {
		dp->mii_xstatus = gem_mii_read(dp, MII_XSTATUS);

		cmn_err(CE_CONT, "!%s: xstatus:%b",
		    dp->name, dp->mii_xstatus, MII_XSTATUS_BITS);
	}

	/* check if the phy can advertize pause abilities */
	adv_org = gem_mii_read(dp, MII_AN_ADVERT);

	gem_mii_write(dp, MII_AN_ADVERT,
	    MII_ABILITY_PAUSE | MII_ABILITY_ASMPAUSE);

	adv = gem_mii_read(dp, MII_AN_ADVERT);

	if ((adv & MII_ABILITY_PAUSE) == 0) {
		dp->gc.gc_flow_control &= ~1;
	}

	if ((adv & MII_ABILITY_ASMPAUSE) == 0) {
		dp->gc.gc_flow_control &= ~2;
	}

	gem_mii_write(dp, MII_AN_ADVERT, adv_org);

	return (GEM_SUCCESS);
}

static void
gem_mii_start(struct gem_dev *dp)
{
	DPRINTF(3, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* make a first call of check link */
	dp->mii_state = MII_STATE_UNKNOWN;
	dp->mii_last_check = ddi_get_lbolt();
	dp->linkup_delay = dp->gc.gc_mii_linkdown_timeout;
	(void) gem_mii_link_watcher(dp);
}

static void
gem_mii_stop(struct gem_dev *dp)
{
	DPRINTF(3, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* Ensure timer routine stopped */
	mutex_enter(&dp->intrlock);
	if (dp->link_watcher_id) {
		while (untimeout(dp->link_watcher_id) == -1)
			;
		dp->link_watcher_id = 0;
	}
	mutex_exit(&dp->intrlock);
}

boolean_t
gem_get_mac_addr_conf(struct gem_dev *dp)
{
	char		propname[32];
	char		*valstr;
	uint8_t		mac[ETHERADDRL];
	char		*cp;
	int		c;
	int		i;
	int		j;
	uint8_t		v;
	uint8_t		d;
	uint8_t		ored;

	DPRINTF(3, (CE_CONT, "!%s: %s: called", dp->name, __func__));
	/*
	 * Get ethernet address from .conf file
	 */
	(void) sprintf(propname, "mac-addr");
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, dp->dip,
	    DDI_PROP_DONTPASS, propname, &valstr)) !=
	    DDI_PROP_SUCCESS) {
		return (B_FALSE);
	}

	if (strlen(valstr) != ETHERADDRL*3-1) {
		goto syntax_err;
	}

	cp = valstr;
	j  = 0;
	ored = 0;
	for (;;) {
		v = 0;
		for (i = 0; i < 2; i++) {
			c = *cp++;

			if (c >= 'a' && c <= 'f') {
				d = c - 'a' + 10;
			} else if (c >= 'A' && c <= 'F') {
				d = c - 'A' + 10;
			} else if (c >= '0' && c <= '9') {
				d = c - '0';
			} else {
				goto syntax_err;
			}
			v = (v << 4) | d;
		}

		mac[j++] = v;
		ored |= v;
		if (j == ETHERADDRL) {
			/* done */
			break;
		}

		c = *cp++;
		if (c != ':') {
			goto syntax_err;
		}
	}

	if (ored == 0) {
		goto err;
	}
	for (i = 0; i < ETHERADDRL; i++) {
		dp->dev_addr.ether_addr_octet[i] = mac[i];
	}
	ddi_prop_free(valstr);
	return (B_TRUE);

syntax_err:
	cmn_err(CE_CONT,
	    "!%s: read mac addr: trying .conf: syntax err %s",
	    dp->name, valstr);
err:
	ddi_prop_free(valstr);

	return (B_FALSE);
}


/* ============================================================== */
/*
 * internal start/stop interface
 */
/* ============================================================== */
static int
gem_mac_set_rx_filter(struct gem_dev *dp)
{
	return ((*dp->gc.gc_set_rx_filter)(dp));
}

/*
 * gem_mac_init: cold start
 */
static int
gem_mac_init(struct gem_dev *dp)
{
	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	if (dp->mac_suspended) {
		return (GEM_FAILURE);
	}

	dp->mac_active = B_FALSE;

	gem_init_rx_ring(dp);
	gem_init_tx_ring(dp);

	/* reset transmitter state */
	dp->tx_blocked = (clock_t)0;
	dp->tx_busy = 0;
	dp->tx_reclaim_busy = 0;
	dp->tx_max_packets = dp->gc.gc_tx_buf_limit;

	if ((*dp->gc.gc_init_chip)(dp) != GEM_SUCCESS) {
		return (GEM_FAILURE);
	}

	gem_prepare_rx_buf(dp);

	return (GEM_SUCCESS);
}
/*
 * gem_mac_start: warm start
 */
static int
gem_mac_start(struct gem_dev *dp)
{
	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	ASSERT(mutex_owned(&dp->intrlock));
	ASSERT(dp->nic_state == NIC_STATE_ONLINE);
	ASSERT(dp->mii_state ==  MII_STATE_LINKUP);

	/* enable tx and rx */
	mutex_enter(&dp->xmitlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->xmitlock);
		return (GEM_FAILURE);
	}
	dp->mac_active = B_TRUE;
	mutex_exit(&dp->xmitlock);

	/* setup rx buffers */
	(*dp->gc.gc_rx_start)(dp,
	    SLOT(dp->rx_active_head, dp->gc.gc_rx_ring_size),
	    dp->rx_active_tail - dp->rx_active_head);

	if ((*dp->gc.gc_start_chip)(dp) != GEM_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s: start_chip: failed",
		    dp->name, __func__);
		return (GEM_FAILURE);
	}

	mutex_enter(&dp->xmitlock);

	/* load untranmitted packets to the nic */
	ASSERT(dp->tx_softq_tail - dp->tx_softq_head >= 0);
	if (dp->tx_softq_tail - dp->tx_softq_head > 0) {
		gem_tx_load_descs_oo(dp,
		    dp->tx_softq_head, dp->tx_softq_tail,
		    GEM_TXFLAG_HEAD);
		/* issue preloaded tx buffers */
		gem_tx_start_unit(dp);
	}

	mutex_exit(&dp->xmitlock);

	return (GEM_SUCCESS);
}

static int
gem_mac_stop(struct gem_dev *dp, uint_t flags)
{
	int		i;
	int		wait_time; /* in uS */
#ifdef GEM_DEBUG_LEVEL
	clock_t		now;
#endif
	int		ret = GEM_SUCCESS;

	DPRINTF(1, (CE_CONT, "!%s: %s: called, rx_buf_free:%d",
	    dp->name, __func__, dp->rx_buf_freecnt));

	ASSERT(mutex_owned(&dp->intrlock));
	ASSERT(!mutex_owned(&dp->xmitlock));

	/*
	 * Block transmits
	 */
	mutex_enter(&dp->xmitlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->xmitlock);
		return (GEM_SUCCESS);
	}
	dp->mac_active = B_FALSE;

	while (dp->tx_busy > 0) {
		cv_wait(&dp->tx_drain_cv, &dp->xmitlock);
	}
	mutex_exit(&dp->xmitlock);

	if ((flags & GEM_RESTART_NOWAIT) == 0) {
		/*
		 * Wait for all tx buffers sent.
		 */
		wait_time =
		    2 * (8 * MAXPKTBUF(dp) / gem_speed_value[dp->speed]) *
		    (dp->tx_active_tail - dp->tx_active_head);

		DPRINTF(0, (CE_CONT, "%s: %s: max drain time: %d uS",
		    dp->name, __func__, wait_time));
		i = 0;
#ifdef GEM_DEBUG_LEVEL
		now = ddi_get_lbolt();
#endif
		while (dp->tx_active_tail != dp->tx_active_head) {
			if (i > wait_time) {
				/* timeout */
				cmn_err(CE_NOTE, "%s: %s timeout: tx drain",
				    dp->name, __func__);
				break;
			}
			(void) gem_reclaim_txbuf(dp);
			drv_usecwait(100);
			i += 100;
		}
		DPRINTF(0, (CE_NOTE,
		    "!%s: %s: the nic have drained in %d uS, real %d mS",
		    dp->name, __func__, i,
		    10*((int)(ddi_get_lbolt() - now))));
	}

	/*
	 * Now we can stop the nic safely.
	 */
	if ((*dp->gc.gc_stop_chip)(dp) != GEM_SUCCESS) {
		cmn_err(CE_NOTE, "%s: %s: resetting the chip to stop it",
		    dp->name, __func__);
		if ((*dp->gc.gc_reset_chip)(dp) != GEM_SUCCESS) {
			cmn_err(CE_WARN, "%s: %s: failed to reset chip",
			    dp->name, __func__);
		}
	}

	/*
	 * Clear all rx buffers
	 */
	if (flags & GEM_RESTART_KEEP_BUF) {
		(void) gem_receive(dp);
	}
	gem_clean_rx_buf(dp);

	/*
	 * Update final statistics
	 */
	(*dp->gc.gc_get_stats)(dp);

	/*
	 * Clear all pended tx packets
	 */
	ASSERT(dp->tx_active_tail == dp->tx_softq_head);
	ASSERT(dp->tx_softq_tail == dp->tx_free_head);
	if (flags & GEM_RESTART_KEEP_BUF) {
		/* restore active tx buffers */
		dp->tx_active_tail = dp->tx_active_head;
		dp->tx_softq_head  = dp->tx_active_head;
	} else {
		gem_clean_tx_buf(dp);
	}

	return (ret);
}

static int
gem_add_multicast(struct gem_dev *dp, const uint8_t *ep)
{
	int		cnt;
	int		err;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	mutex_enter(&dp->intrlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->intrlock);
		return (GEM_FAILURE);
	}

	if (dp->mc_count_req++ < GEM_MAXMC) {
		/* append the new address at the end of the mclist */
		cnt = dp->mc_count;
		bcopy(ep, dp->mc_list[cnt].addr.ether_addr_octet,
		    ETHERADDRL);
		if (dp->gc.gc_multicast_hash) {
			dp->mc_list[cnt].hash =
			    (*dp->gc.gc_multicast_hash)(dp, (uint8_t *)ep);
		}
		dp->mc_count = cnt + 1;
	}

	if (dp->mc_count_req != dp->mc_count) {
		/* multicast address list overflow */
		dp->rxmode |= RXMODE_MULTI_OVF;
	} else {
		dp->rxmode &= ~RXMODE_MULTI_OVF;
	}

	/* tell new multicast list to the hardware */
	err = gem_mac_set_rx_filter(dp);

	mutex_exit(&dp->intrlock);

	return (err);
}

static int
gem_remove_multicast(struct gem_dev *dp, const uint8_t *ep)
{
	size_t		len;
	int		i;
	int		cnt;
	int		err;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	mutex_enter(&dp->intrlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->intrlock);
		return (GEM_FAILURE);
	}

	dp->mc_count_req--;
	cnt = dp->mc_count;
	for (i = 0; i < cnt; i++) {
		if (bcmp(ep, &dp->mc_list[i].addr, ETHERADDRL)) {
			continue;
		}
		/* shrink the mclist by copying forward */
		len = (cnt - (i + 1)) * sizeof (*dp->mc_list);
		if (len > 0) {
			bcopy(&dp->mc_list[i+1], &dp->mc_list[i], len);
		}
		dp->mc_count--;
		break;
	}

	if (dp->mc_count_req != dp->mc_count) {
		/* multicast address list overflow */
		dp->rxmode |= RXMODE_MULTI_OVF;
	} else {
		dp->rxmode &= ~RXMODE_MULTI_OVF;
	}
	/* In gem v2, don't hold xmitlock on calling set_rx_filter */
	err = gem_mac_set_rx_filter(dp);

	mutex_exit(&dp->intrlock);

	return (err);
}

/* ============================================================== */
/*
 * ND interface
 */
/* ============================================================== */
enum {
	PARAM_AUTONEG_CAP,
	PARAM_PAUSE_CAP,
	PARAM_ASYM_PAUSE_CAP,
	PARAM_1000FDX_CAP,
	PARAM_1000HDX_CAP,
	PARAM_100T4_CAP,
	PARAM_100FDX_CAP,
	PARAM_100HDX_CAP,
	PARAM_10FDX_CAP,
	PARAM_10HDX_CAP,

	PARAM_ADV_AUTONEG_CAP,
	PARAM_ADV_PAUSE_CAP,
	PARAM_ADV_ASYM_PAUSE_CAP,
	PARAM_ADV_1000FDX_CAP,
	PARAM_ADV_1000HDX_CAP,
	PARAM_ADV_100T4_CAP,
	PARAM_ADV_100FDX_CAP,
	PARAM_ADV_100HDX_CAP,
	PARAM_ADV_10FDX_CAP,
	PARAM_ADV_10HDX_CAP,

	PARAM_LP_AUTONEG_CAP,
	PARAM_LP_PAUSE_CAP,
	PARAM_LP_ASYM_PAUSE_CAP,
	PARAM_LP_1000FDX_CAP,
	PARAM_LP_1000HDX_CAP,
	PARAM_LP_100T4_CAP,
	PARAM_LP_100FDX_CAP,
	PARAM_LP_100HDX_CAP,
	PARAM_LP_10FDX_CAP,
	PARAM_LP_10HDX_CAP,

	PARAM_LINK_STATUS,
	PARAM_LINK_SPEED,
	PARAM_LINK_DUPLEX,

	PARAM_LINK_AUTONEG,
	PARAM_LINK_RX_PAUSE,
	PARAM_LINK_TX_PAUSE,

	PARAM_LOOP_MODE,
	PARAM_MSI_CNT,

#ifdef DEBUG_RESUME
	PARAM_RESUME_TEST,
#endif
	PARAM_COUNT
};

enum ioc_reply {
	IOC_INVAL = -1,				/* bad, NAK with EINVAL	*/
	IOC_DONE,				/* OK, reply sent	*/
	IOC_ACK,				/* OK, just send ACK	*/
	IOC_REPLY,				/* OK, just send reply	*/
	IOC_RESTART_ACK,			/* OK, restart & ACK	*/
	IOC_RESTART_REPLY			/* OK, restart & reply	*/
};

struct gem_nd_arg {
	struct gem_dev	*dp;
	int		item;
};

static int
gem_param_get(queue_t *q, mblk_t *mp, caddr_t arg, cred_t *credp)
{
	struct gem_dev	*dp = ((struct gem_nd_arg *)(void *)arg)->dp;
	int		item = ((struct gem_nd_arg *)(void *)arg)->item;
	long		val;

	DPRINTF(0, (CE_CONT, "!%s: %s: called, item:%d",
	    dp->name, __func__, item));

	switch (item) {
	case PARAM_AUTONEG_CAP:
		val = BOOLEAN(dp->mii_status & MII_STATUS_CANAUTONEG);
		DPRINTF(0, (CE_CONT, "autoneg_cap:%d", val));
		break;

	case PARAM_PAUSE_CAP:
		val = BOOLEAN(dp->gc.gc_flow_control & 1);
		break;

	case PARAM_ASYM_PAUSE_CAP:
		val = BOOLEAN(dp->gc.gc_flow_control & 2);
		break;

	case PARAM_1000FDX_CAP:
		val = (dp->mii_xstatus & MII_XSTATUS_1000BASET_FD) ||
		    (dp->mii_xstatus & MII_XSTATUS_1000BASEX_FD);
		break;

	case PARAM_1000HDX_CAP:
		val = (dp->mii_xstatus & MII_XSTATUS_1000BASET) ||
		    (dp->mii_xstatus & MII_XSTATUS_1000BASEX);
		break;

	case PARAM_100T4_CAP:
		val = BOOLEAN(dp->mii_status & MII_STATUS_100_BASE_T4);
		break;

	case PARAM_100FDX_CAP:
		val = BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX_FD);
		break;

	case PARAM_100HDX_CAP:
		val = BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX);
		break;

	case PARAM_10FDX_CAP:
		val = BOOLEAN(dp->mii_status & MII_STATUS_10_FD);
		break;

	case PARAM_10HDX_CAP:
		val = BOOLEAN(dp->mii_status & MII_STATUS_10);
		break;

	case PARAM_ADV_AUTONEG_CAP:
		val = dp->anadv_autoneg;
		break;

	case PARAM_ADV_PAUSE_CAP:
		val = BOOLEAN(dp->anadv_flow_control & 1);
		break;

	case PARAM_ADV_ASYM_PAUSE_CAP:
		val = BOOLEAN(dp->anadv_flow_control & 2);
		break;

	case PARAM_ADV_1000FDX_CAP:
		val = dp->anadv_1000fdx;
		break;

	case PARAM_ADV_1000HDX_CAP:
		val = dp->anadv_1000hdx;
		break;

	case PARAM_ADV_100T4_CAP:
		val = dp->anadv_100t4;
		break;

	case PARAM_ADV_100FDX_CAP:
		val = dp->anadv_100fdx;
		break;

	case PARAM_ADV_100HDX_CAP:
		val = dp->anadv_100hdx;
		break;

	case PARAM_ADV_10FDX_CAP:
		val = dp->anadv_10fdx;
		break;

	case PARAM_ADV_10HDX_CAP:
		val = dp->anadv_10hdx;
		break;

	case PARAM_LP_AUTONEG_CAP:
		val = BOOLEAN(dp->mii_exp & MII_AN_EXP_LPCANAN);
		break;

	case PARAM_LP_PAUSE_CAP:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_PAUSE);
		break;

	case PARAM_LP_ASYM_PAUSE_CAP:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_ASMPAUSE);
		break;

	case PARAM_LP_1000FDX_CAP:
		val = BOOLEAN(dp->mii_stat1000 & MII_1000TS_LP_FULL);
		break;

	case PARAM_LP_1000HDX_CAP:
		val = BOOLEAN(dp->mii_stat1000 & MII_1000TS_LP_HALF);
		break;

	case PARAM_LP_100T4_CAP:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_100BASE_T4);
		break;

	case PARAM_LP_100FDX_CAP:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_100BASE_TX_FD);
		break;

	case PARAM_LP_100HDX_CAP:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_100BASE_TX);
		break;

	case PARAM_LP_10FDX_CAP:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_10BASE_T_FD);
		break;

	case PARAM_LP_10HDX_CAP:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_10BASE_T);
		break;

	case PARAM_LINK_STATUS:
		val = (dp->mii_state == MII_STATE_LINKUP);
		break;

	case PARAM_LINK_SPEED:
		val = gem_speed_value[dp->speed];
		break;

	case PARAM_LINK_DUPLEX:
		val = 0;
		if (dp->mii_state == MII_STATE_LINKUP) {
			val = dp->full_duplex ? 2 : 1;
		}
		break;

	case PARAM_LINK_AUTONEG:
		val = BOOLEAN(dp->mii_exp & MII_AN_EXP_LPCANAN);
		break;

	case PARAM_LINK_RX_PAUSE:
		val = (dp->flow_control == FLOW_CONTROL_SYMMETRIC) ||
		    (dp->flow_control == FLOW_CONTROL_RX_PAUSE);
		break;

	case PARAM_LINK_TX_PAUSE:
		val = (dp->flow_control == FLOW_CONTROL_SYMMETRIC) ||
		    (dp->flow_control == FLOW_CONTROL_TX_PAUSE);
		break;

#ifdef DEBUG_RESUME
	case PARAM_RESUME_TEST:
		val = 0;
		break;
#endif
	default:
		cmn_err(CE_WARN, "%s: unimplemented ndd control (%d)",
		    dp->name, item);
		break;
	}

	(void) mi_mpprintf(mp, "%ld", val);

	return (0);
}

static int
gem_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t arg, cred_t *credp)
{
	struct gem_dev	*dp = ((struct gem_nd_arg *)(void *)arg)->dp;
	int		item = ((struct gem_nd_arg *)(void *)arg)->item;
	long		val;
	char		*end;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));
	if (ddi_strtol(value, &end, 10, &val)) {
		return (EINVAL);
	}
	if (end == value) {
		return (EINVAL);
	}

	switch (item) {
	case PARAM_ADV_AUTONEG_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val && (dp->mii_status & MII_STATUS_CANAUTONEG) == 0) {
			goto err;
		}
		dp->anadv_autoneg = (int)val;
		break;

	case PARAM_ADV_PAUSE_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val) {
			dp->anadv_flow_control |= 1;
		} else {
			dp->anadv_flow_control &= ~1;
		}
		break;

	case PARAM_ADV_ASYM_PAUSE_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val) {
			dp->anadv_flow_control |= 2;
		} else {
			dp->anadv_flow_control &= ~2;
		}
		break;

	case PARAM_ADV_1000FDX_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val && (dp->mii_xstatus &
		    (MII_XSTATUS_1000BASET_FD |
		    MII_XSTATUS_1000BASEX_FD)) == 0) {
			goto err;
		}
		dp->anadv_1000fdx = (int)val;
		break;

	case PARAM_ADV_1000HDX_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val && (dp->mii_xstatus &
		    (MII_XSTATUS_1000BASET | MII_XSTATUS_1000BASEX)) == 0) {
			goto err;
		}
		dp->anadv_1000hdx = (int)val;
		break;

	case PARAM_ADV_100T4_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val && (dp->mii_status & MII_STATUS_100_BASE_T4) == 0) {
			goto err;
		}
		dp->anadv_100t4 = (int)val;
		break;

	case PARAM_ADV_100FDX_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val && (dp->mii_status & MII_STATUS_100_BASEX_FD) == 0) {
			goto err;
		}
		dp->anadv_100fdx = (int)val;
		break;

	case PARAM_ADV_100HDX_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val && (dp->mii_status & MII_STATUS_100_BASEX) == 0) {
			goto err;
		}
		dp->anadv_100hdx = (int)val;
		break;

	case PARAM_ADV_10FDX_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val && (dp->mii_status & MII_STATUS_10_FD) == 0) {
			goto err;
		}
		dp->anadv_10fdx = (int)val;
		break;

	case PARAM_ADV_10HDX_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val && (dp->mii_status & MII_STATUS_10) == 0) {
			goto err;
		}
		dp->anadv_10hdx = (int)val;
		break;
	}

	/* sync with PHY */
	gem_choose_forcedmode(dp);

	dp->mii_state = MII_STATE_UNKNOWN;
	if (dp->gc.gc_mii_hw_link_detection && dp->link_watcher_id == 0) {
		/* XXX - Can we ignore the return code ? */
		(void) gem_mii_link_check(dp);
	}

	return (0);
err:
	return (EINVAL);
}

static void
gem_nd_load(struct gem_dev *dp, char *name, ndgetf_t gf, ndsetf_t sf, int item)
{
	struct gem_nd_arg	*arg;

	ASSERT(item >= 0);
	ASSERT(item < PARAM_COUNT);

	arg = &((struct gem_nd_arg *)(void *)dp->nd_arg_p)[item];
	arg->dp = dp;
	arg->item = item;

	DPRINTF(2, (CE_CONT, "!%s: %s: name:%s, item:%d",
	    dp->name, __func__, name, item));
	(void) nd_load(&dp->nd_data_p, name, gf, sf, (caddr_t)arg);
}

static void
gem_nd_setup(struct gem_dev *dp)
{
	DPRINTF(0, (CE_CONT, "!%s: %s: called, mii_status:0x%b",
	    dp->name, __func__, dp->mii_status, MII_STATUS_BITS));

	ASSERT(dp->nd_arg_p == NULL);

	dp->nd_arg_p =
	    kmem_zalloc(sizeof (struct gem_nd_arg) * PARAM_COUNT, KM_SLEEP);

#define	SETFUNC(x)	((x) ? gem_param_set : NULL)

	gem_nd_load(dp, "autoneg_cap",
	    gem_param_get, NULL, PARAM_AUTONEG_CAP);
	gem_nd_load(dp, "pause_cap",
	    gem_param_get, NULL, PARAM_PAUSE_CAP);
	gem_nd_load(dp, "asym_pause_cap",
	    gem_param_get, NULL, PARAM_ASYM_PAUSE_CAP);
	gem_nd_load(dp, "1000fdx_cap",
	    gem_param_get, NULL, PARAM_1000FDX_CAP);
	gem_nd_load(dp, "1000hdx_cap",
	    gem_param_get, NULL, PARAM_1000HDX_CAP);
	gem_nd_load(dp, "100T4_cap",
	    gem_param_get, NULL, PARAM_100T4_CAP);
	gem_nd_load(dp, "100fdx_cap",
	    gem_param_get, NULL, PARAM_100FDX_CAP);
	gem_nd_load(dp, "100hdx_cap",
	    gem_param_get, NULL, PARAM_100HDX_CAP);
	gem_nd_load(dp, "10fdx_cap",
	    gem_param_get, NULL, PARAM_10FDX_CAP);
	gem_nd_load(dp, "10hdx_cap",
	    gem_param_get, NULL, PARAM_10HDX_CAP);

	/* Our advertised capabilities */
	gem_nd_load(dp, "adv_autoneg_cap", gem_param_get,
	    SETFUNC(dp->mii_status & MII_STATUS_CANAUTONEG),
	    PARAM_ADV_AUTONEG_CAP);
	gem_nd_load(dp, "adv_pause_cap", gem_param_get,
	    SETFUNC(dp->gc.gc_flow_control & 1),
	    PARAM_ADV_PAUSE_CAP);
	gem_nd_load(dp, "adv_asym_pause_cap", gem_param_get,
	    SETFUNC(dp->gc.gc_flow_control & 2),
	    PARAM_ADV_ASYM_PAUSE_CAP);
	gem_nd_load(dp, "adv_1000fdx_cap", gem_param_get,
	    SETFUNC(dp->mii_xstatus &
	    (MII_XSTATUS_1000BASEX_FD | MII_XSTATUS_1000BASET_FD)),
	    PARAM_ADV_1000FDX_CAP);
	gem_nd_load(dp, "adv_1000hdx_cap", gem_param_get,
	    SETFUNC(dp->mii_xstatus &
	    (MII_XSTATUS_1000BASEX | MII_XSTATUS_1000BASET)),
	    PARAM_ADV_1000HDX_CAP);
	gem_nd_load(dp, "adv_100T4_cap", gem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_100_BASE_T4) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_100T4_CAP);
	gem_nd_load(dp, "adv_100fdx_cap", gem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_100_BASEX_FD) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_100FDX_CAP);
	gem_nd_load(dp, "adv_100hdx_cap", gem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_100_BASEX) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_100HDX_CAP);
	gem_nd_load(dp, "adv_10fdx_cap", gem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_10_FD) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_10FDX_CAP);
	gem_nd_load(dp, "adv_10hdx_cap", gem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_10) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_10HDX_CAP);

	/* Partner's advertised capabilities */
	gem_nd_load(dp, "lp_autoneg_cap",
	    gem_param_get, NULL, PARAM_LP_AUTONEG_CAP);
	gem_nd_load(dp, "lp_pause_cap",
	    gem_param_get, NULL, PARAM_LP_PAUSE_CAP);
	gem_nd_load(dp, "lp_asym_pause_cap",
	    gem_param_get, NULL, PARAM_LP_ASYM_PAUSE_CAP);
	gem_nd_load(dp, "lp_1000fdx_cap",
	    gem_param_get, NULL, PARAM_LP_1000FDX_CAP);
	gem_nd_load(dp, "lp_1000hdx_cap",
	    gem_param_get, NULL, PARAM_LP_1000HDX_CAP);
	gem_nd_load(dp, "lp_100T4_cap",
	    gem_param_get, NULL, PARAM_LP_100T4_CAP);
	gem_nd_load(dp, "lp_100fdx_cap",
	    gem_param_get, NULL, PARAM_LP_100FDX_CAP);
	gem_nd_load(dp, "lp_100hdx_cap",
	    gem_param_get, NULL, PARAM_LP_100HDX_CAP);
	gem_nd_load(dp, "lp_10fdx_cap",
	    gem_param_get, NULL, PARAM_LP_10FDX_CAP);
	gem_nd_load(dp, "lp_10hdx_cap",
	    gem_param_get, NULL, PARAM_LP_10HDX_CAP);

	/* Current operating modes */
	gem_nd_load(dp, "link_status",
	    gem_param_get, NULL, PARAM_LINK_STATUS);
	gem_nd_load(dp, "link_speed",
	    gem_param_get, NULL, PARAM_LINK_SPEED);
	gem_nd_load(dp, "link_duplex",
	    gem_param_get, NULL, PARAM_LINK_DUPLEX);
	gem_nd_load(dp, "link_autoneg",
	    gem_param_get, NULL, PARAM_LINK_AUTONEG);
	gem_nd_load(dp, "link_rx_pause",
	    gem_param_get, NULL, PARAM_LINK_RX_PAUSE);
	gem_nd_load(dp, "link_tx_pause",
	    gem_param_get, NULL, PARAM_LINK_TX_PAUSE);
#ifdef DEBUG_RESUME
	gem_nd_load(dp, "resume_test",
	    gem_param_get, NULL, PARAM_RESUME_TEST);
#endif
#undef	SETFUNC
}

static
enum ioc_reply
gem_nd_ioctl(struct gem_dev *dp, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	boolean_t	ok;

	ASSERT(mutex_owned(&dp->intrlock));

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	switch (iocp->ioc_cmd) {
	case ND_GET:
		ok = nd_getset(wq, dp->nd_data_p, mp);
		DPRINTF(0, (CE_CONT,
		    "%s: get %s", dp->name, ok ? "OK" : "FAIL"));
		return (ok ? IOC_REPLY : IOC_INVAL);

	case ND_SET:
		ok = nd_getset(wq, dp->nd_data_p, mp);

		DPRINTF(0, (CE_CONT, "%s: set %s err %d",
		    dp->name, ok ? "OK" : "FAIL", iocp->ioc_error));

		if (!ok) {
			return (IOC_INVAL);
		}

		if (iocp->ioc_error) {
			return (IOC_REPLY);
		}

		return (IOC_RESTART_REPLY);
	}

	cmn_err(CE_WARN, "%s: invalid cmd 0x%x", dp->name, iocp->ioc_cmd);

	return (IOC_INVAL);
}

static void
gem_nd_cleanup(struct gem_dev *dp)
{
	ASSERT(dp->nd_data_p != NULL);
	ASSERT(dp->nd_arg_p != NULL);

	nd_free(&dp->nd_data_p);

	kmem_free(dp->nd_arg_p, sizeof (struct gem_nd_arg) * PARAM_COUNT);
	dp->nd_arg_p = NULL;
}

static void
gem_mac_ioctl(struct gem_dev *dp, queue_t *wq, mblk_t *mp)
{
	struct iocblk	*iocp;
	enum ioc_reply	status;
	int		cmd;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/*
	 * Validate the command before bothering with the mutex ...
	 */
	iocp = (void *)mp->b_rptr;
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;

	DPRINTF(0, (CE_CONT, "%s: %s cmd:0x%x", dp->name, __func__, cmd));

	mutex_enter(&dp->intrlock);
	mutex_enter(&dp->xmitlock);

	switch (cmd) {
	default:
		_NOTE(NOTREACHED)
		status = IOC_INVAL;
		break;

	case ND_GET:
	case ND_SET:
		status = gem_nd_ioctl(dp, wq, mp, iocp);
		break;
	}

	mutex_exit(&dp->xmitlock);
	mutex_exit(&dp->intrlock);

#ifdef DEBUG_RESUME
	if (cmd == ND_GET)  {
		gem_suspend(dp->dip);
		gem_resume(dp->dip);
	}
#endif
	/*
	 * Finally, decide how to reply
	 */
	switch (status) {
	default:
	case IOC_INVAL:
		/*
		 * Error, reply with a NAK and EINVAL or the specified error
		 */
		miocnak(wq, mp, 0, iocp->ioc_error == 0 ?
		    EINVAL : iocp->ioc_error);
		break;

	case IOC_DONE:
		/*
		 * OK, reply already sent
		 */
		break;

	case IOC_RESTART_ACK:
	case IOC_ACK:
		/*
		 * OK, reply with an ACK
		 */
		miocack(wq, mp, 0, 0);
		break;

	case IOC_RESTART_REPLY:
	case IOC_REPLY:
		/*
		 * OK, send prepared reply as ACK or NAK
		 */
		mp->b_datap->db_type =
		    iocp->ioc_error == 0 ? M_IOCACK : M_IOCNAK;
		qreply(wq, mp);
		break;
	}
}

#ifndef SYS_MAC_H
#define	XCVR_UNDEFINED	0
#define	XCVR_NONE	1
#define	XCVR_10		2
#define	XCVR_100T4	3
#define	XCVR_100X	4
#define	XCVR_100T2	5
#define	XCVR_1000X	6
#define	XCVR_1000T	7
#endif
static int
gem_mac_xcvr_inuse(struct gem_dev *dp)
{
	int	val = XCVR_UNDEFINED;

	if ((dp->mii_status & MII_STATUS_XSTATUS) == 0) {
		if (dp->mii_status & MII_STATUS_100_BASE_T4) {
			val = XCVR_100T4;
		} else if (dp->mii_status &
		    (MII_STATUS_100_BASEX_FD |
		    MII_STATUS_100_BASEX)) {
			val = XCVR_100X;
		} else if (dp->mii_status &
		    (MII_STATUS_100_BASE_T2_FD |
		    MII_STATUS_100_BASE_T2)) {
			val = XCVR_100T2;
		} else if (dp->mii_status &
		    (MII_STATUS_10_FD | MII_STATUS_10)) {
			val = XCVR_10;
		}
	} else if (dp->mii_xstatus &
	    (MII_XSTATUS_1000BASET_FD | MII_XSTATUS_1000BASET)) {
		val = XCVR_1000T;
	} else if (dp->mii_xstatus &
	    (MII_XSTATUS_1000BASEX_FD | MII_XSTATUS_1000BASEX)) {
		val = XCVR_1000X;
	}

	return (val);
}

/* ============================================================== */
/*
 * GLDv3 interface
 */
/* ============================================================== */
static int		gem_m_getstat(void *, uint_t, uint64_t *);
static int		gem_m_start(void *);
static void		gem_m_stop(void *);
static int		gem_m_setpromisc(void *, boolean_t);
static int		gem_m_multicst(void *, boolean_t, const uint8_t *);
static int		gem_m_unicst(void *, const uint8_t *);
static mblk_t		*gem_m_tx(void *, mblk_t *);
static void		gem_m_ioctl(void *, queue_t *, mblk_t *);
static boolean_t	gem_m_getcapab(void *, mac_capab_t, void *);

#define	GEM_M_CALLBACK_FLAGS	(MC_IOCTL | MC_GETCAPAB)

static mac_callbacks_t gem_m_callbacks = {
	GEM_M_CALLBACK_FLAGS,
	gem_m_getstat,
	gem_m_start,
	gem_m_stop,
	gem_m_setpromisc,
	gem_m_multicst,
	gem_m_unicst,
	gem_m_tx,
	NULL,
	gem_m_ioctl,
	gem_m_getcapab,
};

static int
gem_m_start(void *arg)
{
	int		err = 0;
	struct gem_dev *dp = arg;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	mutex_enter(&dp->intrlock);
	if (dp->mac_suspended) {
		err = EIO;
		goto x;
	}
	if (gem_mac_init(dp) != GEM_SUCCESS) {
		err = EIO;
		goto x;
	}
	dp->nic_state = NIC_STATE_INITIALIZED;

	/* reset rx filter state */
	dp->mc_count = 0;
	dp->mc_count_req = 0;

	/* setup media mode if the link have been up */
	if (dp->mii_state == MII_STATE_LINKUP) {
		(dp->gc.gc_set_media)(dp);
	}

	/* setup initial rx filter */
	bcopy(dp->dev_addr.ether_addr_octet,
	    dp->cur_addr.ether_addr_octet, ETHERADDRL);
	dp->rxmode |= RXMODE_ENABLE;

	if (gem_mac_set_rx_filter(dp) != GEM_SUCCESS) {
		err = EIO;
		goto x;
	}

	dp->nic_state = NIC_STATE_ONLINE;
	if (dp->mii_state == MII_STATE_LINKUP) {
		if (gem_mac_start(dp) != GEM_SUCCESS) {
			err = EIO;
			goto x;
		}
	}

	dp->timeout_id = timeout((void (*)(void *))gem_tx_timeout,
	    (void *)dp, dp->gc.gc_tx_timeout_interval);
	mutex_exit(&dp->intrlock);

	return (0);
x:
	dp->nic_state = NIC_STATE_STOPPED;
	mutex_exit(&dp->intrlock);
	return (err);
}

static void
gem_m_stop(void *arg)
{
	struct gem_dev	*dp = arg;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* stop rx */
	mutex_enter(&dp->intrlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->intrlock);
		return;
	}
	dp->rxmode &= ~RXMODE_ENABLE;
	(void) gem_mac_set_rx_filter(dp);
	mutex_exit(&dp->intrlock);

	/* stop tx timeout watcher */
	if (dp->timeout_id) {
		while (untimeout(dp->timeout_id) == -1)
			;
		dp->timeout_id = 0;
	}

	/* make the nic state inactive */
	mutex_enter(&dp->intrlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->intrlock);
		return;
	}
	dp->nic_state = NIC_STATE_STOPPED;

	/* we need deassert mac_active due to block interrupt handler */
	mutex_enter(&dp->xmitlock);
	dp->mac_active = B_FALSE;
	mutex_exit(&dp->xmitlock);

	/* block interrupts */
	while (dp->intr_busy) {
		cv_wait(&dp->tx_drain_cv, &dp->intrlock);
	}
	(void) gem_mac_stop(dp, 0);
	mutex_exit(&dp->intrlock);
}

static int
gem_m_multicst(void *arg, boolean_t add, const uint8_t *ep)
{
	int		err;
	int		ret;
	struct gem_dev	*dp = arg;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	if (add) {
		ret = gem_add_multicast(dp, ep);
	} else {
		ret = gem_remove_multicast(dp, ep);
	}

	err = 0;
	if (ret != GEM_SUCCESS) {
		err = EIO;
	}

	return (err);
}

static int
gem_m_setpromisc(void *arg, boolean_t on)
{
	int		err = 0;	/* no error */
	struct gem_dev	*dp = arg;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	mutex_enter(&dp->intrlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->intrlock);
		return (EIO);
	}
	if (on) {
		dp->rxmode |= RXMODE_PROMISC;
	} else {
		dp->rxmode &= ~RXMODE_PROMISC;
	}

	if (gem_mac_set_rx_filter(dp) != GEM_SUCCESS) {
		err = EIO;
	}
	mutex_exit(&dp->intrlock);

	return (err);
}

int
gem_m_getstat(void *arg, uint_t stat, uint64_t *valp)
{
	struct gem_dev		*dp = arg;
	struct gem_stats	*gstp = &dp->stats;
	uint64_t		val = 0;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	if (mutex_owned(&dp->intrlock)) {
		if (dp->mac_suspended) {
			return (EIO);
		}
	} else {
		mutex_enter(&dp->intrlock);
		if (dp->mac_suspended) {
			mutex_exit(&dp->intrlock);
			return (EIO);
		}
		mutex_exit(&dp->intrlock);
	}

	if ((*dp->gc.gc_get_stats)(dp) != GEM_SUCCESS) {
		return (EIO);
	}

	switch (stat) {
	case MAC_STAT_IFSPEED:
		val = gem_speed_value[dp->speed] *1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		val = gstp->rmcast;
		break;

	case MAC_STAT_BRDCSTRCV:
		val = gstp->rbcast;
		break;

	case MAC_STAT_MULTIXMT:
		val = gstp->omcast;
		break;

	case MAC_STAT_BRDCSTXMT:
		val = gstp->obcast;
		break;

	case MAC_STAT_NORCVBUF:
		val = gstp->norcvbuf + gstp->missed;
		break;

	case MAC_STAT_IERRORS:
		val = gstp->errrcv;
		break;

	case MAC_STAT_NOXMTBUF:
		val = gstp->noxmtbuf;
		break;

	case MAC_STAT_OERRORS:
		val = gstp->errxmt;
		break;

	case MAC_STAT_COLLISIONS:
		val = gstp->collisions;
		break;

	case MAC_STAT_RBYTES:
		val = gstp->rbytes;
		break;

	case MAC_STAT_IPACKETS:
		val = gstp->rpackets;
		break;

	case MAC_STAT_OBYTES:
		val = gstp->obytes;
		break;

	case MAC_STAT_OPACKETS:
		val = gstp->opackets;
		break;

	case MAC_STAT_UNDERFLOWS:
		val = gstp->underflow;
		break;

	case MAC_STAT_OVERFLOWS:
		val = gstp->overflow;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		val = gstp->frame;
		break;

	case ETHER_STAT_FCS_ERRORS:
		val = gstp->crc;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		val = gstp->first_coll;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		val = gstp->multi_coll;
		break;

	case ETHER_STAT_SQE_ERRORS:
		val = gstp->sqe;
		break;

	case ETHER_STAT_DEFER_XMTS:
		val = gstp->defer;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		val = gstp->xmtlatecoll;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		val = gstp->excoll;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		val = gstp->xmit_internal_err;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		val = gstp->nocarrier;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		val = gstp->frame_too_long;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		val = gstp->rcv_internal_err;
		break;

	case ETHER_STAT_XCVR_ADDR:
		val = dp->mii_phy_addr;
		break;

	case ETHER_STAT_XCVR_ID:
		val = dp->mii_phy_id;
		break;

	case ETHER_STAT_XCVR_INUSE:
		val = gem_mac_xcvr_inuse(dp);
		break;

	case ETHER_STAT_CAP_1000FDX:
		val = (dp->mii_xstatus & MII_XSTATUS_1000BASET_FD) ||
		    (dp->mii_xstatus & MII_XSTATUS_1000BASEX_FD);
		break;

	case ETHER_STAT_CAP_1000HDX:
		val = (dp->mii_xstatus & MII_XSTATUS_1000BASET) ||
		    (dp->mii_xstatus & MII_XSTATUS_1000BASEX);
		break;

	case ETHER_STAT_CAP_100FDX:
		val = BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX_FD);
		break;

	case ETHER_STAT_CAP_100HDX:
		val = BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX);
		break;

	case ETHER_STAT_CAP_10FDX:
		val = BOOLEAN(dp->mii_status & MII_STATUS_10_FD);
		break;

	case ETHER_STAT_CAP_10HDX:
		val = BOOLEAN(dp->mii_status & MII_STATUS_10);
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		val = BOOLEAN(dp->gc.gc_flow_control & 2);
		break;

	case ETHER_STAT_CAP_PAUSE:
		val = BOOLEAN(dp->gc.gc_flow_control & 1);
		break;

	case ETHER_STAT_CAP_AUTONEG:
		val = BOOLEAN(dp->mii_status & MII_STATUS_CANAUTONEG);
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		val = dp->anadv_1000fdx;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		val = dp->anadv_1000hdx;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		val = dp->anadv_100fdx;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		val = dp->anadv_100hdx;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		val = dp->anadv_10fdx;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		val = dp->anadv_10hdx;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		val = BOOLEAN(dp->anadv_flow_control & 2);
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		val = BOOLEAN(dp->anadv_flow_control & 1);
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		val = dp->anadv_autoneg;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		val = BOOLEAN(dp->mii_stat1000 & MII_1000TS_LP_FULL);
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
		val = BOOLEAN(dp->mii_stat1000 & MII_1000TS_LP_HALF);
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_100BASE_TX_FD);
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_100BASE_TX);
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_10BASE_T_FD);
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_10BASE_T);
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_ASMPAUSE);
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_PAUSE);
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		val = BOOLEAN(dp->mii_exp & MII_AN_EXP_LPCANAN);
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		val = BOOLEAN(dp->flow_control & 2);
		break;

	case ETHER_STAT_LINK_PAUSE:
		val = BOOLEAN(dp->flow_control & 1);
		break;

	case ETHER_STAT_LINK_AUTONEG:
		val = dp->anadv_autoneg &&
		    BOOLEAN(dp->mii_exp & MII_AN_EXP_LPCANAN);
		break;

	case ETHER_STAT_LINK_DUPLEX:
		val = (dp->mii_state == MII_STATE_LINKUP) ?
		    (dp->full_duplex ? 2 : 1) : 0;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		val = gstp->runt;
		break;
	case ETHER_STAT_LP_REMFAULT:
		val = BOOLEAN(dp->mii_lpable & MII_AN_ADVERT_REMFAULT);
		break;

	case ETHER_STAT_JABBER_ERRORS:
		val = gstp->jabber;
		break;

	case ETHER_STAT_CAP_100T4:
		val = BOOLEAN(dp->mii_status & MII_STATUS_100_BASE_T4);
		break;

	case ETHER_STAT_ADV_CAP_100T4:
		val = dp->anadv_100t4;
		break;

	case ETHER_STAT_LP_CAP_100T4:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_100BASE_T4);
		break;

	default:
#if GEM_DEBUG_LEVEL > 2
		cmn_err(CE_WARN,
		    "%s: unrecognized parameter value = %d",
		    __func__, stat);
#endif
		return (ENOTSUP);
	}

	*valp = val;

	return (0);
}

static int
gem_m_unicst(void *arg, const uint8_t *mac)
{
	int		err = 0;
	struct gem_dev	*dp = arg;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	mutex_enter(&dp->intrlock);
	if (dp->mac_suspended) {
		mutex_exit(&dp->intrlock);
		return (EIO);
	}
	bcopy(mac, dp->cur_addr.ether_addr_octet, ETHERADDRL);
	dp->rxmode |= RXMODE_ENABLE;

	if (gem_mac_set_rx_filter(dp) != GEM_SUCCESS) {
		err = EIO;
	}
	mutex_exit(&dp->intrlock);

	return (err);
}

/*
 * gem_m_tx is used only for sending data packets into ethernet wire.
 */
static mblk_t *
gem_m_tx(void *arg, mblk_t *mp)
{
	uint32_t	flags = 0;
	struct gem_dev	*dp = arg;
	mblk_t		*tp;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	ASSERT(dp->nic_state == NIC_STATE_ONLINE);
	if (dp->mii_state != MII_STATE_LINKUP) {
		/* Some nics hate to send packets when the link is down. */
		while (mp) {
			tp = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
			mp = tp;
		}
		return (NULL);
	}

	return (gem_send_common(dp, mp, flags));
}

static void
gem_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	DPRINTF(0, (CE_CONT, "!%s: %s: called",
	    ((struct gem_dev *)arg)->name, __func__));

	gem_mac_ioctl((struct gem_dev *)arg, wq, mp);
}

/* ARGSUSED */
static boolean_t
gem_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	return (B_FALSE);
}

static void
gem_gld3_init(struct gem_dev *dp, mac_register_t *macp)
{
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = dp;
	macp->m_dip = dp->dip;
	macp->m_src_addr = dp->dev_addr.ether_addr_octet;
	macp->m_callbacks = &gem_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = dp->mtu;

	if (dp->misc_flag & GEM_VLAN) {
		macp->m_margin = VTAG_SIZE;
	}
}

/* ======================================================================== */
/*
 * attach/detatch support
 */
/* ======================================================================== */
static void
gem_read_conf(struct gem_dev *dp)
{
	int	val;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/*
	 * Get media mode infomation from .conf file
	 */
	dp->anadv_autoneg = gem_prop_get_int(dp, "adv_autoneg_cap", 1) != 0;
	dp->anadv_1000fdx = gem_prop_get_int(dp, "adv_1000fdx_cap", 1) != 0;
	dp->anadv_1000hdx = gem_prop_get_int(dp, "adv_1000hdx_cap", 1) != 0;
	dp->anadv_100t4   = gem_prop_get_int(dp, "adv_100T4_cap", 1) != 0;
	dp->anadv_100fdx  = gem_prop_get_int(dp, "adv_100fdx_cap", 1) != 0;
	dp->anadv_100hdx  = gem_prop_get_int(dp, "adv_100hdx_cap", 1) != 0;
	dp->anadv_10fdx   = gem_prop_get_int(dp, "adv_10fdx_cap", 1) != 0;
	dp->anadv_10hdx   = gem_prop_get_int(dp, "adv_10hdx_cap", 1) != 0;

	if ((ddi_prop_exists(DDI_DEV_T_ANY, dp->dip,
	    DDI_PROP_DONTPASS, "full-duplex"))) {
		dp->full_duplex = gem_prop_get_int(dp, "full-duplex", 1) != 0;
		dp->anadv_autoneg = B_FALSE;
		if (dp->full_duplex) {
			dp->anadv_1000hdx = B_FALSE;
			dp->anadv_100hdx = B_FALSE;
			dp->anadv_10hdx = B_FALSE;
		} else {
			dp->anadv_1000fdx = B_FALSE;
			dp->anadv_100fdx = B_FALSE;
			dp->anadv_10fdx = B_FALSE;
		}
	}

	if ((val = gem_prop_get_int(dp, "speed", 0)) > 0) {
		dp->anadv_autoneg = B_FALSE;
		switch (val) {
		case 1000:
			dp->speed = GEM_SPD_1000;
			dp->anadv_100t4   = B_FALSE;
			dp->anadv_100fdx  = B_FALSE;
			dp->anadv_100hdx  = B_FALSE;
			dp->anadv_10fdx   = B_FALSE;
			dp->anadv_10hdx   = B_FALSE;
			break;
		case 100:
			dp->speed = GEM_SPD_100;
			dp->anadv_1000fdx = B_FALSE;
			dp->anadv_1000hdx = B_FALSE;
			dp->anadv_10fdx   = B_FALSE;
			dp->anadv_10hdx   = B_FALSE;
			break;
		case 10:
			dp->speed = GEM_SPD_10;
			dp->anadv_1000fdx = B_FALSE;
			dp->anadv_1000hdx = B_FALSE;
			dp->anadv_100t4   = B_FALSE;
			dp->anadv_100fdx  = B_FALSE;
			dp->anadv_100hdx  = B_FALSE;
			break;
		default:
			cmn_err(CE_WARN,
			    "!%s: property %s: illegal value:%d",
			    dp->name, "speed", val);
			dp->anadv_autoneg = B_TRUE;
			break;
		}
	}

	val = gem_prop_get_int(dp, "flow-control", dp->gc.gc_flow_control);
	if (val > FLOW_CONTROL_RX_PAUSE || val < FLOW_CONTROL_NONE) {
		cmn_err(CE_WARN,
		    "!%s: property %s: illegal value:%d",
		    dp->name, "flow-control", val);
	} else {
		val = min(val, dp->gc.gc_flow_control);
	}
	dp->anadv_flow_control = val;

	if (gem_prop_get_int(dp, "nointr", 0)) {
		dp->misc_flag |= GEM_NOINTR;
		cmn_err(CE_NOTE, "!%s: polling mode enabled", dp->name);
	}

	dp->mtu = gem_prop_get_int(dp, "mtu", dp->mtu);
	dp->txthr = gem_prop_get_int(dp, "txthr", dp->txthr);
	dp->rxthr = gem_prop_get_int(dp, "rxthr", dp->rxthr);
	dp->txmaxdma = gem_prop_get_int(dp, "txmaxdma", dp->txmaxdma);
	dp->rxmaxdma = gem_prop_get_int(dp, "rxmaxdma", dp->rxmaxdma);
}


/*
 * Gem kstat support
 */

#define	GEM_LOCAL_DATA_SIZE(gc)	\
	(sizeof (struct gem_dev) + \
	sizeof (struct mcast_addr) * GEM_MAXMC + \
	sizeof (struct txbuf) * ((gc)->gc_tx_buf_size) + \
	sizeof (void *) * ((gc)->gc_tx_buf_size))

struct gem_dev *
gem_do_attach(dev_info_t *dip, int port,
	struct gem_conf *gc, void *base, ddi_acc_handle_t *regs_handlep,
	void *lp, int lmsize)
{
	struct gem_dev		*dp;
	int			i;
	ddi_iblock_cookie_t	c;
	mac_register_t		*macp = NULL;
	int			ret;
	int			unit;
	int			nports;

	unit = ddi_get_instance(dip);
	if ((nports = gc->gc_nports) == 0) {
		nports = 1;
	}
	if (nports == 1) {
		ddi_set_driver_private(dip, NULL);
	}

	DPRINTF(2, (CE_CONT, "!gem%d: gem_do_attach: called cmd:ATTACH",
	    unit));

	/*
	 * Allocate soft data structure
	 */
	dp = kmem_zalloc(GEM_LOCAL_DATA_SIZE(gc), KM_SLEEP);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		cmn_err(CE_WARN, "!gem%d: %s: mac_alloc failed",
		    unit, __func__);
		return (NULL);
	}
	/* ddi_set_driver_private(dip, dp); */

	/* link to private area */
	dp->private = lp;
	dp->priv_size = lmsize;
	dp->mc_list = (struct mcast_addr *)&dp[1];

	dp->dip = dip;
	(void) sprintf(dp->name, gc->gc_name, nports * unit + port);

	/*
	 * Get iblock cookie
	 */
	if (ddi_get_iblock_cookie(dip, 0, &c) != DDI_SUCCESS) {
		cmn_err(CE_CONT,
		    "!%s: gem_do_attach: ddi_get_iblock_cookie: failed",
		    dp->name);
		goto err_free_private;
	}
	dp->iblock_cookie = c;

	/*
	 * Initialize mutex's for this device.
	 */
	mutex_init(&dp->intrlock, NULL, MUTEX_DRIVER, (void *)c);
	mutex_init(&dp->xmitlock, NULL, MUTEX_DRIVER, (void *)c);
	cv_init(&dp->tx_drain_cv, NULL, CV_DRIVER, NULL);

	/*
	 * configure gem parameter
	 */
	dp->base_addr = base;
	dp->regs_handle = *regs_handlep;
	dp->gc = *gc;
	gc = &dp->gc;
	/* patch for simplify dma resource management */
	gc->gc_tx_max_frags = 1;
	gc->gc_tx_max_descs_per_pkt = 1;
	gc->gc_tx_ring_size = gc->gc_tx_buf_size;
	gc->gc_tx_ring_limit = gc->gc_tx_buf_limit;
	gc->gc_tx_desc_write_oo = B_TRUE;

	gc->gc_nports = nports;	/* fix nports */

	/* fix copy threadsholds */
	gc->gc_tx_copy_thresh = max(ETHERMIN, gc->gc_tx_copy_thresh);
	gc->gc_rx_copy_thresh = max(ETHERMIN, gc->gc_rx_copy_thresh);

	/* fix rx buffer boundary for iocache line size */
	ASSERT(gc->gc_dma_attr_txbuf.dma_attr_align-1 == gc->gc_tx_buf_align);
	ASSERT(gc->gc_dma_attr_rxbuf.dma_attr_align-1 == gc->gc_rx_buf_align);
	gc->gc_rx_buf_align = max(gc->gc_rx_buf_align, IOC_LINESIZE - 1);
	gc->gc_dma_attr_rxbuf.dma_attr_align = gc->gc_rx_buf_align + 1;

	/* fix descriptor boundary for cache line size */
	gc->gc_dma_attr_desc.dma_attr_align =
	    max(gc->gc_dma_attr_desc.dma_attr_align, IOC_LINESIZE);

	/* patch get_packet method */
	if (gc->gc_get_packet == NULL) {
		gc->gc_get_packet = &gem_get_packet_default;
	}

	/* patch get_rx_start method */
	if (gc->gc_rx_start == NULL) {
		gc->gc_rx_start = &gem_rx_start_default;
	}

	/* calculate descriptor area */
	if (gc->gc_rx_desc_unit_shift >= 0) {
		dp->rx_desc_size =
		    ROUNDUP(gc->gc_rx_ring_size << gc->gc_rx_desc_unit_shift,
		    gc->gc_dma_attr_desc.dma_attr_align);
	}
	if (gc->gc_tx_desc_unit_shift >= 0) {
		dp->tx_desc_size =
		    ROUNDUP(gc->gc_tx_ring_size << gc->gc_tx_desc_unit_shift,
		    gc->gc_dma_attr_desc.dma_attr_align);
	}

	dp->mtu = ETHERMTU;
	dp->tx_buf = (void *)&dp->mc_list[GEM_MAXMC];
	/* link tx buffers */
	for (i = 0; i < dp->gc.gc_tx_buf_size; i++) {
		dp->tx_buf[i].txb_next =
		    &dp->tx_buf[SLOT(i + 1, dp->gc.gc_tx_buf_size)];
	}

	dp->rxmode	   = 0;
	dp->speed	   = GEM_SPD_10;	/* default is 10Mbps */
	dp->full_duplex    = B_FALSE;		/* default is half */
	dp->flow_control   = FLOW_CONTROL_NONE;
	dp->poll_pkt_delay = 8;		/* typical coalease for rx packets */

	/* performance tuning parameters */
	dp->txthr    = ETHERMAX;	/* tx fifo threshold */
	dp->txmaxdma = 16*4;		/* tx max dma burst size */
	dp->rxthr    = 128;		/* rx fifo threshold */
	dp->rxmaxdma = 16*4;		/* rx max dma burst size */

	/*
	 * Get media mode information from .conf file
	 */
	gem_read_conf(dp);

	/* rx_buf_len is required buffer length without padding for alignment */
	dp->rx_buf_len = MAXPKTBUF(dp) + dp->gc.gc_rx_header_len;

	/*
	 * Reset the chip
	 */
	mutex_enter(&dp->intrlock);
	dp->nic_state = NIC_STATE_STOPPED;
	ret = (*dp->gc.gc_reset_chip)(dp);
	mutex_exit(&dp->intrlock);
	if (ret != GEM_SUCCESS) {
		goto err_free_regs;
	}

	/*
	 * HW dependant paremeter initialization
	 */
	mutex_enter(&dp->intrlock);
	ret = (*dp->gc.gc_attach_chip)(dp);
	mutex_exit(&dp->intrlock);
	if (ret != GEM_SUCCESS) {
		goto err_free_regs;
	}

#ifdef DEBUG_MULTIFRAGS
	dp->gc.gc_tx_copy_thresh = dp->mtu;
#endif
	/* allocate tx and rx resources */
	if (gem_alloc_memory(dp)) {
		goto err_free_regs;
	}

	DPRINTF(0, (CE_CONT,
	    "!%s: at 0x%x, %02x:%02x:%02x:%02x:%02x:%02x",
	    dp->name, (long)dp->base_addr,
	    dp->dev_addr.ether_addr_octet[0],
	    dp->dev_addr.ether_addr_octet[1],
	    dp->dev_addr.ether_addr_octet[2],
	    dp->dev_addr.ether_addr_octet[3],
	    dp->dev_addr.ether_addr_octet[4],
	    dp->dev_addr.ether_addr_octet[5]));

	/* copy mac address */
	dp->cur_addr = dp->dev_addr;

	gem_gld3_init(dp, macp);

	/* Probe MII phy (scan phy) */
	dp->mii_lpable = 0;
	dp->mii_advert = 0;
	dp->mii_exp = 0;
	dp->mii_ctl1000 = 0;
	dp->mii_stat1000 = 0;
	if ((*dp->gc.gc_mii_probe)(dp) != GEM_SUCCESS) {
		goto err_free_ring;
	}

	/* mask unsupported abilities */
	dp->anadv_autoneg &= BOOLEAN(dp->mii_status & MII_STATUS_CANAUTONEG);
	dp->anadv_1000fdx &=
	    BOOLEAN(dp->mii_xstatus &
	    (MII_XSTATUS_1000BASEX_FD | MII_XSTATUS_1000BASET_FD));
	dp->anadv_1000hdx &=
	    BOOLEAN(dp->mii_xstatus &
	    (MII_XSTATUS_1000BASEX | MII_XSTATUS_1000BASET));
	dp->anadv_100t4  &= BOOLEAN(dp->mii_status & MII_STATUS_100_BASE_T4);
	dp->anadv_100fdx &= BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX_FD);
	dp->anadv_100hdx &= BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX);
	dp->anadv_10fdx  &= BOOLEAN(dp->mii_status & MII_STATUS_10_FD);
	dp->anadv_10hdx  &= BOOLEAN(dp->mii_status & MII_STATUS_10);

	gem_choose_forcedmode(dp);

	/* initialize MII phy if required */
	if (dp->gc.gc_mii_init) {
		if ((*dp->gc.gc_mii_init)(dp) != GEM_SUCCESS) {
			goto err_free_ring;
		}
	}

	/*
	 * initialize kstats including mii statistics
	 */
	gem_nd_setup(dp);

	/*
	 * Add interrupt to system.
	 */
	if (ret = mac_register(macp, &dp->mh)) {
		cmn_err(CE_WARN, "!%s: mac_register failed, error:%d",
		    dp->name, ret);
		goto err_release_stats;
	}
	mac_free(macp);
	macp = NULL;

	if (dp->misc_flag & GEM_SOFTINTR) {
		if (ddi_add_softintr(dip,
		    DDI_SOFTINT_LOW, &dp->soft_id,
		    NULL, NULL,
		    (uint_t (*)(caddr_t))gem_intr,
		    (caddr_t)dp) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!%s: ddi_add_softintr failed",
			    dp->name);
			goto err_unregister;
		}
	} else if ((dp->misc_flag & GEM_NOINTR) == 0) {
		if (ddi_add_intr(dip, 0, NULL, NULL,
		    (uint_t (*)(caddr_t))gem_intr,
		    (caddr_t)dp) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!%s: ddi_add_intr failed", dp->name);
			goto err_unregister;
		}
	} else {
		/*
		 * Dont use interrupt.
		 * schedule first call of gem_intr_watcher
		 */
		dp->intr_watcher_id =
		    timeout((void (*)(void *))gem_intr_watcher,
		    (void *)dp, drv_usectohz(3*1000000));
	}

	/* link this device to dev_info */
	dp->next = (struct gem_dev *)ddi_get_driver_private(dip);
	dp->port = port;
	ddi_set_driver_private(dip, (caddr_t)dp);

	/* reset mii phy and start mii link watcher */
	gem_mii_start(dp);

	DPRINTF(2, (CE_CONT, "!gem_do_attach: return: success"));
	return (dp);

err_unregister:
	(void) mac_unregister(dp->mh);
err_release_stats:
	/* release NDD resources */
	gem_nd_cleanup(dp);

err_free_ring:
	gem_free_memory(dp);
err_free_regs:
	ddi_regs_map_free(&dp->regs_handle);
err_free_locks:
	mutex_destroy(&dp->xmitlock);
	mutex_destroy(&dp->intrlock);
	cv_destroy(&dp->tx_drain_cv);
err_free_private:
	if (macp) {
		mac_free(macp);
	}
	kmem_free((caddr_t)dp, GEM_LOCAL_DATA_SIZE(gc));

	return (NULL);
}

int
gem_do_detach(dev_info_t *dip)
{
	struct gem_dev	*dp;
	struct gem_dev	*tmp;
	caddr_t		private;
	int		priv_size;
	ddi_acc_handle_t	rh;

	dp = GEM_GET_DEV(dip);
	if (dp == NULL) {
		return (DDI_SUCCESS);
	}

	rh = dp->regs_handle;
	private = dp->private;
	priv_size = dp->priv_size;

	while (dp) {
		/* unregister with gld v3 */
		if (mac_unregister(dp->mh) != 0) {
			return (DDI_FAILURE);
		}

		/* ensure any rx buffers are not used */
		if (dp->rx_buf_allocated != dp->rx_buf_freecnt) {
			/* resource is busy */
			cmn_err(CE_PANIC,
			    "!%s: %s: rxbuf is busy: allocated:%d, freecnt:%d",
			    dp->name, __func__,
			    dp->rx_buf_allocated, dp->rx_buf_freecnt);
			/* NOT REACHED */
		}

		/* stop mii link watcher */
		gem_mii_stop(dp);

		/* unregister interrupt handler */
		if (dp->misc_flag & GEM_SOFTINTR) {
			ddi_remove_softintr(dp->soft_id);
		} else if ((dp->misc_flag & GEM_NOINTR) == 0) {
			ddi_remove_intr(dip, 0, dp->iblock_cookie);
		} else {
			/* stop interrupt watcher */
			if (dp->intr_watcher_id) {
				while (untimeout(dp->intr_watcher_id) == -1)
					;
				dp->intr_watcher_id = 0;
			}
		}

		/* release NDD resources */
		gem_nd_cleanup(dp);
		/* release buffers, descriptors and dma resources */
		gem_free_memory(dp);

		/* release locks and condition variables */
		mutex_destroy(&dp->xmitlock);
		mutex_destroy(&dp->intrlock);
		cv_destroy(&dp->tx_drain_cv);

		/* release basic memory resources */
		tmp = dp->next;
		kmem_free((caddr_t)dp, GEM_LOCAL_DATA_SIZE(&dp->gc));
		dp = tmp;
	}

	/* release common private memory for the nic */
	kmem_free(private, priv_size);

	/* release register mapping resources */
	ddi_regs_map_free(&rh);

	DPRINTF(2, (CE_CONT, "!%s%d: gem_do_detach: return: success",
	    ddi_driver_name(dip), ddi_get_instance(dip)));

	return (DDI_SUCCESS);
}

int
gem_suspend(dev_info_t *dip)
{
	struct gem_dev	*dp;

	/*
	 * stop the device
	 */
	dp = GEM_GET_DEV(dip);
	ASSERT(dp);

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	for (; dp; dp = dp->next) {

		/* stop mii link watcher */
		gem_mii_stop(dp);

		/* stop interrupt watcher for no-intr mode */
		if (dp->misc_flag & GEM_NOINTR) {
			if (dp->intr_watcher_id) {
				while (untimeout(dp->intr_watcher_id) == -1)
					;
			}
			dp->intr_watcher_id = 0;
		}

		/* stop tx timeout watcher */
		if (dp->timeout_id) {
			while (untimeout(dp->timeout_id) == -1)
				;
			dp->timeout_id = 0;
		}

		/* make the nic state inactive */
		mutex_enter(&dp->intrlock);
		(void) gem_mac_stop(dp, 0);
		ASSERT(!dp->mac_active);

		/* no further register access */
		dp->mac_suspended = B_TRUE;
		mutex_exit(&dp->intrlock);
	}

	/* XXX - power down the nic */

	return (DDI_SUCCESS);
}

int
gem_resume(dev_info_t *dip)
{
	struct gem_dev	*dp;

	/*
	 * restart the device
	 */
	dp = GEM_GET_DEV(dip);
	ASSERT(dp);

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	for (; dp; dp = dp->next) {

		/*
		 * Bring up the nic after power up
		 */

		/* gem_xxx.c layer to setup power management state. */
		ASSERT(!dp->mac_active);

		/* reset the chip, because we are just after power up. */
		mutex_enter(&dp->intrlock);

		dp->mac_suspended = B_FALSE;
		dp->nic_state = NIC_STATE_STOPPED;

		if ((*dp->gc.gc_reset_chip)(dp) != GEM_SUCCESS) {
			cmn_err(CE_WARN, "%s: %s: failed to reset chip",
			    dp->name, __func__);
			mutex_exit(&dp->intrlock);
			goto err;
		}
		mutex_exit(&dp->intrlock);

		/* initialize mii phy because we are just after power up */
		if (dp->gc.gc_mii_init) {
			(void) (*dp->gc.gc_mii_init)(dp);
		}

		if (dp->misc_flag & GEM_NOINTR) {
			/*
			 * schedule first call of gem_intr_watcher
			 * instead of interrupts.
			 */
			dp->intr_watcher_id =
			    timeout((void (*)(void *))gem_intr_watcher,
			    (void *)dp, drv_usectohz(3*1000000));
		}

		/* restart mii link watcher */
		gem_mii_start(dp);

		/* restart mac */
		mutex_enter(&dp->intrlock);

		if (gem_mac_init(dp) != GEM_SUCCESS) {
			mutex_exit(&dp->intrlock);
			goto err_reset;
		}
		dp->nic_state = NIC_STATE_INITIALIZED;

		/* setup media mode if the link have been up */
		if (dp->mii_state == MII_STATE_LINKUP) {
			if ((dp->gc.gc_set_media)(dp) != GEM_SUCCESS) {
				mutex_exit(&dp->intrlock);
				goto err_reset;
			}
		}

		/* enable mac address and rx filter */
		dp->rxmode |= RXMODE_ENABLE;
		if ((*dp->gc.gc_set_rx_filter)(dp) != GEM_SUCCESS) {
			mutex_exit(&dp->intrlock);
			goto err_reset;
		}
		dp->nic_state = NIC_STATE_ONLINE;

		/* restart tx timeout watcher */
		dp->timeout_id = timeout((void (*)(void *))gem_tx_timeout,
		    (void *)dp,
		    dp->gc.gc_tx_timeout_interval);

		/* now the nic is fully functional */
		if (dp->mii_state == MII_STATE_LINKUP) {
			if (gem_mac_start(dp) != GEM_SUCCESS) {
				mutex_exit(&dp->intrlock);
				goto err_reset;
			}
		}
		mutex_exit(&dp->intrlock);
	}

	return (DDI_SUCCESS);

err_reset:
	if (dp->intr_watcher_id) {
		while (untimeout(dp->intr_watcher_id) == -1)
			;
		dp->intr_watcher_id = 0;
	}
	mutex_enter(&dp->intrlock);
	(*dp->gc.gc_reset_chip)(dp);
	dp->nic_state = NIC_STATE_STOPPED;
	mutex_exit(&dp->intrlock);

err:
	return (DDI_FAILURE);
}

/*
 * misc routines for PCI
 */
uint8_t
gem_search_pci_cap(dev_info_t *dip,
		ddi_acc_handle_t conf_handle, uint8_t target)
{
	uint8_t		pci_cap_ptr;
	uint32_t	pci_cap;

	/* search power management capablities */
	pci_cap_ptr = pci_config_get8(conf_handle, PCI_CONF_CAP_PTR);
	while (pci_cap_ptr) {
		/* read pci capability header */
		pci_cap = pci_config_get32(conf_handle, pci_cap_ptr);
		if ((pci_cap & 0xff) == target) {
			/* found */
			break;
		}
		/* get next_ptr */
		pci_cap_ptr = (pci_cap >> 8) & 0xff;
	}
	return (pci_cap_ptr);
}

int
gem_pci_set_power_state(dev_info_t *dip,
		ddi_acc_handle_t conf_handle, uint_t new_mode)
{
	uint8_t		pci_cap_ptr;
	uint32_t	pmcsr;
	uint_t		unit;
	const char	*drv_name;

	ASSERT(new_mode < 4);

	unit = ddi_get_instance(dip);
	drv_name = ddi_driver_name(dip);

	/* search power management capablities */
	pci_cap_ptr = gem_search_pci_cap(dip, conf_handle, PCI_CAP_ID_PM);

	if (pci_cap_ptr == 0) {
		cmn_err(CE_CONT,
		    "!%s%d: doesn't have pci power management capability",
		    drv_name, unit);
		return (DDI_FAILURE);
	}

	/* read power management capabilities */
	pmcsr = pci_config_get32(conf_handle, pci_cap_ptr + PCI_PMCSR);

	DPRINTF(0, (CE_CONT,
	    "!%s%d: pmc found at 0x%x: pmcsr: 0x%08x",
	    drv_name, unit, pci_cap_ptr, pmcsr));

	/*
	 * Is the resuested power mode supported?
	 */
	/* not yet */

	/*
	 * move to new mode
	 */
	pmcsr = (pmcsr & ~PCI_PMCSR_STATE_MASK) | new_mode;
	pci_config_put32(conf_handle, pci_cap_ptr + PCI_PMCSR, pmcsr);

	return (DDI_SUCCESS);
}

/*
 * select suitable register for by specified address space or register
 * offset in PCI config space
 */
int
gem_pci_regs_map_setup(dev_info_t *dip, uint32_t which, uint32_t mask,
	struct ddi_device_acc_attr *attrp,
	caddr_t *basep, ddi_acc_handle_t *hp)
{
	struct pci_phys_spec	*regs;
	uint_t		len;
	uint_t		unit;
	uint_t		n;
	uint_t		i;
	int		ret;
	const char	*drv_name;

	unit = ddi_get_instance(dip);
	drv_name = ddi_driver_name(dip);

	/* Search IO-range or memory-range to be mapped */
	regs = NULL;
	len  = 0;

	if ((ret = ddi_prop_lookup_int_array(
	    DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (void *)&regs, &len)) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "!%s%d: failed to get reg property (ret:%d)",
		    drv_name, unit, ret);
		return (DDI_FAILURE);
	}
	n = len / (sizeof (struct pci_phys_spec) / sizeof (int));

	ASSERT(regs != NULL && len > 0);

#if GEM_DEBUG_LEVEL > 0
	for (i = 0; i < n; i++) {
		cmn_err(CE_CONT,
		    "!%s%d: regs[%d]: %08x.%08x.%08x.%08x.%08x",
		    drv_name, unit, i,
		    regs[i].pci_phys_hi,
		    regs[i].pci_phys_mid,
		    regs[i].pci_phys_low,
		    regs[i].pci_size_hi,
		    regs[i].pci_size_low);
	}
#endif
	for (i = 0; i < n; i++) {
		if ((regs[i].pci_phys_hi & mask) == which) {
			/* it's the requested space */
			ddi_prop_free(regs);
			goto address_range_found;
		}
	}
	ddi_prop_free(regs);
	return (DDI_FAILURE);

address_range_found:
	if ((ret = ddi_regs_map_setup(dip, i, basep, 0, 0, attrp, hp))
	    != DDI_SUCCESS) {
		cmn_err(CE_CONT,
		    "!%s%d: ddi_regs_map_setup failed (ret:%d)",
		    drv_name, unit, ret);
	}

	return (ret);
}

void
gem_mod_init(struct dev_ops *dop, char *name)
{
	mac_init_ops(dop, name);
}

void
gem_mod_fini(struct dev_ops *dop)
{
	mac_fini_ops(dop);
}
