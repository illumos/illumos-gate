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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * Copyright (c) 2004 Christian Limpach.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. This section intentionally left blank.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Section 3 of the above license was updated in response to bug 6379571.
 */

/*
 * xnf.c - Nemo-based network driver for domU
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/strsun.h>
#include <sys/pattr.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <sys/gld.h>
#include <sys/modctl.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/bootinfo.h>
#include <sys/mach_mmu.h>
#ifdef	XPV_HVM_DRIVER
#include <sys/xpv_support.h>
#include <sys/hypervisor.h>
#else
#include <sys/hypervisor.h>
#include <sys/evtchn_impl.h>
#include <sys/balloon_impl.h>
#endif
#include <xen/public/io/netif.h>
#include <sys/gnttab.h>
#include <xen/sys/xendev.h>
#include <sys/sdt.h>

#include <io/xnf.h>


/*
 *  Declarations and Module Linkage
 */

#define	IDENT	"Virtual Ethernet driver"

#if defined(DEBUG) || defined(__lint)
#define	XNF_DEBUG
int	xnfdebug = 0;
#endif

/*
 * On a 32 bit PAE system physical and machine addresses are larger
 * than 32 bits.  ddi_btop() on such systems take an unsigned long
 * argument, and so addresses above 4G are truncated before ddi_btop()
 * gets to see them.  To avoid this, code the shift operation here.
 */
#define	xnf_btop(addr)	((addr) >> PAGESHIFT)

boolean_t	xnf_cksum_offload = B_TRUE;

/* Default value for hypervisor-based copy operations */
boolean_t	xnf_rx_hvcopy = B_TRUE;

/*
 * Should pages used for transmit be readonly for the peer?
 */
boolean_t	xnf_tx_pages_readonly = B_FALSE;
/*
 * Packets under this size are bcopied instead of using desballoc.
 * Choose a value > XNF_FRAMESIZE (1514) to force the receive path to
 * always copy.
 */
unsigned int	xnf_rx_bcopy_thresh = 64;

unsigned int	xnf_max_tx_frags = 1;

/* Required system entry points */
static int	xnf_attach(dev_info_t *, ddi_attach_cmd_t);
static int	xnf_detach(dev_info_t *, ddi_detach_cmd_t);

/* Required driver entry points for Nemo */
static int	xnf_start(void *);
static void	xnf_stop(void *);
static int	xnf_set_mac_addr(void *, const uint8_t *);
static int	xnf_set_multicast(void *, boolean_t, const uint8_t *);
static int	xnf_set_promiscuous(void *, boolean_t);
static mblk_t	*xnf_send(void *, mblk_t *);
static uint_t	xnf_intr(caddr_t);
static int	xnf_stat(void *, uint_t, uint64_t *);
static void	xnf_blank(void *, time_t, uint_t);
static void	xnf_resources(void *);
static void	xnf_ioctl(void *, queue_t *, mblk_t *);
static boolean_t xnf_getcapab(void *, mac_capab_t, void *);

/* Driver private functions */
static int xnf_alloc_dma_resources(xnf_t *);
static void xnf_release_dma_resources(xnf_t *);
static mblk_t *xnf_process_recv(xnf_t *);
static void xnf_rcv_complete(struct xnf_buffer_desc *);
static void xnf_release_mblks(xnf_t *);
static struct xnf_buffer_desc *xnf_alloc_tx_buffer(xnf_t *);
static struct xnf_buffer_desc *xnf_alloc_buffer(xnf_t *);
static struct xnf_buffer_desc *xnf_get_tx_buffer(xnf_t *);
static struct xnf_buffer_desc *xnf_get_buffer(xnf_t *);
static void xnf_free_buffer(struct xnf_buffer_desc *);
static void xnf_free_tx_buffer(struct xnf_buffer_desc *);
void xnf_send_driver_status(int, int);
static void rx_buffer_hang(xnf_t *, struct xnf_buffer_desc *);
static int xnf_clean_tx_ring(xnf_t  *);
static void oe_state_change(dev_info_t *, ddi_eventcookie_t,
    void *, void *);
static mblk_t *xnf_process_hvcopy_recv(xnf_t *xnfp);
static boolean_t xnf_hvcopy_peer_status(dev_info_t *devinfo);
static boolean_t xnf_kstat_init(xnf_t *xnfp);

/*
 * XXPV dme: remove MC_IOCTL?
 */
static mac_callbacks_t xnf_callbacks = {
	MC_RESOURCES | MC_IOCTL | MC_GETCAPAB,
	xnf_stat,
	xnf_start,
	xnf_stop,
	xnf_set_promiscuous,
	xnf_set_multicast,
	xnf_set_mac_addr,
	xnf_send,
	xnf_resources,
	xnf_ioctl,
	xnf_getcapab
};

#define	GRANT_INVALID_REF	0
const int xnf_rx_bufs_lowat = 4 * NET_RX_RING_SIZE;
const int xnf_rx_bufs_hiwat = 8 * NET_RX_RING_SIZE; /* default max */

/* DMA attributes for network ring buffer */
static ddi_dma_attr_t ringbuf_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	MMU_PAGESIZE,		/* alignment in bytes */
	0x7ff,			/* bitmap of burst sizes */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

/* DMA attributes for transmit data */
static ddi_dma_attr_t tx_buffer_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	MMU_PAGESIZE,		/* alignment in bytes */
	0x7ff,			/* bitmap of burst sizes */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

/* DMA attributes for a receive buffer */
static ddi_dma_attr_t rx_buffer_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	MMU_PAGESIZE,		/* alignment in bytes */
	0x7ff,			/* bitmap of burst sizes */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

/* DMA access attributes for registers and descriptors */
static ddi_device_acc_attr_t accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,	/* This is a little-endian device */
	DDI_STRICTORDER_ACC
};

/* DMA access attributes for data: NOT to be byte swapped. */
static ddi_device_acc_attr_t data_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

unsigned char xnf_broadcastaddr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
int xnf_diagnose = 0; /* Patchable global for diagnostic purposes */

DDI_DEFINE_STREAM_OPS(xnf_dev_ops, nulldev, nulldev, xnf_attach, xnf_detach,
    nodev, NULL, D_MP, NULL);

static struct modldrv xnf_modldrv = {
	&mod_driverops,
	"Virtual Ethernet driver",
	&xnf_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &xnf_modldrv, NULL
};

int
_init(void)
{
	int r;

	mac_init_ops(&xnf_dev_ops, "xnf");
	r = mod_install(&modlinkage);
	if (r != DDI_SUCCESS)
		mac_fini_ops(&xnf_dev_ops);

	return (r);
}

int
_fini(void)
{
	return (EBUSY); /* XXPV dme: should be removable */
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
xnf_setup_rings(xnf_t *xnfp)
{
	int			ix, err;
	RING_IDX		i;
	struct xnf_buffer_desc	*bdesc, *rbp;
	struct xenbus_device	*xsd;
	domid_t			oeid;

	oeid = xvdi_get_oeid(xnfp->xnf_devinfo);
	xsd = xvdi_get_xsd(xnfp->xnf_devinfo);

	if (xnfp->xnf_tx_ring_ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(xnfp->xnf_tx_ring_ref, 0, 0);

	err = gnttab_grant_foreign_access(oeid,
	    xnf_btop(pa_to_ma(xnfp->xnf_tx_ring_phys_addr)), 0);
	if (err <= 0) {
		err = -err;
		xenbus_dev_error(xsd, err, "granting access to tx ring page");
		goto out;
	}
	xnfp->xnf_tx_ring_ref = (grant_ref_t)err;

	if (xnfp->xnf_rx_ring_ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(xnfp->xnf_rx_ring_ref, 0, 0);

	err = gnttab_grant_foreign_access(oeid,
	    xnf_btop(pa_to_ma(xnfp->xnf_rx_ring_phys_addr)), 0);
	if (err <= 0) {
		err = -err;
		xenbus_dev_error(xsd, err, "granting access to rx ring page");
		goto out;
	}
	xnfp->xnf_rx_ring_ref = (grant_ref_t)err;


	mutex_enter(&xnfp->xnf_intrlock);

	/*
	 * Cleanup the TX ring.  We just clean up any valid tx_pktinfo structs
	 * and reset the ring.  Note that this can lose packets after a resume,
	 * but we expect to stagger on.
	 */
	mutex_enter(&xnfp->xnf_txlock);

	for (i = 0; i < xnfp->xnf_n_tx; i++) {
		struct tx_pktinfo *txp = &xnfp->xnf_tx_pkt_info[i];

		txp->id = i + 1;

		if (txp->grant_ref == GRANT_INVALID_REF) {
			ASSERT(txp->mp == NULL);
			ASSERT(txp->bdesc == NULL);
			continue;
		}

		if (gnttab_query_foreign_access(txp->grant_ref) != 0)
			panic("tx grant still in use by backend domain");

		freemsg(txp->mp);
		txp->mp = NULL;

		(void) ddi_dma_unbind_handle(txp->dma_handle);

		if (txp->bdesc != NULL) {
			xnf_free_tx_buffer(txp->bdesc);
			txp->bdesc = NULL;
		}

		(void) gnttab_end_foreign_access_ref(txp->grant_ref,
		    xnfp->xnf_tx_pages_readonly);
		gnttab_release_grant_reference(&xnfp->xnf_gref_tx_head,
		    txp->grant_ref);
		txp->grant_ref = GRANT_INVALID_REF;
	}

	xnfp->xnf_tx_pkt_id_list = 0;
	xnfp->xnf_tx_ring.rsp_cons = 0;
	xnfp->xnf_tx_ring.req_prod_pvt = 0;

	/* LINTED: constant in conditional context */
	SHARED_RING_INIT(xnfp->xnf_tx_ring.sring);

	mutex_exit(&xnfp->xnf_txlock);

	/*
	 * Rebuild the RX ring.  We have to rebuild the RX ring because some of
	 * our pages are currently flipped out/granted so we can't just free
	 * the RX buffers.  Reclaim any unprocessed recv buffers, they won't be
	 * useable anyway since the mfn's they refer to are no longer valid.
	 * Grant the backend domain access to each hung rx buffer.
	 */
	i = xnfp->xnf_rx_ring.rsp_cons;
	while (i++ != xnfp->xnf_rx_ring.sring->req_prod) {
		volatile netif_rx_request_t	*rxrp;

		rxrp = RING_GET_REQUEST(&xnfp->xnf_rx_ring, i);
		ix = rxrp - RING_GET_REQUEST(&xnfp->xnf_rx_ring, 0);
		rbp = xnfp->xnf_rxpkt_bufptr[ix];
		if (rbp != NULL) {
			grant_ref_t	ref = rbp->grant_ref;

			ASSERT(ref != GRANT_INVALID_REF);
			if (xnfp->xnf_rx_hvcopy) {
				pfn_t pfn = xnf_btop(rbp->buf_phys);
				mfn_t mfn = pfn_to_mfn(pfn);

				gnttab_grant_foreign_access_ref(ref, oeid,
				    mfn, 0);
			} else {
				gnttab_grant_foreign_transfer_ref(ref,
				    oeid, 0);
			}
			rxrp->id = ix;
			rxrp->gref = ref;
		}
	}

	/*
	 * Reset the ring pointers to initial state.
	 * Hang buffers for any empty ring slots.
	 */
	xnfp->xnf_rx_ring.rsp_cons = 0;
	xnfp->xnf_rx_ring.req_prod_pvt = 0;

	/* LINTED: constant in conditional context */
	SHARED_RING_INIT(xnfp->xnf_rx_ring.sring);

	for (i = 0; i < NET_RX_RING_SIZE; i++) {
		xnfp->xnf_rx_ring.req_prod_pvt = i;
		if (xnfp->xnf_rxpkt_bufptr[i] != NULL)
			continue;
		if ((bdesc = xnf_get_buffer(xnfp)) == NULL)
			break;
		rx_buffer_hang(xnfp, bdesc);
	}
	xnfp->xnf_rx_ring.req_prod_pvt = i;
	/* LINTED: constant in conditional context */
	RING_PUSH_REQUESTS(&xnfp->xnf_rx_ring);

	mutex_exit(&xnfp->xnf_intrlock);

	return (0);

out:
	if (xnfp->xnf_tx_ring_ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(xnfp->xnf_tx_ring_ref, 0, 0);
	xnfp->xnf_tx_ring_ref = GRANT_INVALID_REF;

	if (xnfp->xnf_rx_ring_ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(xnfp->xnf_rx_ring_ref, 0, 0);
	xnfp->xnf_rx_ring_ref = GRANT_INVALID_REF;

	return (err);
}


/* Called when the upper layers free a message we passed upstream */
static void
xnf_copy_rcv_complete(struct xnf_buffer_desc *bdesc)
{
	(void) ddi_dma_unbind_handle(bdesc->dma_handle);
	ddi_dma_mem_free(&bdesc->acc_handle);
	ddi_dma_free_handle(&bdesc->dma_handle);
	kmem_free(bdesc, sizeof (*bdesc));
}


/*
 * Connect driver to back end, called to set up communication with
 * back end driver both initially and on resume after restore/migrate.
 */
void
xnf_be_connect(xnf_t *xnfp)
{
	const char	*message;
	xenbus_transaction_t xbt;
	struct		xenbus_device *xsd;
	char		*xsname;
	int		err;

	ASSERT(!xnfp->xnf_connected);

	xsd = xvdi_get_xsd(xnfp->xnf_devinfo);
	xsname = xvdi_get_xsname(xnfp->xnf_devinfo);

	err = xnf_setup_rings(xnfp);
	if (err != 0) {
		cmn_err(CE_WARN, "failed to set up tx/rx rings");
		xenbus_dev_error(xsd, err, "setting up ring");
		return;
	}

again:
	err = xenbus_transaction_start(&xbt);
	if (err != 0) {
		xenbus_dev_error(xsd, EIO, "starting transaction");
		return;
	}

	err = xenbus_printf(xbt, xsname, "tx-ring-ref", "%u",
	    xnfp->xnf_tx_ring_ref);
	if (err != 0) {
		message = "writing tx ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, xsname, "rx-ring-ref", "%u",
	    xnfp->xnf_rx_ring_ref);
	if (err != 0) {
		message = "writing rx ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, xsname, "event-channel", "%u",
	    xnfp->xnf_evtchn);
	if (err != 0) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, xsname, "feature-rx-notify", "%d", 1);
	if (err != 0) {
		message = "writing feature-rx-notify";
		goto abort_transaction;
	}

	if (!xnfp->xnf_tx_pages_readonly) {
		err = xenbus_printf(xbt, xsname, "feature-tx-writable",
		    "%d", 1);
		if (err != 0) {
			message = "writing feature-tx-writable";
			goto abort_transaction;
		}
	}

	err = xenbus_printf(xbt, xsname, "feature-no-csum-offload", "%d",
	    xnfp->xnf_cksum_offload ? 0 : 1);
	if (err != 0) {
		message = "writing feature-no-csum-offload";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, xsname, "request-rx-copy", "%d",
	    xnfp->xnf_rx_hvcopy ? 1 : 0);
	if (err != 0) {
		message = "writing request-rx-copy";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, xsname, "state", "%d", XenbusStateConnected);
	if (err != 0) {
		message = "writing frontend XenbusStateConnected";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err != 0) {
		if (err == EAGAIN)
			goto again;
		xenbus_dev_error(xsd, err, "completing transaction");
	}

	return;

abort_transaction:
	(void) xenbus_transaction_end(xbt, 1);
	xenbus_dev_error(xsd, err, "%s", message);
}

/*
 * Read config info from xenstore
 */
void
xnf_read_config(xnf_t *xnfp)
{
	char		mac[ETHERADDRL * 3];
	int		err, be_no_cksum_offload;

	err = xenbus_scanf(XBT_NULL, xvdi_get_oename(xnfp->xnf_devinfo), "mac",
	    "%s", (char *)&mac[0]);
	if (err != 0) {
		/*
		 * bad: we're supposed to be set up with a proper mac
		 * addr. at this point
		 */
		cmn_err(CE_WARN, "%s%d: no mac address",
		    ddi_driver_name(xnfp->xnf_devinfo),
		    ddi_get_instance(xnfp->xnf_devinfo));
			return;
	}
	if (ether_aton(mac, xnfp->xnf_mac_addr) != ETHERADDRL) {
		err = ENOENT;
		xenbus_dev_error(xvdi_get_xsd(xnfp->xnf_devinfo), ENOENT,
		    "parsing %s/mac", xvdi_get_xsname(xnfp->xnf_devinfo));
		return;
	}

	err = xenbus_scanf(XBT_NULL, xvdi_get_oename(xnfp->xnf_devinfo),
	    "feature-no-csum-offload", "%d", &be_no_cksum_offload);
	/*
	 * If we fail to read the store we assume that the key is
	 * absent, implying an older domain at the far end.  Older
	 * domains always support checksum offload.
	 */
	if (err != 0)
		be_no_cksum_offload = 0;
	/*
	 * If the far end cannot do checksum offload or we do not wish
	 * to do it, disable it.
	 */
	if ((be_no_cksum_offload == 1) || !xnfp->xnf_cksum_offload)
		xnfp->xnf_cksum_offload = B_FALSE;
}

/*
 *  attach(9E) -- Attach a device to the system
 *
 *  Called once for each board successfully probed.
 */
static int
xnf_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	mac_register_t *macp;
	xnf_t *xnfp;
	int err;

#ifdef XNF_DEBUG
	if (xnfdebug & XNF_DEBUG_DDI)
		printf("xnf%d: attach(0x%p)\n", ddi_get_instance(devinfo),
		    (void *)devinfo);
#endif

	switch (cmd) {
	case DDI_RESUME:
		xnfp = ddi_get_driver_private(devinfo);

		(void) xvdi_resume(devinfo);
		(void) xvdi_alloc_evtchn(devinfo);
		xnfp->xnf_evtchn = xvdi_get_evtchn(devinfo);
#ifdef XPV_HVM_DRIVER
		ec_bind_evtchn_to_handler(xnfp->xnf_evtchn, IPL_VIF, xnf_intr,
		    xnfp);
#else
		(void) ddi_add_intr(devinfo, 0, NULL, NULL, xnf_intr,
		    (caddr_t)xnfp);
#endif
		xnf_be_connect(xnfp);
		/*
		 * Our MAC address may have changed if we're resuming:
		 * - on a different host
		 * - on the same one and got a different MAC address
		 *   because we didn't specify one of our own.
		 * so it's useful to claim that it changed in order that
		 * IP send out a gratuitous ARP.
		 */
		mac_unicst_update(xnfp->xnf_mh, xnfp->xnf_mac_addr);
		return (DDI_SUCCESS);

	case DDI_ATTACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	/*
	 *  Allocate gld_mac_info_t and xnf_instance structures
	 */
	macp = mac_alloc(MAC_VERSION);
	if (macp == NULL)
		return (DDI_FAILURE);
	xnfp = kmem_zalloc(sizeof (*xnfp), KM_SLEEP);

	macp->m_dip = devinfo;
	macp->m_driver = xnfp;
	xnfp->xnf_devinfo = devinfo;

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_src_addr = xnfp->xnf_mac_addr;
	macp->m_callbacks = &xnf_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = XNF_MAXPKT;

	xnfp->xnf_running = B_FALSE;
	xnfp->xnf_connected = B_FALSE;
	xnfp->xnf_cksum_offload = xnf_cksum_offload;
	xnfp->xnf_tx_pages_readonly = xnf_tx_pages_readonly;

	xnfp->xnf_rx_hvcopy = xnf_hvcopy_peer_status(devinfo) && xnf_rx_hvcopy;
#ifdef XPV_HVM_DRIVER
	/*
	 * Report our version to dom0.
	 */
	if (xenbus_printf(XBT_NULL, "hvmpv/xnf", "version", "%d",
	    HVMPV_XNF_VERS))
		cmn_err(CE_WARN, "xnf: couldn't write version\n");

	if (!xnfp->xnf_rx_hvcopy) {
		cmn_err(CE_WARN, "The xnf driver requires a dom0 that "
		    "supports 'feature-rx-copy'");
		goto failure;
	}
#endif

	/*
	 * Get the iblock cookie with which to initialize the mutexes.
	 */
	if (ddi_get_iblock_cookie(devinfo, 0, &xnfp->xnf_icookie)
	    != DDI_SUCCESS)
		goto failure;
	/*
	 * Driver locking strategy: the txlock protects all paths
	 * through the driver, except the interrupt thread.
	 * If the interrupt thread needs to do something which could
	 * affect the operation of any other part of the driver,
	 * it needs to acquire the txlock mutex.
	 */
	mutex_init(&xnfp->xnf_tx_buf_mutex,
	    NULL, MUTEX_DRIVER, xnfp->xnf_icookie);
	mutex_init(&xnfp->xnf_rx_buf_mutex,
	    NULL, MUTEX_DRIVER, xnfp->xnf_icookie);
	mutex_init(&xnfp->xnf_txlock,
	    NULL, MUTEX_DRIVER, xnfp->xnf_icookie);
	mutex_init(&xnfp->xnf_intrlock,
	    NULL, MUTEX_DRIVER, xnfp->xnf_icookie);
	cv_init(&xnfp->xnf_cv, NULL, CV_DEFAULT, NULL);

	xnfp->xnf_gref_tx_head = (grant_ref_t)-1;
	xnfp->xnf_gref_rx_head = (grant_ref_t)-1;
	if (gnttab_alloc_grant_references(NET_TX_RING_SIZE,
	    &xnfp->xnf_gref_tx_head) < 0) {
		cmn_err(CE_WARN, "xnf%d: can't alloc tx grant refs",
		    ddi_get_instance(xnfp->xnf_devinfo));
		goto failure_1;
	}
	if (gnttab_alloc_grant_references(NET_RX_RING_SIZE,
	    &xnfp->xnf_gref_rx_head) < 0) {
		cmn_err(CE_WARN, "xnf%d: can't alloc rx grant refs",
		    ddi_get_instance(xnfp->xnf_devinfo));
		goto failure_1;
	}
	if (xnf_alloc_dma_resources(xnfp) == DDI_FAILURE) {
		cmn_err(CE_WARN, "xnf%d: failed to allocate and initialize "
		    "driver data structures",
		    ddi_get_instance(xnfp->xnf_devinfo));
		goto failure_1;
	}

	xnfp->xnf_rx_ring.sring->rsp_event =
	    xnfp->xnf_tx_ring.sring->rsp_event = 1;

	xnfp->xnf_tx_ring_ref = GRANT_INVALID_REF;
	xnfp->xnf_rx_ring_ref = GRANT_INVALID_REF;

	/* set driver private pointer now */
	ddi_set_driver_private(devinfo, xnfp);

	if (xvdi_add_event_handler(devinfo, XS_OE_STATE, oe_state_change)
	    != DDI_SUCCESS)
		goto failure_1;

	if (!xnf_kstat_init(xnfp))
		goto failure_2;

	/*
	 * Allocate an event channel, add the interrupt handler and
	 * bind it to the event channel.
	 */
	(void) xvdi_alloc_evtchn(devinfo);
	xnfp->xnf_evtchn = xvdi_get_evtchn(devinfo);
#ifdef XPV_HVM_DRIVER
	ec_bind_evtchn_to_handler(xnfp->xnf_evtchn, IPL_VIF, xnf_intr, xnfp);
#else
	(void) ddi_add_intr(devinfo, 0, NULL, NULL, xnf_intr, (caddr_t)xnfp);
#endif

	xnf_read_config(xnfp);
	err = mac_register(macp, &xnfp->xnf_mh);
	mac_free(macp);
	macp = NULL;
	if (err != 0)
		goto failure_3;

#ifdef XPV_HVM_DRIVER
	/*
	 * In the HVM case, this driver essentially replaces a driver for
	 * a 'real' PCI NIC. Without the "model" property set to
	 * "Ethernet controller", like the PCI code does, netbooting does
	 * not work correctly, as strplumb_get_netdev_path() will not find
	 * this interface.
	 */
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, devinfo, "model",
	    "Ethernet controller");
#endif

	/*
	 * connect to the backend
	 */
	xnf_be_connect(xnfp);

	return (DDI_SUCCESS);

failure_3:
	kstat_delete(xnfp->xnf_kstat_aux);
#ifdef XPV_HVM_DRIVER
	ec_unbind_evtchn(xnfp->xnf_evtchn);
	xvdi_free_evtchn(devinfo);
#else
	ddi_remove_intr(devinfo, 0, xnfp->xnf_icookie);
#endif
	xnfp->xnf_evtchn = INVALID_EVTCHN;

failure_2:
	xvdi_remove_event_handler(devinfo, XS_OE_STATE);

failure_1:
	if (xnfp->xnf_gref_tx_head != (grant_ref_t)-1)
		gnttab_free_grant_references(xnfp->xnf_gref_tx_head);
	if (xnfp->xnf_gref_rx_head != (grant_ref_t)-1)
		gnttab_free_grant_references(xnfp->xnf_gref_rx_head);
	xnf_release_dma_resources(xnfp);
	cv_destroy(&xnfp->xnf_cv);
	mutex_destroy(&xnfp->xnf_rx_buf_mutex);
	mutex_destroy(&xnfp->xnf_txlock);
	mutex_destroy(&xnfp->xnf_intrlock);

failure:
	kmem_free(xnfp, sizeof (*xnfp));
	if (macp != NULL)
		mac_free(macp);

	return (DDI_FAILURE);
}

/*  detach(9E) -- Detach a device from the system */
static int
xnf_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	xnf_t *xnfp;		/* Our private device info */
	int i;

#ifdef XNF_DEBUG
	if (xnfdebug & XNF_DEBUG_DDI)
		printf("xnf_detach(0x%p)\n", (void *)devinfo);
#endif

	xnfp = ddi_get_driver_private(devinfo);

	switch (cmd) {
	case DDI_SUSPEND:
#ifdef XPV_HVM_DRIVER
		ec_unbind_evtchn(xnfp->xnf_evtchn);
		xvdi_free_evtchn(devinfo);
#else
		ddi_remove_intr(devinfo, 0, xnfp->xnf_icookie);
#endif

		xvdi_suspend(devinfo);

		mutex_enter(&xnfp->xnf_intrlock);
		mutex_enter(&xnfp->xnf_txlock);

		xnfp->xnf_evtchn = INVALID_EVTCHN;
		xnfp->xnf_connected = B_FALSE;
		mutex_exit(&xnfp->xnf_txlock);
		mutex_exit(&xnfp->xnf_intrlock);
		return (DDI_SUCCESS);

	case DDI_DETACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	if (xnfp->xnf_connected)
		return (DDI_FAILURE);

	/* Wait for receive buffers to be returned; give up after 5 seconds */
	i = 50;

	mutex_enter(&xnfp->xnf_rx_buf_mutex);
	while (xnfp->xnf_rx_bufs_outstanding > 0) {
		mutex_exit(&xnfp->xnf_rx_buf_mutex);
		delay(drv_usectohz(100000));
		if (--i == 0) {
			cmn_err(CE_WARN,
			    "xnf%d: never reclaimed all the "
			    "receive buffers.  Still have %d "
			    "buffers outstanding.",
			    ddi_get_instance(xnfp->xnf_devinfo),
			    xnfp->xnf_rx_bufs_outstanding);
			return (DDI_FAILURE);
		}
		mutex_enter(&xnfp->xnf_rx_buf_mutex);
	}
	mutex_exit(&xnfp->xnf_rx_buf_mutex);

	if (mac_unregister(xnfp->xnf_mh) != 0)
		return (DDI_FAILURE);

	kstat_delete(xnfp->xnf_kstat_aux);

	/* Stop the receiver */
	xnf_stop(xnfp);

	xvdi_remove_event_handler(devinfo, XS_OE_STATE);

	/* Remove the interrupt */
#ifdef XPV_HVM_DRIVER
	ec_unbind_evtchn(xnfp->xnf_evtchn);
	xvdi_free_evtchn(devinfo);
#else
	ddi_remove_intr(devinfo, 0, xnfp->xnf_icookie);
#endif

	/* Release any pending xmit mblks */
	xnf_release_mblks(xnfp);

	/* Release all DMA resources */
	xnf_release_dma_resources(xnfp);

	cv_destroy(&xnfp->xnf_cv);
	mutex_destroy(&xnfp->xnf_rx_buf_mutex);
	mutex_destroy(&xnfp->xnf_txlock);
	mutex_destroy(&xnfp->xnf_intrlock);

	kmem_free(xnfp, sizeof (*xnfp));

	return (DDI_SUCCESS);
}

/*
 *  xnf_set_mac_addr() -- set the physical network address on the board.
 */
/*ARGSUSED*/
static int
xnf_set_mac_addr(void *arg, const uint8_t *macaddr)
{
	xnf_t *xnfp = arg;

#ifdef XNF_DEBUG
	if (xnfdebug & XNF_DEBUG_TRACE)
		printf("xnf%d: set_mac_addr(0x%p): "
		    "%02x:%02x:%02x:%02x:%02x:%02x\n",
		    ddi_get_instance(xnfp->xnf_devinfo),
		    (void *)xnfp, macaddr[0], macaddr[1], macaddr[2],
		    macaddr[3], macaddr[4], macaddr[5]);
#endif
	/*
	 * We can't set our macaddr.
	 *
	 * XXPV dme: Why not?
	 */
	return (ENOTSUP);
}

/*
 *  xnf_set_multicast() -- set (enable) or disable a multicast address.
 *
 *  Program the hardware to enable/disable the multicast address
 *  in "mcast".  Enable if "add" is true, disable if false.
 */
/*ARGSUSED*/
static int
xnf_set_multicast(void *arg, boolean_t add, const uint8_t *mca)
{
	xnf_t *xnfp = arg;

#ifdef XNF_DEBUG
	if (xnfdebug & XNF_DEBUG_TRACE)
		printf("xnf%d set_multicast(0x%p): "
		    "%02x:%02x:%02x:%02x:%02x:%02x\n",
		    ddi_get_instance(xnfp->xnf_devinfo),
		    (void *)xnfp, mca[0], mca[1], mca[2],
		    mca[3], mca[4], mca[5]);
#endif

	/*
	 * XXPV dme: Ideally we'd relay the address to the backend for
	 * enabling.  The protocol doesn't support that (interesting
	 * extension), so we simply succeed and hope that the relevant
	 * packets are going to arrive.
	 *
	 * If protocol support is added for enable/disable then we'll
	 * need to keep a list of those in use and re-add on resume.
	 */
	return (0);
}

/*
 * xnf_set_promiscuous() -- set or reset promiscuous mode on the board
 *
 *  Program the hardware to enable/disable promiscuous mode.
 */
/*ARGSUSED*/
static int
xnf_set_promiscuous(void *arg, boolean_t on)
{
	xnf_t *xnfp = arg;

#ifdef XNF_DEBUG
	if (xnfdebug & XNF_DEBUG_TRACE)
		printf("xnf%d set_promiscuous(0x%p, %x)\n",
		    ddi_get_instance(xnfp->xnf_devinfo),
		    (void *)xnfp, on);
#endif
	/*
	 * We can't really do this, but we pretend that we can in
	 * order that snoop will work.
	 */
	return (0);
}

/*
 * Clean buffers that we have responses for from the transmit ring.
 */
static int
xnf_clean_tx_ring(xnf_t *xnfp)
{
	RING_IDX		next_resp, i;
	struct tx_pktinfo	*reap;
	int			id;
	grant_ref_t		ref;
	boolean_t		work_to_do;

	ASSERT(MUTEX_HELD(&xnfp->xnf_txlock));

loop:
	while (RING_HAS_UNCONSUMED_RESPONSES(&xnfp->xnf_tx_ring)) {
		/*
		 * index of next transmission ack
		 */
		next_resp = xnfp->xnf_tx_ring.sring->rsp_prod;
		membar_consumer();
		/*
		 * Clean tx packets from ring that we have responses for
		 */
		for (i = xnfp->xnf_tx_ring.rsp_cons; i != next_resp; i++) {
			id = RING_GET_RESPONSE(&xnfp->xnf_tx_ring, i)->id;
			reap = &xnfp->xnf_tx_pkt_info[id];
			ref = reap->grant_ref;
			/*
			 * Return id to free list
			 */
			reap->id = xnfp->xnf_tx_pkt_id_list;
			xnfp->xnf_tx_pkt_id_list = id;
			if (gnttab_query_foreign_access(ref) != 0)
				panic("tx grant still in use "
				    "by backend domain");
			(void) ddi_dma_unbind_handle(reap->dma_handle);
			(void) gnttab_end_foreign_access_ref(ref,
			    xnfp->xnf_tx_pages_readonly);
			gnttab_release_grant_reference(&xnfp->xnf_gref_tx_head,
			    ref);
			freemsg(reap->mp);
			reap->mp = NULL;
			reap->grant_ref = GRANT_INVALID_REF;
			if (reap->bdesc != NULL)
				xnf_free_tx_buffer(reap->bdesc);
			reap->bdesc = NULL;
		}
		xnfp->xnf_tx_ring.rsp_cons = next_resp;
		membar_enter();
	}

	/* LINTED: constant in conditional context */
	RING_FINAL_CHECK_FOR_RESPONSES(&xnfp->xnf_tx_ring, work_to_do);
	if (work_to_do)
		goto loop;

	return (RING_FREE_REQUESTS(&xnfp->xnf_tx_ring));
}

/*
 * If we need to pull up data from either a packet that crosses a page
 * boundary or consisting of multiple mblks, do it here.  We allocate
 * a page aligned buffer and copy the data into it.  The header for the
 * allocated buffer is returned. (which is also allocated here)
 */
static struct xnf_buffer_desc *
xnf_pullupmsg(xnf_t *xnfp, mblk_t *mp)
{
	struct xnf_buffer_desc	*bdesc;
	mblk_t			*mptr;
	caddr_t			bp;
	int			len;

	/*
	 * get a xmit buffer from the xmit buffer pool
	 */
	mutex_enter(&xnfp->xnf_rx_buf_mutex);
	bdesc = xnf_get_tx_buffer(xnfp);
	mutex_exit(&xnfp->xnf_rx_buf_mutex);
	if (bdesc == NULL)
		return (bdesc);
	/*
	 * Copy the data into the buffer
	 */
	xnfp->xnf_stat_tx_pullup++;
	bp = bdesc->buf;
	for (mptr = mp; mptr != NULL; mptr = mptr->b_cont) {
		len = mptr->b_wptr - mptr->b_rptr;
		bcopy(mptr->b_rptr, bp, len);
		bp += len;
	}
	return (bdesc);
}

void
xnf_pseudo_cksum(caddr_t buf, int length)
{
	struct ether_header *ehp;
	uint16_t sap, len, *stuff;
	uint32_t cksum;
	size_t offset;
	ipha_t *ipha;
	ipaddr_t src, dst;

	ASSERT(length >= sizeof (*ehp));
	ehp = (struct ether_header *)buf;

	if (ntohs(ehp->ether_type) == VLAN_TPID) {
		struct ether_vlan_header *evhp;

		ASSERT(length >= sizeof (*evhp));
		evhp = (struct ether_vlan_header *)buf;
		sap = ntohs(evhp->ether_type);
		offset = sizeof (*evhp);
	} else {
		sap = ntohs(ehp->ether_type);
		offset = sizeof (*ehp);
	}

	ASSERT(sap == ETHERTYPE_IP);

	/* Packet should have been pulled up by the caller. */
	if ((offset + sizeof (ipha_t)) > length) {
		cmn_err(CE_WARN, "xnf_pseudo_cksum: no room for checksum");
		return;
	}

	ipha = (ipha_t *)(buf + offset);

	ASSERT(IPH_HDR_LENGTH(ipha) == IP_SIMPLE_HDR_LENGTH);

	len = ntohs(ipha->ipha_length) - IP_SIMPLE_HDR_LENGTH;

	switch (ipha->ipha_protocol) {
	case IPPROTO_TCP:
		stuff = IPH_TCPH_CHECKSUMP(ipha, IP_SIMPLE_HDR_LENGTH);
		cksum = IP_TCP_CSUM_COMP;
		break;
	case IPPROTO_UDP:
		stuff = IPH_UDPH_CHECKSUMP(ipha, IP_SIMPLE_HDR_LENGTH);
		cksum = IP_UDP_CSUM_COMP;
		break;
	default:
		cmn_err(CE_WARN, "xnf_pseudo_cksum: unexpected protocol %d",
		    ipha->ipha_protocol);
		return;
	}

	src = ipha->ipha_src;
	dst = ipha->ipha_dst;

	cksum += (dst >> 16) + (dst & 0xFFFF);
	cksum += (src >> 16) + (src & 0xFFFF);
	cksum += htons(len);

	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	cksum = (cksum >> 16) + (cksum & 0xFFFF);

	ASSERT(cksum <= 0xFFFF);

	*stuff = (uint16_t)(cksum ? cksum : ~cksum);
}

/*
 *  xnf_send_one() -- send a packet
 *
 *  Called when a packet is ready to be transmitted. A pointer to an
 *  M_DATA message that contains the packet is passed to this routine.
 *  At least the complete LLC header is contained in the message's
 *  first message block, and the remainder of the packet is contained
 *  within additional M_DATA message blocks linked to the first
 *  message block.
 *
 */
static boolean_t
xnf_send_one(xnf_t *xnfp, mblk_t *mp)
{
	struct xnf_buffer_desc	*xmitbuf;
	struct tx_pktinfo	*txp_info;
	mblk_t			*mptr;
	ddi_dma_cookie_t	dma_cookie;
	RING_IDX		slot;
	int			length = 0, i, pktlen = 0, rc, tx_id;
	int			tx_ring_freespace, page_oops;
	uint_t			ncookies;
	volatile netif_tx_request_t	*txrp;
	caddr_t			bufaddr;
	grant_ref_t		ref;
	unsigned long		mfn;
	uint32_t		pflags;
	domid_t			oeid;

#ifdef XNF_DEBUG
	if (xnfdebug & XNF_DEBUG_SEND)
		printf("xnf%d send(0x%p, 0x%p)\n",
		    ddi_get_instance(xnfp->xnf_devinfo),
		    (void *)xnfp, (void *)mp);
#endif

	ASSERT(mp != NULL);
	ASSERT(mp->b_next == NULL);
	ASSERT(MUTEX_HELD(&xnfp->xnf_txlock));

	tx_ring_freespace = xnf_clean_tx_ring(xnfp);
	ASSERT(tx_ring_freespace >= 0);

	oeid = xvdi_get_oeid(xnfp->xnf_devinfo);
	xnfp->xnf_stat_tx_attempt++;
	/*
	 * If there are no xmit ring slots available, return.
	 */
	if (tx_ring_freespace == 0) {
		xnfp->xnf_stat_tx_defer++;
		return (B_FALSE);	/* Send should be retried */
	}

	slot = xnfp->xnf_tx_ring.req_prod_pvt;
	/* Count the number of mblks in message and compute packet size */
	for (i = 0, mptr = mp; mptr != NULL; mptr = mptr->b_cont, i++)
		pktlen += (mptr->b_wptr - mptr->b_rptr);

	/* Make sure packet isn't too large */
	if (pktlen > XNF_FRAMESIZE) {
		cmn_err(CE_WARN, "xnf%d: oversized packet (%d bytes) dropped",
		    ddi_get_instance(xnfp->xnf_devinfo), pktlen);
		freemsg(mp);
		return (B_TRUE);
	}

	/*
	 * Test if we cross a page boundary with our buffer
	 */
	page_oops = (i == 1) &&
	    (xnf_btop((size_t)mp->b_rptr) !=
	    xnf_btop((size_t)(mp->b_rptr + pktlen)));
	/*
	 * XXPV - unfortunately, the Xen virtual net device currently
	 * doesn't support multiple packet frags, so this will always
	 * end up doing the pullup if we got more than one packet.
	 */
	if (i > xnf_max_tx_frags || page_oops) {
		if (page_oops)
			xnfp->xnf_stat_tx_pagebndry++;
		if ((xmitbuf = xnf_pullupmsg(xnfp, mp)) == NULL) {
			/* could not allocate resources? */
#ifdef XNF_DEBUG
			cmn_err(CE_WARN, "xnf%d: pullupmsg failed",
			    ddi_get_instance(xnfp->xnf_devinfo));
#endif
			xnfp->xnf_stat_tx_defer++;
			return (B_FALSE);	/* Retry send */
		}
		bufaddr = xmitbuf->buf;
	} else {
		xmitbuf = NULL;
		bufaddr = (caddr_t)mp->b_rptr;
	}

	/* set up data descriptor */
	length = pktlen;

	/*
	 * Get packet id from free list
	 */
	tx_id = xnfp->xnf_tx_pkt_id_list;
	ASSERT(tx_id < NET_TX_RING_SIZE);
	txp_info = &xnfp->xnf_tx_pkt_info[tx_id];
	xnfp->xnf_tx_pkt_id_list = txp_info->id;
	txp_info->id = tx_id;

	/* Prepare for DMA mapping of tx buffer(s) */
	rc = ddi_dma_addr_bind_handle(txp_info->dma_handle,
	    NULL, bufaddr, length, DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, 0, &dma_cookie, &ncookies);
	if (rc != DDI_DMA_MAPPED) {
		ASSERT(rc != DDI_DMA_INUSE);
		ASSERT(rc != DDI_DMA_PARTIAL_MAP);
		/*
		 *  Return id to free list
		 */
		txp_info->id = xnfp->xnf_tx_pkt_id_list;
		xnfp->xnf_tx_pkt_id_list = tx_id;
		if (rc == DDI_DMA_NORESOURCES) {
			xnfp->xnf_stat_tx_defer++;
			return (B_FALSE); /* Retry later */
		}
#ifdef XNF_DEBUG
		cmn_err(CE_WARN, "xnf%d: bind_handle failed (%x)",
		    ddi_get_instance(xnfp->xnf_devinfo), rc);
#endif
		return (B_FALSE);
	}

	ASSERT(ncookies == 1);
	ref = gnttab_claim_grant_reference(&xnfp->xnf_gref_tx_head);
	ASSERT((signed short)ref >= 0);
	mfn = xnf_btop(pa_to_ma((paddr_t)dma_cookie.dmac_laddress));
	gnttab_grant_foreign_access_ref(ref, oeid, mfn,
	    xnfp->xnf_tx_pages_readonly);
	txp_info->grant_ref = ref;
	txrp = RING_GET_REQUEST(&xnfp->xnf_tx_ring, slot);
	txrp->gref = ref;
	txrp->size = dma_cookie.dmac_size;
	txrp->offset = (uintptr_t)bufaddr & PAGEOFFSET;
	txrp->id = tx_id;
	txrp->flags = 0;
	hcksum_retrieve(mp, NULL, NULL, NULL, NULL, NULL, NULL, &pflags);
	if (pflags != 0) {
		ASSERT(xnfp->xnf_cksum_offload);
		/*
		 * If the local protocol stack requests checksum
		 * offload we set the 'checksum blank' flag,
		 * indicating to the peer that we need the checksum
		 * calculated for us.
		 *
		 * We _don't_ set the validated flag, because we haven't
		 * validated that the data and the checksum match.
		 */
		xnf_pseudo_cksum(bufaddr, length);
		txrp->flags |= NETTXF_csum_blank;
		xnfp->xnf_stat_tx_cksum_deferred++;
	}
	membar_producer();
	xnfp->xnf_tx_ring.req_prod_pvt = slot + 1;

	txp_info->mp = mp;
	txp_info->bdesc = xmitbuf;

	xnfp->xnf_stat_opackets++;
	xnfp->xnf_stat_obytes += pktlen;

	return (B_TRUE);	/* successful transmit attempt */
}

mblk_t *
xnf_send(void *arg, mblk_t *mp)
{
	xnf_t *xnfp = arg;
	mblk_t *next;
	boolean_t sent_something = B_FALSE;

	mutex_enter(&xnfp->xnf_txlock);

	/*
	 * Transmission attempts should be impossible without having
	 * previously called xnf_start().
	 */
	ASSERT(xnfp->xnf_running);

	/*
	 * Wait for getting connected to the backend
	 */
	while (!xnfp->xnf_connected) {
		cv_wait(&xnfp->xnf_cv, &xnfp->xnf_txlock);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (!xnf_send_one(xnfp, mp)) {
			mp->b_next = next;
			break;
		}

		mp = next;
		sent_something = B_TRUE;
	}

	if (sent_something) {
		boolean_t notify;

		/* LINTED: constant in conditional context */
		RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xnfp->xnf_tx_ring,
		    notify);
		if (notify)
			ec_notify_via_evtchn(xnfp->xnf_evtchn);
	}

	mutex_exit(&xnfp->xnf_txlock);

	return (mp);
}

/*
 *  xnf_intr() -- ring interrupt service routine
 */
static uint_t
xnf_intr(caddr_t arg)
{
	xnf_t *xnfp = (xnf_t *)arg;
	int tx_ring_space;

	mutex_enter(&xnfp->xnf_intrlock);

	/* spurious intr */
	if (!xnfp->xnf_connected) {
		mutex_exit(&xnfp->xnf_intrlock);
		xnfp->xnf_stat_unclaimed_interrupts++;
		return (DDI_INTR_UNCLAIMED);
	}

#ifdef XNF_DEBUG
	if (xnfdebug & XNF_DEBUG_INT)
		printf("xnf%d intr(0x%p)\n",
		    ddi_get_instance(xnfp->xnf_devinfo), (void *)xnfp);
#endif
	if (RING_HAS_UNCONSUMED_RESPONSES(&xnfp->xnf_rx_ring)) {
		mblk_t *mp;

		if (xnfp->xnf_rx_hvcopy)
			mp = xnf_process_hvcopy_recv(xnfp);
		else
			mp = xnf_process_recv(xnfp);

		if (mp != NULL)
			mac_rx(xnfp->xnf_mh, xnfp->xnf_rx_handle, mp);
	}

	/*
	 * Clean tx ring and try to start any blocked xmit streams if
	 * there is now some space.
	 */
	mutex_enter(&xnfp->xnf_txlock);
	tx_ring_space = xnf_clean_tx_ring(xnfp);
	mutex_exit(&xnfp->xnf_txlock);
	if (tx_ring_space > XNF_TX_FREE_THRESH) {
		mutex_exit(&xnfp->xnf_intrlock);
		mac_tx_update(xnfp->xnf_mh);
		mutex_enter(&xnfp->xnf_intrlock);
	}

	xnfp->xnf_stat_interrupts++;
	mutex_exit(&xnfp->xnf_intrlock);
	return (DDI_INTR_CLAIMED); /* indicate that the interrupt was for us */
}

/*
 *  xnf_start() -- start the board receiving and enable interrupts.
 */
static int
xnf_start(void *arg)
{
	xnf_t *xnfp = arg;

#ifdef XNF_DEBUG
	if (xnfdebug & XNF_DEBUG_TRACE)
		printf("xnf%d start(0x%p)\n",
		    ddi_get_instance(xnfp->xnf_devinfo), (void *)xnfp);
#endif

	mutex_enter(&xnfp->xnf_intrlock);
	mutex_enter(&xnfp->xnf_txlock);

	/* Accept packets from above. */
	xnfp->xnf_running = B_TRUE;

	mutex_exit(&xnfp->xnf_txlock);
	mutex_exit(&xnfp->xnf_intrlock);

	return (0);
}

/* xnf_stop() - disable hardware */
static void
xnf_stop(void *arg)
{
	xnf_t *xnfp = arg;

#ifdef XNF_DEBUG
	if (xnfdebug & XNF_DEBUG_TRACE)
		printf("xnf%d stop(0x%p)\n",
		    ddi_get_instance(xnfp->xnf_devinfo), (void *)xnfp);
#endif

	mutex_enter(&xnfp->xnf_intrlock);
	mutex_enter(&xnfp->xnf_txlock);

	xnfp->xnf_running = B_FALSE;

	mutex_exit(&xnfp->xnf_txlock);
	mutex_exit(&xnfp->xnf_intrlock);
}

/*
 * Driver private functions follow
 */

/*
 * Hang buffer on rx ring
 */
static void
rx_buffer_hang(xnf_t *xnfp, struct xnf_buffer_desc *bdesc)
{
	volatile netif_rx_request_t	*reqp;
	RING_IDX			hang_ix;
	grant_ref_t			ref;
	domid_t				oeid;

	oeid = xvdi_get_oeid(xnfp->xnf_devinfo);

	ASSERT(MUTEX_HELD(&xnfp->xnf_intrlock));
	reqp = RING_GET_REQUEST(&xnfp->xnf_rx_ring,
	    xnfp->xnf_rx_ring.req_prod_pvt);
	hang_ix = (RING_IDX) (reqp - RING_GET_REQUEST(&xnfp->xnf_rx_ring, 0));
	ASSERT(xnfp->xnf_rxpkt_bufptr[hang_ix] == NULL);
	if (bdesc->grant_ref == GRANT_INVALID_REF) {
		ref = gnttab_claim_grant_reference(&xnfp->xnf_gref_rx_head);
		ASSERT((signed short)ref >= 0);
		bdesc->grant_ref = ref;
		if (xnfp->xnf_rx_hvcopy) {
			pfn_t pfn = xnf_btop(bdesc->buf_phys);
			mfn_t mfn = pfn_to_mfn(pfn);

			gnttab_grant_foreign_access_ref(ref, oeid, mfn, 0);
		} else {
			gnttab_grant_foreign_transfer_ref(ref, oeid, 0);
		}
	}
	reqp->id = hang_ix;
	reqp->gref = bdesc->grant_ref;
	bdesc->id = hang_ix;
	xnfp->xnf_rxpkt_bufptr[hang_ix] = bdesc;
	membar_producer();
	xnfp->xnf_rx_ring.req_prod_pvt++;
}

static mblk_t *
xnf_process_hvcopy_recv(xnf_t *xnfp)
{
	netif_rx_response_t *rxpkt;
	mblk_t		*mp, *head, *tail;
	struct		xnf_buffer_desc *bdesc;
	boolean_t	hwcsum = B_FALSE, notify, work_to_do;
	size_t 		len;

	/*
	 * in loop over unconsumed responses, we do:
	 * 1. get a response
	 * 2. take corresponding buffer off recv. ring
	 * 3. indicate this by setting slot to NULL
	 * 4. create a new message and
	 * 5. copy data in, adjust ptr
	 *
	 * outside loop:
	 * 7. make sure no more data has arrived; kick HV
	 */

	head = tail = NULL;

loop:
	while (RING_HAS_UNCONSUMED_RESPONSES(&xnfp->xnf_rx_ring)) {

		/* 1. */
		rxpkt = RING_GET_RESPONSE(&xnfp->xnf_rx_ring,
		    xnfp->xnf_rx_ring.rsp_cons);

		DTRACE_PROBE4(got_PKT, int, (int)rxpkt->id, int,
		    (int)rxpkt->offset,
		    int, (int)rxpkt->flags, int, (int)rxpkt->status);

		/*
		 * 2.
		 * Take buffer off of receive ring
		 */
		hwcsum = B_FALSE;
		bdesc = xnfp->xnf_rxpkt_bufptr[rxpkt->id];
		/* 3 */
		xnfp->xnf_rxpkt_bufptr[rxpkt->id] = NULL;
		ASSERT(bdesc->id == rxpkt->id);
		mp = NULL;
		if (!xnfp->xnf_running) {
			DTRACE_PROBE4(pkt_dropped, int, rxpkt->status,
			    char *, bdesc->buf, int, rxpkt->offset,
			    char *, ((char *)bdesc->buf) + rxpkt->offset);
			xnfp->xnf_stat_drop++;
			/*
			 * re-hang the buffer
			 */
			rx_buffer_hang(xnfp, bdesc);
		} else if (rxpkt->status <= 0) {
			DTRACE_PROBE4(pkt_status_negative, int, rxpkt->status,
			    char *, bdesc->buf, int, rxpkt->offset,
			    char *, ((char *)bdesc->buf) + rxpkt->offset);
			xnfp->xnf_stat_errrx++;
			if (rxpkt->status == 0)
				xnfp->xnf_stat_runt++;
			if (rxpkt->status == NETIF_RSP_ERROR)
				xnfp->xnf_stat_mac_rcv_error++;
			if (rxpkt->status == NETIF_RSP_DROPPED)
				xnfp->xnf_stat_norxbuf++;
			/*
			 * re-hang the buffer
			 */
			rx_buffer_hang(xnfp, bdesc);
		} else {
			grant_ref_t		ref =  bdesc->grant_ref;
			struct xnf_buffer_desc	*new_bdesc;
			unsigned long		off = rxpkt->offset;

			DTRACE_PROBE4(pkt_status_ok, int, rxpkt->status,
			    char *, bdesc->buf, int, rxpkt->offset,
			    char *, ((char *)bdesc->buf) + rxpkt->offset);
			len = rxpkt->status;
			ASSERT(off + len <= PAGEOFFSET);
			if (ref == GRANT_INVALID_REF) {
				mp = NULL;
				new_bdesc = bdesc;
				cmn_err(CE_WARN, "Bad rx grant reference %d "
				    "from dom %d", ref,
				    xvdi_get_oeid(xnfp->xnf_devinfo));
				goto luckless;
			}
			/*
			 * Release ref which we'll be re-claiming in
			 * rx_buffer_hang().
			 */
			bdesc->grant_ref = GRANT_INVALID_REF;
			(void) gnttab_end_foreign_access_ref(ref, 0);
			gnttab_release_grant_reference(&xnfp->xnf_gref_rx_head,
			    ref);
			if (rxpkt->flags & NETRXF_data_validated)
				hwcsum = B_TRUE;

			/*
			 * XXPV for the initial implementation of HVcopy,
			 * create a new msg and copy in the data
			 */
			/* 4. */
			if ((mp = allocb(len, BPRI_MED)) == NULL) {
				/*
				 * Couldn't get buffer to copy to,
				 * drop this data, and re-hang
				 * the buffer on the ring.
				 */
				xnfp->xnf_stat_norxbuf++;
				DTRACE_PROBE(alloc_nix);
			} else {
				/* 5. */
				DTRACE_PROBE(alloc_ok);
				bcopy(bdesc->buf + off, mp->b_wptr,
				    len);
				mp->b_wptr += len;
			}
			new_bdesc = bdesc;
luckless:

			/* Re-hang old or hang new buffer. */
			rx_buffer_hang(xnfp, new_bdesc);
		}
		if (mp) {
			if (hwcsum) {
				/*
				 * See comments in xnf_process_recv().
				 */

				(void) hcksum_assoc(mp, NULL,
				    NULL, 0, 0, 0, 0,
				    HCK_FULLCKSUM |
				    HCK_FULLCKSUM_OK,
				    0);
				xnfp->xnf_stat_rx_cksum_no_need++;
			}
			if (head == NULL) {
				head = tail = mp;
			} else {
				tail->b_next = mp;
				tail = mp;
			}

			ASSERT(mp->b_next == NULL);

			xnfp->xnf_stat_ipackets++;
			xnfp->xnf_stat_rbytes += len;
		}

		xnfp->xnf_rx_ring.rsp_cons++;

		xnfp->xnf_stat_hvcopy_packet_processed++;
	}

	/* 7. */
	/*
	 * Has more data come in since we started?
	 */
	/* LINTED: constant in conditional context */
	RING_FINAL_CHECK_FOR_RESPONSES(&xnfp->xnf_rx_ring, work_to_do);
	if (work_to_do)
		goto loop;

	/*
	 * Indicate to the backend that we have re-filled the receive
	 * ring.
	 */
	/* LINTED: constant in conditional context */
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xnfp->xnf_rx_ring, notify);
	if (notify)
		ec_notify_via_evtchn(xnfp->xnf_evtchn);

	return (head);
}

/* Process all queued received packets */
static mblk_t *
xnf_process_recv(xnf_t *xnfp)
{
	volatile netif_rx_response_t *rxpkt;
	mblk_t *mp, *head, *tail;
	struct xnf_buffer_desc *bdesc;
	extern mblk_t *desballoc(unsigned char *, size_t, uint_t, frtn_t *);
	boolean_t hwcsum = B_FALSE, notify, work_to_do;
	size_t len;
	pfn_t pfn;
	long cnt;

	head = tail = NULL;
loop:
	while (RING_HAS_UNCONSUMED_RESPONSES(&xnfp->xnf_rx_ring)) {

		rxpkt = RING_GET_RESPONSE(&xnfp->xnf_rx_ring,
		    xnfp->xnf_rx_ring.rsp_cons);

		/*
		 * Take buffer off of receive ring
		 */
		hwcsum = B_FALSE;
		bdesc = xnfp->xnf_rxpkt_bufptr[rxpkt->id];
		xnfp->xnf_rxpkt_bufptr[rxpkt->id] = NULL;
		ASSERT(bdesc->id == rxpkt->id);
		mp = NULL;
		if (!xnfp->xnf_running) {
			xnfp->xnf_stat_drop++;
			/*
			 * re-hang the buffer
			 */
			rx_buffer_hang(xnfp, bdesc);
		} else if (rxpkt->status <= 0) {
			xnfp->xnf_stat_errrx++;
			if (rxpkt->status == 0)
				xnfp->xnf_stat_runt++;
			if (rxpkt->status == NETIF_RSP_ERROR)
				xnfp->xnf_stat_mac_rcv_error++;
			if (rxpkt->status == NETIF_RSP_DROPPED)
				xnfp->xnf_stat_norxbuf++;
			/*
			 * re-hang the buffer
			 */
			rx_buffer_hang(xnfp, bdesc);
		} else {
			grant_ref_t ref =  bdesc->grant_ref;
			struct xnf_buffer_desc *new_bdesc;
			unsigned long off = rxpkt->offset;
			unsigned long mfn;

			len = rxpkt->status;
			ASSERT(off + len <= PAGEOFFSET);
			if (ref == GRANT_INVALID_REF) {
				mp = NULL;
				new_bdesc = bdesc;
				cmn_err(CE_WARN, "Bad rx grant reference %d "
				    "from dom %d", ref,
				    xvdi_get_oeid(xnfp->xnf_devinfo));
				goto luckless;
			}
			bdesc->grant_ref = GRANT_INVALID_REF;
			mfn = gnttab_end_foreign_transfer_ref(ref);
			ASSERT(mfn != MFN_INVALID);
			ASSERT(hat_getpfnum(kas.a_hat, bdesc->buf) ==
			    PFN_INVALID);

			gnttab_release_grant_reference(&xnfp->xnf_gref_rx_head,
			    ref);
			reassign_pfn(xnf_btop(bdesc->buf_phys), mfn);
			hat_devload(kas.a_hat, bdesc->buf, PAGESIZE,
			    xnf_btop(bdesc->buf_phys),
			    PROT_READ | PROT_WRITE, HAT_LOAD);
			balloon_drv_added(1);

			if (rxpkt->flags & NETRXF_data_validated)
				hwcsum = B_TRUE;
			if (len <= xnf_rx_bcopy_thresh) {
				/*
				 * For small buffers, just copy the data
				 * and send the copy upstream.
				 */
				new_bdesc = NULL;
			} else {
				/*
				 * We send a pointer to this data upstream;
				 * we need a new buffer to replace this one.
				 */
				mutex_enter(&xnfp->xnf_rx_buf_mutex);
				new_bdesc = xnf_get_buffer(xnfp);
				if (new_bdesc != NULL) {
					xnfp->xnf_rx_bufs_outstanding++;
				} else {
					xnfp->xnf_stat_rx_no_ringbuf++;
				}
				mutex_exit(&xnfp->xnf_rx_buf_mutex);
			}

			if (new_bdesc == NULL) {
				/*
				 * Don't have a new ring buffer; bcopy the data
				 * from the buffer, and preserve the
				 * original buffer
				 */
				if ((mp = allocb(len, BPRI_MED)) == NULL) {
					/*
					 * Could't get buffer to copy to,
					 * drop this data, and re-hang
					 * the buffer on the ring.
					 */
					xnfp->xnf_stat_norxbuf++;
				} else {
					bcopy(bdesc->buf + off, mp->b_wptr,
					    len);
				}
				/*
				 * Give the buffer page back to xen
				 */
				pfn = xnf_btop(bdesc->buf_phys);
				cnt = balloon_free_pages(1, &mfn, bdesc->buf,
				    &pfn);
				if (cnt != 1) {
					cmn_err(CE_WARN, "unable to give a "
					    "page back to the hypervisor\n");
				}
				new_bdesc = bdesc;
			} else {
				if ((mp = desballoc((unsigned char *)bdesc->buf,
				    off + len, 0, (frtn_t *)bdesc)) == NULL) {
					/*
					 * Couldn't get mblk to pass recv data
					 * up with, free the old ring buffer
					 */
					xnfp->xnf_stat_norxbuf++;
					xnf_rcv_complete(bdesc);
					goto luckless;
				}
				(void) ddi_dma_sync(bdesc->dma_handle,
				    0, 0, DDI_DMA_SYNC_FORCPU);

				mp->b_wptr += off;
				mp->b_rptr += off;
			}
luckless:
			if (mp)
				mp->b_wptr += len;
			/* re-hang old or hang new buffer */
			rx_buffer_hang(xnfp, new_bdesc);
		}
		if (mp) {
			if (hwcsum) {
				/*
				 * If the peer says that the data has
				 * been validated then we declare that
				 * the full checksum has been
				 * verified.
				 *
				 * We don't look at the "checksum
				 * blank" flag, and hence could have a
				 * packet here that we are asserting
				 * is good with a blank checksum.
				 *
				 * The hardware checksum offload
				 * specification says that we must
				 * provide the actual checksum as well
				 * as an assertion that it is valid,
				 * but the protocol stack doesn't
				 * actually use it and some other
				 * drivers don't bother, so we don't.
				 * If it was necessary we could grovel
				 * in the packet to find it.
				 */

				(void) hcksum_assoc(mp, NULL,
				    NULL, 0, 0, 0, 0,
				    HCK_FULLCKSUM |
				    HCK_FULLCKSUM_OK,
				    0);
				xnfp->xnf_stat_rx_cksum_no_need++;
			}
			if (head == NULL) {
				head = tail = mp;
			} else {
				tail->b_next = mp;
				tail = mp;
			}

			ASSERT(mp->b_next == NULL);

			xnfp->xnf_stat_ipackets++;
			xnfp->xnf_stat_rbytes += len;
		}

		xnfp->xnf_rx_ring.rsp_cons++;
	}

	/*
	 * Has more data come in since we started?
	 */
	/* LINTED: constant in conditional context */
	RING_FINAL_CHECK_FOR_RESPONSES(&xnfp->xnf_rx_ring, work_to_do);
	if (work_to_do)
		goto loop;

	/*
	 * Indicate to the backend that we have re-filled the receive
	 * ring.
	 */
	/* LINTED: constant in conditional context */
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xnfp->xnf_rx_ring, notify);
	if (notify)
		ec_notify_via_evtchn(xnfp->xnf_evtchn);

	return (head);
}

/* Called when the upper layers free a message we passed upstream */
static void
xnf_rcv_complete(struct xnf_buffer_desc *bdesc)
{
	xnf_t *xnfp = bdesc->xnfp;
	pfn_t pfn;
	long cnt;

	/* One less outstanding receive buffer */
	mutex_enter(&xnfp->xnf_rx_buf_mutex);
	--xnfp->xnf_rx_bufs_outstanding;
	/*
	 * Return buffer to the free list, unless the free list is getting
	 * too large.  XXPV - this threshold may need tuning.
	 */
	if (xnfp->xnf_rx_descs_free < xnf_rx_bufs_lowat) {
		/*
		 * Unmap the page, and hand the machine page back
		 * to xen so it can be re-used as a backend net buffer.
		 */
		pfn = xnf_btop(bdesc->buf_phys);
		cnt = balloon_free_pages(1, NULL, bdesc->buf, &pfn);
		if (cnt != 1) {
			cmn_err(CE_WARN, "unable to give a page back to the "
			    "hypervisor\n");
		}

		bdesc->next = xnfp->xnf_free_list;
		xnfp->xnf_free_list = bdesc;
		xnfp->xnf_rx_descs_free++;
		mutex_exit(&xnfp->xnf_rx_buf_mutex);
	} else {
		/*
		 * We can return everything here since we have a free buffer
		 * that we have not given the backing page for back to xen.
		 */
		--xnfp->xnf_rx_buffer_count;
		mutex_exit(&xnfp->xnf_rx_buf_mutex);
		(void) ddi_dma_unbind_handle(bdesc->dma_handle);
		ddi_dma_mem_free(&bdesc->acc_handle);
		ddi_dma_free_handle(&bdesc->dma_handle);
		kmem_free(bdesc, sizeof (*bdesc));
	}
}

/*
 *  xnf_alloc_dma_resources() -- initialize the drivers structures
 */
static int
xnf_alloc_dma_resources(xnf_t *xnfp)
{
	dev_info_t 		*devinfo = xnfp->xnf_devinfo;
	int			i;
	size_t			len;
	ddi_dma_cookie_t	dma_cookie;
	uint_t			ncookies;
	struct xnf_buffer_desc	*bdesc;
	int			rc;
	caddr_t			rptr;

	xnfp->xnf_n_rx = NET_RX_RING_SIZE;
	xnfp->xnf_max_rx_bufs = xnf_rx_bufs_hiwat;

	xnfp->xnf_n_tx = NET_TX_RING_SIZE;

	/*
	 * The code below allocates all the DMA data structures that
	 * need to be released when the driver is detached.
	 *
	 * First allocate handles for mapping (virtual address) pointers to
	 * transmit data buffers to physical addresses
	 */
	for (i = 0; i < xnfp->xnf_n_tx; i++) {
		if ((rc = ddi_dma_alloc_handle(devinfo,
		    &tx_buffer_dma_attr, DDI_DMA_SLEEP, 0,
		    &xnfp->xnf_tx_pkt_info[i].dma_handle)) != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	/*
	 * Allocate page for the transmit descriptor ring.
	 */
	if (ddi_dma_alloc_handle(devinfo, &ringbuf_dma_attr,
	    DDI_DMA_SLEEP, 0, &xnfp->xnf_tx_ring_dma_handle) != DDI_SUCCESS)
		goto alloc_error;

	if (ddi_dma_mem_alloc(xnfp->xnf_tx_ring_dma_handle,
	    PAGESIZE, &accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &rptr, &len,
	    &xnfp->xnf_tx_ring_dma_acchandle) != DDI_SUCCESS) {
		ddi_dma_free_handle(&xnfp->xnf_tx_ring_dma_handle);
		xnfp->xnf_tx_ring_dma_handle = NULL;
		goto alloc_error;
	}

	if ((rc = ddi_dma_addr_bind_handle(xnfp->xnf_tx_ring_dma_handle, NULL,
	    rptr, PAGESIZE, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &dma_cookie, &ncookies)) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&xnfp->xnf_tx_ring_dma_acchandle);
		ddi_dma_free_handle(&xnfp->xnf_tx_ring_dma_handle);
		xnfp->xnf_tx_ring_dma_handle = NULL;
		xnfp->xnf_tx_ring_dma_acchandle = NULL;
		if (rc == DDI_DMA_NORESOURCES)
			goto alloc_error;
		else
			goto error;
	}

	ASSERT(ncookies == 1);
	bzero(rptr, PAGESIZE);
	/* LINTED: constant in conditional context */
	SHARED_RING_INIT((netif_tx_sring_t *)rptr);
	/* LINTED: constant in conditional context */
	FRONT_RING_INIT(&xnfp->xnf_tx_ring, (netif_tx_sring_t *)rptr, PAGESIZE);
	xnfp->xnf_tx_ring_phys_addr = dma_cookie.dmac_laddress;

	/*
	 * Allocate page for the receive descriptor ring.
	 */
	if (ddi_dma_alloc_handle(devinfo, &ringbuf_dma_attr,
	    DDI_DMA_SLEEP, 0, &xnfp->xnf_rx_ring_dma_handle) != DDI_SUCCESS)
		goto alloc_error;

	if (ddi_dma_mem_alloc(xnfp->xnf_rx_ring_dma_handle,
	    PAGESIZE, &accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &rptr, &len,
	    &xnfp->xnf_rx_ring_dma_acchandle) != DDI_SUCCESS) {
		ddi_dma_free_handle(&xnfp->xnf_rx_ring_dma_handle);
		xnfp->xnf_rx_ring_dma_handle = NULL;
		goto alloc_error;
	}

	if ((rc = ddi_dma_addr_bind_handle(xnfp->xnf_rx_ring_dma_handle, NULL,
	    rptr, PAGESIZE, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &dma_cookie, &ncookies)) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&xnfp->xnf_rx_ring_dma_acchandle);
		ddi_dma_free_handle(&xnfp->xnf_rx_ring_dma_handle);
		xnfp->xnf_rx_ring_dma_handle = NULL;
		xnfp->xnf_rx_ring_dma_acchandle = NULL;
		if (rc == DDI_DMA_NORESOURCES)
			goto alloc_error;
		else
			goto error;
	}

	ASSERT(ncookies == 1);
	bzero(rptr, PAGESIZE);
	/* LINTED: constant in conditional context */
	SHARED_RING_INIT((netif_rx_sring_t *)rptr);
	/* LINTED: constant in conditional context */
	FRONT_RING_INIT(&xnfp->xnf_rx_ring, (netif_rx_sring_t *)rptr, PAGESIZE);
	xnfp->xnf_rx_ring_phys_addr = dma_cookie.dmac_laddress;

	/*
	 * Preallocate receive buffers for each receive descriptor.
	 */

	/* Set up the "free list" of receive buffer descriptors */
	for (i = 0; i < xnfp->xnf_n_rx; i++) {
		if ((bdesc = xnf_alloc_buffer(xnfp)) == NULL)
			goto alloc_error;
		bdesc->next = xnfp->xnf_free_list;
		xnfp->xnf_free_list = bdesc;
	}

	return (DDI_SUCCESS);

alloc_error:
	cmn_err(CE_WARN, "xnf%d: could not allocate enough DMA memory",
	    ddi_get_instance(xnfp->xnf_devinfo));
error:
	xnf_release_dma_resources(xnfp);
	return (DDI_FAILURE);
}

/*
 * Release all DMA resources in the opposite order from acquisition
 * Should not be called until all outstanding esballoc buffers
 * have been returned.
 */
static void
xnf_release_dma_resources(xnf_t *xnfp)
{
	int i;

	/*
	 * Free receive buffers which are currently associated with
	 * descriptors
	 */
	for (i = 0; i < xnfp->xnf_n_rx; i++) {
		struct xnf_buffer_desc *bp;

		if ((bp = xnfp->xnf_rxpkt_bufptr[i]) == NULL)
			continue;
		xnf_free_buffer(bp);
		xnfp->xnf_rxpkt_bufptr[i] = NULL;
	}

	/* Free the receive ring buffer */
	if (xnfp->xnf_rx_ring_dma_acchandle != NULL) {
		(void) ddi_dma_unbind_handle(xnfp->xnf_rx_ring_dma_handle);
		ddi_dma_mem_free(&xnfp->xnf_rx_ring_dma_acchandle);
		ddi_dma_free_handle(&xnfp->xnf_rx_ring_dma_handle);
		xnfp->xnf_rx_ring_dma_acchandle = NULL;
	}
	/* Free the transmit ring buffer */
	if (xnfp->xnf_tx_ring_dma_acchandle != NULL) {
		(void) ddi_dma_unbind_handle(xnfp->xnf_tx_ring_dma_handle);
		ddi_dma_mem_free(&xnfp->xnf_tx_ring_dma_acchandle);
		ddi_dma_free_handle(&xnfp->xnf_tx_ring_dma_handle);
		xnfp->xnf_tx_ring_dma_acchandle = NULL;
	}

	/*
	 * Free handles for mapping (virtual address) pointers to
	 * transmit data buffers to physical addresses
	 */
	for (i = 0; i < xnfp->xnf_n_tx; i++) {
		if (xnfp->xnf_tx_pkt_info[i].dma_handle != NULL) {
			ddi_dma_free_handle(
			    &xnfp->xnf_tx_pkt_info[i].dma_handle);
		}
	}

}

static void
xnf_release_mblks(xnf_t *xnfp)
{
	int	i;

	for (i = 0; i < xnfp->xnf_n_tx; i++) {
		if (xnfp->xnf_tx_pkt_info[i].mp == NULL)
			continue;
		freemsg(xnfp->xnf_tx_pkt_info[i].mp);
		xnfp->xnf_tx_pkt_info[i].mp = NULL;
		(void) ddi_dma_unbind_handle(
		    xnfp->xnf_tx_pkt_info[i].dma_handle);
	}
}

/*
 * Remove a xmit buffer descriptor from the head of the free list and return
 * a pointer to it.  If no buffers on list, attempt to allocate a new one.
 * Called with the tx_buf_mutex held.
 */
static struct xnf_buffer_desc *
xnf_get_tx_buffer(xnf_t *xnfp)
{
	struct xnf_buffer_desc *bdesc;

	bdesc = xnfp->xnf_tx_free_list;
	if (bdesc != NULL) {
		xnfp->xnf_tx_free_list = bdesc->next;
	} else {
		bdesc = xnf_alloc_tx_buffer(xnfp);
	}
	return (bdesc);
}

/*
 * Remove a buffer descriptor from the head of the free list and return
 * a pointer to it.  If no buffers on list, attempt to allocate a new one.
 * Called with the rx_buf_mutex held.
 */
static struct xnf_buffer_desc *
xnf_get_buffer(xnf_t *xnfp)
{
	struct xnf_buffer_desc *bdesc;

	bdesc = xnfp->xnf_free_list;
	if (bdesc != NULL) {
		xnfp->xnf_free_list = bdesc->next;
		xnfp->xnf_rx_descs_free--;
	} else {
		bdesc = xnf_alloc_buffer(xnfp);
	}
	return (bdesc);
}

/*
 * Free a xmit buffer back to the xmit free list
 */
static void
xnf_free_tx_buffer(struct xnf_buffer_desc *bp)
{
	xnf_t *xnfp = bp->xnfp;

	mutex_enter(&xnfp->xnf_tx_buf_mutex);
	bp->next = xnfp->xnf_tx_free_list;
	xnfp->xnf_tx_free_list = bp;
	mutex_exit(&xnfp->xnf_tx_buf_mutex);
}

/*
 * Put a buffer descriptor onto the head of the free list.
 * for page-flip:
 * We can't really free these buffers back to the kernel
 * since we have given away their backing page to be used
 * by the back end net driver.
 * for hvcopy:
 * release all the memory
 */
static void
xnf_free_buffer(struct xnf_buffer_desc *bdesc)
{
	xnf_t *xnfp = bdesc->xnfp;

	mutex_enter(&xnfp->xnf_rx_buf_mutex);
	if (xnfp->xnf_rx_hvcopy) {
		if (ddi_dma_unbind_handle(bdesc->dma_handle) != DDI_SUCCESS)
			goto out;
		ddi_dma_mem_free(&bdesc->acc_handle);
		ddi_dma_free_handle(&bdesc->dma_handle);
		kmem_free(bdesc, sizeof (*bdesc));
		xnfp->xnf_rx_buffer_count--;
	} else {
		bdesc->next = xnfp->xnf_free_list;
		xnfp->xnf_free_list = bdesc;
		xnfp->xnf_rx_descs_free++;
	}
out:
	mutex_exit(&xnfp->xnf_rx_buf_mutex);
}

/*
 * Allocate a DMA-able xmit buffer, including a structure to
 * keep track of the buffer.  Called with tx_buf_mutex held.
 */
static struct xnf_buffer_desc *
xnf_alloc_tx_buffer(xnf_t *xnfp)
{
	struct xnf_buffer_desc *bdesc;
	size_t len;

	if ((bdesc = kmem_zalloc(sizeof (*bdesc), KM_NOSLEEP)) == NULL)
		return (NULL);

	/* allocate a DMA access handle for receive buffer */
	if (ddi_dma_alloc_handle(xnfp->xnf_devinfo, &tx_buffer_dma_attr,
	    0, 0, &bdesc->dma_handle) != DDI_SUCCESS)
		goto failure;

	/* Allocate DMA-able memory for transmit buffer */
	if (ddi_dma_mem_alloc(bdesc->dma_handle,
	    PAGESIZE, &data_accattr, DDI_DMA_STREAMING, 0, 0,
	    &bdesc->buf, &len, &bdesc->acc_handle) != DDI_SUCCESS)
		goto failure_1;

	bdesc->xnfp = xnfp;
	xnfp->xnf_tx_buffer_count++;

	return (bdesc);

failure_1:
	ddi_dma_free_handle(&bdesc->dma_handle);

failure:
	kmem_free(bdesc, sizeof (*bdesc));
	return (NULL);
}

/*
 * Allocate a DMA-able receive buffer, including a structure to
 * keep track of the buffer.  Called with rx_buf_mutex held.
 */
static struct xnf_buffer_desc *
xnf_alloc_buffer(xnf_t *xnfp)
{
	struct			xnf_buffer_desc *bdesc;
	size_t			len;
	uint_t			ncookies;
	ddi_dma_cookie_t	dma_cookie;
	long			cnt;
	pfn_t			pfn;

	if (xnfp->xnf_rx_buffer_count >= xnfp->xnf_max_rx_bufs)
		return (NULL);

	if ((bdesc = kmem_zalloc(sizeof (*bdesc), KM_NOSLEEP)) == NULL)
		return (NULL);

	/* allocate a DMA access handle for receive buffer */
	if (ddi_dma_alloc_handle(xnfp->xnf_devinfo, &rx_buffer_dma_attr,
	    0, 0, &bdesc->dma_handle) != DDI_SUCCESS)
		goto failure;

	/* Allocate DMA-able memory for receive buffer */
	if (ddi_dma_mem_alloc(bdesc->dma_handle,
	    PAGESIZE, &data_accattr, DDI_DMA_STREAMING, 0, 0,
	    &bdesc->buf, &len, &bdesc->acc_handle) != DDI_SUCCESS)
		goto failure_1;

	/* bind to virtual address of buffer to get physical address */
	if (ddi_dma_addr_bind_handle(bdesc->dma_handle, NULL,
	    bdesc->buf, PAGESIZE, DDI_DMA_READ | DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, 0, &dma_cookie, &ncookies) != DDI_DMA_MAPPED)
		goto failure_2;

	bdesc->buf_phys = dma_cookie.dmac_laddress;
	bdesc->xnfp = xnfp;
	if (xnfp->xnf_rx_hvcopy) {
		bdesc->free_rtn.free_func = xnf_copy_rcv_complete;
	} else {
		bdesc->free_rtn.free_func = xnf_rcv_complete;
	}
	bdesc->free_rtn.free_arg = (char *)bdesc;
	bdesc->grant_ref = GRANT_INVALID_REF;
	ASSERT(ncookies == 1);

	xnfp->xnf_rx_buffer_count++;

	if (!xnfp->xnf_rx_hvcopy) {
		/*
		 * Unmap the page, and hand the machine page back
		 * to xen so it can be used as a backend net buffer.
		 */
		pfn = xnf_btop(bdesc->buf_phys);
		cnt = balloon_free_pages(1, NULL, bdesc->buf, &pfn);
		if (cnt != 1) {
			cmn_err(CE_WARN, "unable to give a page back to the "
			    "hypervisor\n");
		}
	}

	return (bdesc);

failure_2:
	ddi_dma_mem_free(&bdesc->acc_handle);

failure_1:
	ddi_dma_free_handle(&bdesc->dma_handle);

failure:
	kmem_free(bdesc, sizeof (*bdesc));
	return (NULL);
}

/*
 * Statistics.
 */
static char *xnf_aux_statistics[] = {
	"tx_cksum_deferred",
	"rx_cksum_no_need",
	"interrupts",
	"unclaimed_interrupts",
	"tx_pullup",
	"tx_pagebndry",
	"tx_attempt",
	"rx_no_ringbuf",
	"hvcopy_packet_processed",
};

static int
xnf_kstat_aux_update(kstat_t *ksp, int flag)
{
	xnf_t *xnfp;
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	xnfp = ksp->ks_private;
	knp = ksp->ks_data;

	/*
	 * Assignment order must match that of the names in
	 * xnf_aux_statistics.
	 */
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_cksum_deferred;
	(knp++)->value.ui64 = xnfp->xnf_stat_rx_cksum_no_need;

	(knp++)->value.ui64 = xnfp->xnf_stat_interrupts;
	(knp++)->value.ui64 = xnfp->xnf_stat_unclaimed_interrupts;
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_pullup;
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_pagebndry;
	(knp++)->value.ui64 = xnfp->xnf_stat_tx_attempt;
	(knp++)->value.ui64 = xnfp->xnf_stat_rx_no_ringbuf;

	(knp++)->value.ui64 = xnfp->xnf_stat_hvcopy_packet_processed;

	return (0);
}

static boolean_t
xnf_kstat_init(xnf_t *xnfp)
{
	int nstat = sizeof (xnf_aux_statistics) /
	    sizeof (xnf_aux_statistics[0]);
	char **cp = xnf_aux_statistics;
	kstat_named_t *knp;

	/*
	 * Create and initialise kstats.
	 */
	if ((xnfp->xnf_kstat_aux = kstat_create("xnf",
	    ddi_get_instance(xnfp->xnf_devinfo),
	    "aux_statistics", "net", KSTAT_TYPE_NAMED,
	    nstat, 0)) == NULL)
		return (B_FALSE);

	xnfp->xnf_kstat_aux->ks_private = xnfp;
	xnfp->xnf_kstat_aux->ks_update = xnf_kstat_aux_update;

	knp = xnfp->xnf_kstat_aux->ks_data;
	while (nstat > 0) {
		kstat_named_init(knp, *cp, KSTAT_DATA_UINT64);

		knp++;
		cp++;
		nstat--;
	}

	kstat_install(xnfp->xnf_kstat_aux);

	return (B_TRUE);
}

static int
xnf_stat(void *arg, uint_t stat, uint64_t *val)
{
	xnf_t *xnfp = arg;

	mutex_enter(&xnfp->xnf_intrlock);
	mutex_enter(&xnfp->xnf_txlock);

#define	mac_stat(q, r)				\
	case (MAC_STAT_##q):			\
		*val = xnfp->xnf_stat_##r;	\
		break

#define	ether_stat(q, r)			\
	case (ETHER_STAT_##q):			\
		*val = xnfp->xnf_stat_##r;	\
		break

	switch (stat) {

	mac_stat(IPACKETS, ipackets);
	mac_stat(OPACKETS, opackets);
	mac_stat(RBYTES, rbytes);
	mac_stat(OBYTES, obytes);
	mac_stat(NORCVBUF, norxbuf);
	mac_stat(IERRORS, errrx);
	mac_stat(NOXMTBUF, tx_defer);

	ether_stat(MACRCV_ERRORS, mac_rcv_error);
	ether_stat(TOOSHORT_ERRORS, runt);

	default:
		mutex_exit(&xnfp->xnf_txlock);
		mutex_exit(&xnfp->xnf_intrlock);

		return (ENOTSUP);
	}

#undef mac_stat
#undef ether_stat

	mutex_exit(&xnfp->xnf_txlock);
	mutex_exit(&xnfp->xnf_intrlock);

	return (0);
}

/*ARGSUSED*/
static void
xnf_blank(void *arg, time_t ticks, uint_t count)
{
	/*
	 * XXPV dme: blanking is not currently implemented.
	 *
	 * It's not obvious how to use the 'ticks' argument here.
	 *
	 * 'Count' might be used as an indicator of how to set
	 * rsp_event when posting receive buffers to the rx_ring.  It
	 * would replace the code at the tail of xnf_process_recv()
	 * that simply indicates that the next completed packet should
	 * cause an interrupt.
	 */
}

static void
xnf_resources(void *arg)
{
	xnf_t *xnfp = arg;
	mac_rx_fifo_t mrf;

	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_blank = xnf_blank;
	mrf.mrf_arg = (void *)xnfp;
	mrf.mrf_normal_blank_time = 128;	/* XXPV dme: see xnf_blank() */
	mrf.mrf_normal_pkt_count = 8;		/* XXPV dme: see xnf_blank() */

	xnfp->xnf_rx_handle = mac_resource_add(xnfp->xnf_mh,
	    (mac_resource_t *)&mrf);
}

/*ARGSUSED*/
static void
xnf_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	miocnak(q, mp, 0, EINVAL);
}

static boolean_t
xnf_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	xnf_t *xnfp = arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *capab = cap_data;

		/*
		 * Whilst the flag used to communicate with the IO
		 * domain is called "NETTXF_csum_blank", the checksum
		 * in the packet must contain the pseudo-header
		 * checksum and not zero.
		 *
		 * To help out the IO domain, we might use
		 * HCKSUM_INET_PARTIAL. Unfortunately our stack will
		 * then use checksum offload for IPv6 packets, which
		 * the IO domain can't handle.
		 *
		 * As a result, we declare outselves capable of
		 * HCKSUM_INET_FULL_V4. This means that we receive
		 * IPv4 packets from the stack with a blank checksum
		 * field and must insert the pseudo-header checksum
		 * before passing the packet to the IO domain.
		 */
		if (xnfp->xnf_cksum_offload)
			*capab = HCKSUM_INET_FULL_V4;
		else
			*capab = 0;
		break;
	}

	case MAC_CAPAB_POLL:
		/* Just return B_TRUE. */
		break;

	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*ARGSUSED*/
static void
oe_state_change(dev_info_t *dip, ddi_eventcookie_t id,
    void *arg, void *impl_data)
{
	xnf_t *xnfp = ddi_get_driver_private(dip);
	XenbusState new_state = *(XenbusState *)impl_data;

	ASSERT(xnfp != NULL);

	switch (new_state) {
	case XenbusStateConnected:
		mutex_enter(&xnfp->xnf_intrlock);
		mutex_enter(&xnfp->xnf_txlock);

		xnfp->xnf_connected = B_TRUE;
		/*
		 * wake up threads wanting to send data to backend,
		 * but got blocked due to backend is not ready
		 */
		cv_broadcast(&xnfp->xnf_cv);

		mutex_exit(&xnfp->xnf_txlock);
		mutex_exit(&xnfp->xnf_intrlock);

		/*
		 * kick backend in case it missed any tx request
		 * in the TX ring buffer
		 */
		ec_notify_via_evtchn(xnfp->xnf_evtchn);

		/*
		 * there maybe already queued rx data in the RX ring
		 * sent by backend after it gets connected but before
		 * we see its state change here, so we call our intr
		 * handling routine to handle them, if any
		 */
		(void) xnf_intr((caddr_t)xnfp);

		break;

	default:
		break;
	}
}

/*
 * Check whether backend is capable of and willing to talk
 * to us via hypervisor copy, as opposed to page flip.
 */
static boolean_t
xnf_hvcopy_peer_status(dev_info_t *devinfo)
{
	int	be_rx_copy;
	int	err;

	err = xenbus_scanf(XBT_NULL, xvdi_get_oename(devinfo),
	    "feature-rx-copy", "%d", &be_rx_copy);
	/*
	 * If we fail to read the store we assume that the key is
	 * absent, implying an older domain at the far end.  Older
	 * domains cannot do HV copy (we assume ..).
	 */
	if (err != 0)
		be_rx_copy = 0;

	return (be_rx_copy?B_TRUE:B_FALSE);
}
