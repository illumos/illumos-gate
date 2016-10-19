/*
 * udmfE_usbgem.c : Davicom DM9601E USB to Fast Ethernet Driver for Solaris
 *
 * Copyright (c) 2009-2012 Masayuki Murayama.  All rights reserved.
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
 *  Changelog:
 */

/*
 * TODO
 */
/* ======================================================= */

/*
 * Solaris system header files and macros
 */

/* minimum kernel headers for drivers */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>

/* ethernet stuff */
#include <sys/ethernet.h>

/* interface card depend stuff */
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/strsun.h>
#include <sys/usb/usba.h>
#include "usbgem.h"

/* hardware stuff */
#include "usbgem_mii.h"
#include "dm9601reg.h"

char	ident[] = "dm9601 usbnic driver v" VERSION;

/*
 * Useful macros
 */
#define	CHECK_AND_JUMP(err, label)	if (err != USB_SUCCESS) goto label
#define	LE16P(p)	((((uint8_t *)(p))[1] << 8) | ((uint8_t *)(p))[0])

/*
 * Debugging
 */
#ifdef DEBUG_LEVEL
static int udmf_debug = DEBUG_LEVEL;
#define	DPRINTF(n, args)	if (udmf_debug > (n)) cmn_err args
#else
#define	DPRINTF(n, args)
#endif

/*
 * Our configration for dm9601
 */
/* timeouts */
#define	ONESEC	(drv_usectohz(1*1000000))

/*
 * Local device definitions
 */
struct udmf_dev {
	/*
	 * Misc HW information
	 */
	uint8_t	rcr;
	uint8_t	last_nsr;
	uint8_t	mac_addr[ETHERADDRL];
};

/*
 * private functions
 */

/* mii operations */
static uint16_t udmf_mii_read(struct usbgem_dev *, uint_t, int *errp);
static void udmf_mii_write(struct usbgem_dev *, uint_t, uint16_t, int *errp);

/* nic operations */
static int udmf_reset_chip(struct usbgem_dev *);
static int udmf_init_chip(struct usbgem_dev *);
static int udmf_start_chip(struct usbgem_dev *);
static int udmf_stop_chip(struct usbgem_dev *);
static int udmf_set_media(struct usbgem_dev *);
static int udmf_set_rx_filter(struct usbgem_dev *);
static int udmf_get_stats(struct usbgem_dev *);
static void udmf_interrupt(struct usbgem_dev *, mblk_t *);

/* packet operations */
static mblk_t *udmf_tx_make_packet(struct usbgem_dev *, mblk_t *);
static mblk_t *udmf_rx_make_packet(struct usbgem_dev *, mblk_t *);

/* =============================================================== */
/*
 * I/O functions
 */
/* =============================================================== */
#define	OUT(dp, ix, len, buf, errp, label)	\
	if ((*(errp) = usbgem_ctrl_out((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_HOST_TO_DEV	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */	1,	\
	/* wValue */	0,	\
	/* wIndex */	(ix),	\
	/* wLength */	(len),	\
	/* value */	(buf),	\
	/* size */	(len))) != USB_SUCCESS) goto label

#define	OUTB(dp, ix, val, errp, label)	\
	if ((*(errp) = usbgem_ctrl_out((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_HOST_TO_DEV	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */	3,	\
	/* wValue */	(val),	\
	/* wIndex */	(ix),	\
	/* wLength */	0,	\
	/* value */	NULL,	\
	/* size */	0)) != USB_SUCCESS) goto label

#define	IN(dp, ix, len, buf, errp, label)	\
	if ((*(errp) = usbgem_ctrl_in((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_DEV_TO_HOST	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */	0,	\
	/* wValue */	0,	\
	/* wIndex */	(ix),	\
	/* wLength */	(len),	\
	/* valuep */	(buf),	\
	/* size */	(len))) != USB_SUCCESS) goto label

/* =============================================================== */
/*
 * Hardware manupilation
 */
/* =============================================================== */
static void
udmf_enable_phy(struct usbgem_dev *dp)
{
	int	err = USB_SUCCESS;

	/* de-assert reset signal to phy */
	OUTB(dp, GPCR, GPCR_OUT(0), &err, usberr);
	OUTB(dp, GPR, 0, &err, usberr);
usberr:
	;
}

static int
udmf_reset_chip(struct usbgem_dev *dp)
{
	int	err = USB_SUCCESS;

	DPRINTF(2, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	OUTB(dp, NCR, NCR_LBK_NORMAL | NCR_RST, &err, usberr);
	drv_usecwait(100);
usberr:
	return (err);
}

/*
 * Setup dm9601
 */
static int
udmf_init_chip(struct usbgem_dev *dp)
{
	int		i;
	uint32_t	val;
	int		err = USB_SUCCESS;
	uint16_t	reg;
	uint8_t		buf[2];
	struct udmf_dev	*lp = dp->private;

	DPRINTF(2, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	OUTB(dp, NCR, NCR_LBK_NORMAL, &err, usberr);

	/* tx control regiser: enable padding and crc generation */
	OUTB(dp, TCR, 0, &err, usberr);

	/* rx control register: will be set later by udmf_set_rx_filer() */
	lp->rcr = RCR_RUNT;

	/* back pressure threshold: */
	OUTB(dp, BPTR, (2 << BPTR_BPHW_SHIFT) | BPTR_JPT_200us,
	    &err, usberr);

	/* flow control threshold: same as default */
	OUTB(dp, FCTR, (3 << FCTR_HWOT_SHIFT) | (8 << FCTR_LWOT_SHIFT),
	    &err, usberr);

	/* usb control register */
	OUTB(dp, USBC, USBC_EP3ACK | 0x06, &err, usberr);

	/* flow control: will be set later by udmf_set_media() */

	/* wake up control register: */
	OUTB(dp, WCR, 0, &err, usberr);

usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end err:%d(%s)",
	    dp->name, __func__,
	    err, err == USB_SUCCESS ? "success" : "error"));
	return (err);
}

static int
udmf_start_chip(struct usbgem_dev *dp)
{
	int	err = USB_SUCCESS;
	struct udmf_dev	*lp = dp->private;

	/* enable Rx */
	lp->rcr |= RCR_RXEN;
	OUTB(dp, RCR, lp->rcr, &err, usberr);

usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end err:%d(%s)",
	    dp->name, __func__,
	    err, err == USB_SUCCESS ? "success" : "error"));
	return (err);
}

static int
udmf_stop_chip(struct usbgem_dev *dp)
{
	int	err = USB_SUCCESS;
	struct udmf_dev	*lp = dp->private;

	/* disable rx */
	lp->rcr &= ~RCR_RXEN;
	OUTB(dp, RCR, lp->rcr, &err, usberr);

usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end err:%d(%s)",
	    dp->name, __func__,
	    err, err == USB_SUCCESS ? "success" : "error"));
	return (err);
}

static int
udmf_get_stats(struct usbgem_dev *dp)
{
	/* empty */
	return (USB_SUCCESS);
}

static uint_t
udmf_mcast_hash(struct usbgem_dev *dp, const uint8_t *addr)
{
	return (usbgem_ether_crc_le(addr) & 0x3f);
}

static int
udmf_set_rx_filter(struct usbgem_dev *dp)
{
	int		i;
	uint8_t		rcr;
	uint8_t		mode;
	uint8_t		mhash[8];
	uint8_t		*mac;
	uint_t		h;
	int		err = USB_SUCCESS;
	struct udmf_dev	*lp = dp->private;
	static uint8_t	invalid_mac[ETHERADDRL] = {0, 0, 0, 0, 0, 0};

	DPRINTF(2, (CE_CONT, "!%s: %s: called, rxmode:%x",
	    dp->name, __func__, dp->rxmode));

	if (lp->rcr & RCR_RXEN) {
		/* set promiscuous mode before changing rx filter mode */
		OUTB(dp, RCR, lp->rcr | RCR_PRMSC, &err, usberr);
	}

	lp->rcr &= ~(RCR_ALL | RCR_PRMSC);
	mode = 0;
	bzero(mhash, sizeof (mhash));
	mac = dp->cur_addr.ether_addr_octet;

	if ((dp->rxmode & RXMODE_ENABLE) == 0) {
		mac = invalid_mac;
	} else if (dp->rxmode & RXMODE_PROMISC) {
		/* promiscious mode implies all multicast and all physical */
		mode |= RCR_PRMSC;
	} else if ((dp->rxmode & RXMODE_ALLMULTI) || dp->mc_count > 32) {
		/* accept all multicast packets */
		mode |= RCR_ALL;
	} else if (dp->mc_count > 0) {
		/*
		 * make hash table to select interresting
		 * multicast address only.
		 */
		for (i = 0; i < dp->mc_count; i++) {
			/* hash table is 64 = 2^6 bit width */
			h = dp->mc_list[i].hash;
			mhash[h / 8] |= 1 << (h % 8);
		}
	}

	/* set node address */
	if (bcmp(mac, lp->mac_addr, ETHERADDRL) != 0) {
		OUT(dp, PAR, ETHERADDRL, dp->cur_addr.ether_addr_octet,
		    &err, usberr);
		bcopy(mac, lp->mac_addr, ETHERADDRL);
	}

	/* set multicast hash table */
	OUT(dp, MAR, sizeof (mhash), &mhash[0], &err, usberr);

	/* update rcr */
	lp->rcr |= mode;
	OUTB(dp, RCR, lp->rcr, &err, usberr);

#if DEBUG_LEVEL > 1
	/* verify rcr */
	IN(dp, RCR, 1, &rcr, &err, usberr);
	cmn_err(CE_CONT, "!%s: %s: rcr:%b returned",
	    dp->name, __func__, rcr, RCR_BITS);
#endif
usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end err:%d(%s)",
	    dp->name, __func__,
	    err, err == USB_SUCCESS ? "success" : "error"));
	return (err);
}

static int
udmf_set_media(struct usbgem_dev *dp)
{
	int	err = USB_SUCCESS;
	uint8_t	fcr;
	struct udmf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* setup flow control */
	fcr = 0;
	if (dp->full_duplex) {
		/* select flow control */
		switch (dp->flow_control) {
		case FLOW_CONTROL_RX_PAUSE:
			fcr |= FCR_FLCE;
			break;

		case FLOW_CONTROL_TX_PAUSE:
			fcr |= FCR_TXPEN;
			break;

		case FLOW_CONTROL_SYMMETRIC:
			fcr |= FCR_FLCE | FCR_TXPEN;
			break;
		}
	}

	/* update flow control register */
	OUTB(dp, FCR, fcr, &err, usberr);

usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end err:%d(%s)",
	    dp->name, __func__,
	    err, err == USB_SUCCESS ? "success" : "error"));
	return (err);
}

/*
 * send/receive packet check
 */
static mblk_t *
udmf_tx_make_packet(struct usbgem_dev *dp, mblk_t *mp)
{
	int		n;
	size_t		pkt_size;
	mblk_t		*new;
	mblk_t		*tp;
	uint8_t		*bp;
	uint8_t		*last_pos;
	uint_t		align_mask;

	pkt_size = msgdsize(mp);
	align_mask = 63;

	/*
	 * re-allocate the mp
	 */

	/* minimum ethernet packet size of ETHERMIN */
	pkt_size = max(pkt_size, ETHERMIN);

#if 0 /* CONFIG_ADD_TX_DELIMITOR_ALWAYS */
	pkt_size += TX_HEADER_SIZE;
#endif
	if (((pkt_size + TX_HEADER_SIZE) & align_mask) == 0) {
		/* padding is required in usb communication */
		pkt_size += TX_HEADER_SIZE;
	}

	if ((new = allocb(TX_HEADER_SIZE + pkt_size, 0)) == NULL) {
		return (NULL);
	}
	new->b_wptr = new->b_rptr + TX_HEADER_SIZE + pkt_size;

	/* add a header */
	bp = new->b_rptr;
	bp[0] = (uint8_t)pkt_size;
	bp[1] = (uint8_t)(pkt_size >> 8);
	bp += TX_HEADER_SIZE;

	/* copy contents of the buffer */
	for (tp = mp; tp; tp = tp->b_cont) {
		n = MBLKL(tp);
		bcopy(tp->b_rptr, bp, n);
		bp += n;
	}

	/* clear the rest including the next zero length header */
	last_pos = new->b_wptr;
	while (bp < last_pos) {
		*bp++ = 0;
	}

	return (new);
}

static void
udmf_dump_packet(struct usbgem_dev *dp, uint8_t *bp, int n)
{
	int	i;

	for (i = 0; i < n; i += 8, bp += 8) {
		cmn_err(CE_CONT, "%02x %02x %02x %02x %02x %02x %02x %02x",
		    bp[0], bp[1], bp[2], bp[3], bp[4], bp[5], bp[6], bp[7]);
	}
}

static mblk_t *
udmf_rx_make_packet(struct usbgem_dev *dp, mblk_t *mp)
{
	size_t len;
	uint8_t	rx_stat;

	len = MBLKL(mp);

	if (len <= RX_HEADER_SIZE) {
		/*
		 * the usb bulk-in frame doesn't include a valid
		 * ethernet packet.
		 */
		return (NULL);
	}

	/* remove rx header */
	rx_stat = mp->b_rptr[0];
	if (rx_stat & (RSR_RF |  RSR_LCS | RSR_RWTO |
	    RSR_PLE | RSR_AE | RSR_CE |  RSR_FOE)) {
		if (rx_stat & RSR_RF) {
			dp->stats.runt++;
		}
		if (rx_stat & RSR_LCS) {
			/* late collision */
			dp->stats.rcv_internal_err++;
		}
		if (rx_stat & RSR_RWTO) {
			/* rx timeout */
			dp->stats.rcv_internal_err++;
		}
		if (rx_stat & RSR_PLE) {
			/* physical layer error */
			dp->stats.rcv_internal_err++;
		}
		if (rx_stat & RSR_AE) {
			/* alignment error */
			dp->stats.frame++;
		}
		if (rx_stat & RSR_CE) {
			/* crc error */
			dp->stats.crc++;
		}
		if (rx_stat & RSR_FOE) {
			/* fifo overflow error */
			dp->stats.overflow++;
		}
		dp->stats.errrcv++;
	}
	len = LE16P(&mp->b_rptr[1]);
	if (len >= ETHERFCSL) {
		len -= ETHERFCSL;
	}
	mp->b_rptr += RX_HEADER_SIZE;
	mp->b_wptr = mp->b_rptr + len;

	return (mp);
}

/*
 * MII Interfaces
 */
static uint16_t
udmf_ep_read(struct usbgem_dev *dp, uint_t which, uint_t addr, int *errp)
{
	int	i;
	uint8_t	epcr;
	uint16_t	val;

	DPRINTF(4, (CE_CONT, "!%s: %s: called, ix:%d",
	    dp->name, __func__, addr));

	OUTB(dp, EPAR, addr, errp, usberr);
	OUTB(dp, EPCR, which | EPCR_ERPRR, errp, usberr);

	for (i = 0; i < 100; i++) {
		IN(dp, EPCR, sizeof (epcr), &epcr, errp, usberr);
		if ((epcr & EPCR_ERRE) == 0) {
			/* done */
			IN(dp, EPDR, sizeof (val), &val, errp, usberr);
			val = LE_16(val);
			goto done;
		}
		drv_usecwait(10);
	}
	/* timeout */
	cmn_err(CE_WARN, "!%s: %s: timeout", dp->name, __func__);
	val = 0;
done:
	OUTB(dp, EPCR, 0, errp, usberr);
	return (val);

usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end err:%d(%s)",
	    dp->name, __func__,
	    *errp, *errp == USB_SUCCESS ? "success" : "error"));
	return (0);
}

static void
udmf_ep_write(struct usbgem_dev *dp, uint_t which, uint_t addr,
    uint16_t val, int *errp)
{
	int	i;
	uint8_t	epcr;

	DPRINTF(5, (CE_CONT, "!%s: %s called", dp->name, __func__));

	val = LE_16(val);
	OUT(dp, EPDR, sizeof (val), &val, errp, usberr);

	OUTB(dp, EPAR, addr, errp, usberr);

	OUTB(dp, EPCR, which | EPCR_WEP | EPCR_ERPRW, errp, usberr);

	for (i = 0; i < 100; i++) {
		IN(dp, EPCR, 1, &epcr, errp, usberr);
		if ((epcr & EPCR_ERRE) == 0) {
			/* done */
			goto done;
		}
		drv_usecwait(10);
	}
	/* timeout */
	cmn_err(CE_WARN, "!%s: %s: timeout", dp->name, __func__);
done:
	OUTB(dp, EPCR, 0, errp, usberr);
	return;

usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end err:%d(%s)",
	    dp->name, __func__,
	    *errp, *errp == USB_SUCCESS ? "success" : "error"));
}

static uint16_t
udmf_mii_read(struct usbgem_dev *dp, uint_t index, int *errp)
{
	uint16_t	val;

	val = udmf_ep_read(dp, EPCR_EPOS,
	    (dp->mii_phy_addr << EPAR_PHYADR_SHIFT) | index, errp);

	return (val);
}

static void
udmf_mii_write(struct usbgem_dev *dp, uint_t index, uint16_t val, int *errp)
{
	udmf_ep_write(dp, EPCR_EPOS,
	    (dp->mii_phy_addr << EPAR_PHYADR_SHIFT) | index, val, errp);
}

static void
udmf_interrupt(struct usbgem_dev *dp, mblk_t *mp)
{
	struct intr_msg	*imp;
	struct udmf_dev	*lp = dp->private;

	imp = (struct intr_msg *)&mp->b_rptr[0];

	DPRINTF(4, (CE_CONT,
	    "!%s: %s: size:%d, nsr:%b tsr1:%b tsr2:%b"
	    " rsr:%b rocr:%b rxc:%02x txc:%b gpr:%b",
	    dp->name, __func__, mp->b_wptr - mp->b_rptr,
	    imp->im_nsr, NSR_BITS,
	    imp->im_tsr1, TSR_BITS,
	    imp->im_tsr2, TSR_BITS,
	    imp->im_rsr, RSR_BITS,
	    imp->im_rocr, ROCR_BITS,
	    imp->im_rxc,
	    imp->im_txc, TUSR_BITS,
	    imp->im_gpr, GPR_BITS));

	if ((lp->last_nsr ^ imp->im_nsr) & NSR_LINKST) {
		usbgem_mii_update_link(dp);
	}

	lp->last_nsr = imp->im_nsr;
}

/* ======================================================== */
/*
 * OS depend (device driver DKI) routine
 */
/* ======================================================== */
static uint16_t
udmf_eeprom_read(struct usbgem_dev *dp, uint_t index, int *errp)
{
	uint16_t	val;

	val = udmf_ep_read(dp, 0, index, errp);

	return (val);
}

#ifdef DEBUG_LEVEL
static void
udmf_eeprom_dump(struct usbgem_dev *dp, int size)
{
	int	i;
	int	err;
	uint16_t	w0, w1, w2, w3;

	cmn_err(CE_CONT, "!%s: eeprom dump:", dp->name);

	err = USB_SUCCESS;

	for (i = 0; i < size; i += 4) {
		w0 = udmf_eeprom_read(dp, i + 0, &err);
		w1 = udmf_eeprom_read(dp, i + 1, &err);
		w2 = udmf_eeprom_read(dp, i + 2, &err);
		w3 = udmf_eeprom_read(dp, i + 3, &err);
		cmn_err(CE_CONT, "!0x%02x: 0x%04x 0x%04x 0x%04x 0x%04x",
		    i, w0, w1, w2, w3);
	}
usberr:
	;
}
#endif

static int
udmf_attach_chip(struct usbgem_dev *dp)
{
	int	i;
	uint_t	val;
	uint8_t	*m;
	int	err;
	struct udmf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s enter", dp->name, __func__));

	/*
	 * get mac address from EEPROM
	 */
	m = dp->dev_addr.ether_addr_octet;
	for (i = 0; i < ETHERADDRL; i += 2)  {
		val = udmf_eeprom_read(dp, i/2, &err);
		m[i + 0] = (uint8_t)val;
		m[i + 1] = (uint8_t)(val >> 8);
	}

	/* invalidate a private cache for mac addr */
	bzero(lp->mac_addr, sizeof (lp->mac_addr));
#ifdef CONFIG_VLAN
	dp->misc_flag = USBGEM_VLAN;
#endif
#if DEBUG_LEVEL > 0
	udmf_eeprom_dump(dp, /* 0x3f + 1 */ 128);
#endif
{
	static uint8_t bcst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	DPRINTF(0, (CE_CONT, "!%s: %s: hash of bcast:%x",
	    dp->name, __func__, usbgem_ether_crc_be(bcst)));
}
	return (USB_SUCCESS);

usberr:
	cmn_err(CE_WARN, "%s: %s: usb error detected (%d)",
	    dp->name, __func__, err);
	return (USB_FAILURE);
}

static int
udmf_mii_probe(struct usbgem_dev *dp)
{
	DPRINTF(2, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	udmf_enable_phy(dp);
	return (usbgem_mii_probe_default(dp));
}

static int
udmf_mii_init(struct usbgem_dev *dp)
{
	DPRINTF(2, (CE_CONT, "!%s: %s: called", dp->name, __func__));
	udmf_enable_phy(dp);
	return (USB_SUCCESS);
}

static int
udmfattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			i;
	ddi_iblock_cookie_t	c;
	int			ret;
	int			revid;
	int			unit;
	int			len;
	const char		*drv_name;
	struct usbgem_dev	*dp;
	void			*base;
	struct usbgem_conf	*ugcp;
	struct udmf_dev		*lp;

	unit = ddi_get_instance(dip);
	drv_name = ddi_driver_name(dip);

	DPRINTF(3, (CE_CONT, "!%s%d: %s: called, cmd:%d",
	    drv_name, unit, __func__, cmd));

	if (cmd == DDI_ATTACH) {
		/*
		 * construct usbgem configration
		 */
		ugcp = kmem_zalloc(sizeof (*ugcp), KM_SLEEP);

		/* name */
		/*
		 * softmac requires that ppa is the instance number
		 * of the device, otherwise it hangs in seaching the device.
		 */
		(void) sprintf(ugcp->usbgc_name, "%s%d", drv_name, unit);
		ugcp->usbgc_ppa = unit;

		ugcp->usbgc_ifnum = 0;
		ugcp->usbgc_alt = 0;

		ugcp->usbgc_tx_list_max = 64;

		ugcp->usbgc_rx_header_len = RX_HEADER_SIZE;
		ugcp->usbgc_rx_list_max = 64;

		/* time out parameters */
		ugcp->usbgc_tx_timeout = USBGEM_TX_TIMEOUT;
		ugcp->usbgc_tx_timeout_interval = USBGEM_TX_TIMEOUT_INTERVAL;
#if 1
		/* flow control */
		ugcp->usbgc_flow_control = FLOW_CONTROL_RX_PAUSE;
#else
		/*
		 * XXX - flow control caused link down frequently under
		 * heavy traffic
		 */
		ugcp->usbgc_flow_control = FLOW_CONTROL_NONE;
#endif
		/* MII timeout parameters */
		ugcp->usbgc_mii_link_watch_interval =
		    USBGEM_LINK_WATCH_INTERVAL;
		ugcp->usbgc_mii_an_watch_interval =
		    USBGEM_LINK_WATCH_INTERVAL/5;
		ugcp->usbgc_mii_reset_timeout = MII_RESET_TIMEOUT; /* 1 sec */
		ugcp->usbgc_mii_an_timeout = MII_AN_TIMEOUT;	/* 5 sec */
		ugcp->usbgc_mii_an_wait = (25*ONESEC)/10;
		ugcp->usbgc_mii_linkdown_timeout = MII_LINKDOWN_TIMEOUT;

		ugcp->usbgc_mii_an_delay = ONESEC/10;
		ugcp->usbgc_mii_linkdown_action = MII_ACTION_RSA;
		ugcp->usbgc_mii_linkdown_timeout_action = MII_ACTION_RESET;
		ugcp->usbgc_mii_dont_reset = B_FALSE;
		ugcp->usbgc_mii_hw_link_detection = B_TRUE;

		/* I/O methods */

		/* mac operation */
		ugcp->usbgc_attach_chip = &udmf_attach_chip;
		ugcp->usbgc_reset_chip = &udmf_reset_chip;
		ugcp->usbgc_init_chip = &udmf_init_chip;
		ugcp->usbgc_start_chip = &udmf_start_chip;
		ugcp->usbgc_stop_chip = &udmf_stop_chip;
		ugcp->usbgc_multicast_hash = &udmf_mcast_hash;

		ugcp->usbgc_set_rx_filter = &udmf_set_rx_filter;
		ugcp->usbgc_set_media = &udmf_set_media;
		ugcp->usbgc_get_stats = &udmf_get_stats;
		ugcp->usbgc_interrupt = &udmf_interrupt;

		/* packet operation */
		ugcp->usbgc_tx_make_packet = &udmf_tx_make_packet;
		ugcp->usbgc_rx_make_packet = &udmf_rx_make_packet;

		/* mii operations */
		ugcp->usbgc_mii_probe = &udmf_mii_probe;
		ugcp->usbgc_mii_init = &udmf_mii_init;
		ugcp->usbgc_mii_config = &usbgem_mii_config_default;
		ugcp->usbgc_mii_read = &udmf_mii_read;
		ugcp->usbgc_mii_write = &udmf_mii_write;
		ugcp->usbgc_mii_addr_min = 1;

		/* mtu */
		ugcp->usbgc_min_mtu = ETHERMTU;
		ugcp->usbgc_max_mtu = ETHERMTU;
		ugcp->usbgc_default_mtu = ETHERMTU;

		lp = kmem_zalloc(sizeof (struct udmf_dev), KM_SLEEP);

		ddi_set_driver_private(dip, NULL);

		dp = usbgem_do_attach(dip, ugcp, lp, sizeof (struct udmf_dev));

		kmem_free(ugcp, sizeof (*ugcp));

		if (dp != NULL) {
			return (DDI_SUCCESS);
		}

err_free_mem:
		kmem_free(lp, sizeof (struct udmf_dev));
err_close_pipe:
err:
		return (DDI_FAILURE);
	}

	if (cmd == DDI_RESUME) {
		return (usbgem_resume(dip));
	}

	return (DDI_FAILURE);
}

static int
udmfdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	ret;

	if (cmd == DDI_DETACH) {
		ret = usbgem_do_detach(dip);
		if (ret != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	}
	if (cmd == DDI_SUSPEND) {
		return (usbgem_suspend(dip));
	}
	return (DDI_FAILURE);
}

/* ======================================================== */
/*
 * OS depend (loadable streams driver) routine
 */
/* ======================================================== */
#ifdef USBGEM_CONFIG_GLDv3
USBGEM_STREAM_OPS(udmf_ops, udmfattach, udmfdetach);
#else
static	struct module_info udmfminfo = {
	0,			/* mi_idnum */
	"udmf",			/* mi_idname */
	0,			/* mi_minpsz */
	ETHERMTU,		/* mi_maxpsz */
	ETHERMTU*128,		/* mi_hiwat */
	1,			/* mi_lowat */
};

static	struct qinit udmfrinit = {
	(int (*)()) NULL,	/* qi_putp */
	usbgem_rsrv,		/* qi_srvp */
	usbgem_open,		/* qi_qopen */
	usbgem_close,		/* qi_qclose */
	(int (*)()) NULL,	/* qi_qadmin */
	&udmfminfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct qinit udmfwinit = {
	usbgem_wput,		/* qi_putp */
	usbgem_wsrv,		/* qi_srvp */
	(int (*)()) NULL,	/* qi_qopen */
	(int (*)()) NULL,	/* qi_qclose */
	(int (*)()) NULL,	/* qi_qadmin */
	&udmfminfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct streamtab	udmf_info = {
	&udmfrinit,	/* st_rdinit */
	&udmfwinit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

static	struct cb_ops cb_udmf_ops = {
	nulldev,	/* cb_open */
	nulldev,	/* cb_close */
	nodev,		/* cb_strategy */
	nodev,		/* cb_print */
	nodev,		/* cb_dump */
	nodev,		/* cb_read */
	nodev,		/* cb_write */
	nodev,		/* cb_ioctl */
	nodev,		/* cb_devmap */
	nodev,		/* cb_mmap */
	nodev,		/* cb_segmap */
	nochpoll,	/* cb_chpoll */
	ddi_prop_op,	/* cb_prop_op */
	&udmf_info,	/* cb_stream */
	D_NEW|D_MP	/* cb_flag */
};

static	struct dev_ops udmf_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	usbgem_getinfo,	/* devo_getinfo */
	nulldev,	/* devo_identify */
	nulldev,	/* devo_probe */
	udmfattach,	/* devo_attach */
	udmfdetach,	/* devo_detach */
	nodev,		/* devo_reset */
	&cb_udmf_ops,	/* devo_cb_ops */
	NULL,		/* devo_bus_ops */
	usbgem_power,   /* devo_power */
#if DEVO_REV >= 4
	usbgem_quiesce, /* devo_quiesce */
#endif
};
#endif

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	ident,
	&udmf_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/* ======================================================== */
/*
 * _init : done
 */
/* ======================================================== */
int
_init(void)
{
	int 	status;

	DPRINTF(2, (CE_CONT, "!udmf: _init: called"));

	status = usbgem_mod_init(&udmf_ops, "udmf");
	if (status != DDI_SUCCESS) {
		return (status);
	}
	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS) {
		usbgem_mod_fini(&udmf_ops);
	}
	return (status);
}

/*
 * _fini : done
 */
int
_fini(void)
{
	int	status;

	DPRINTF(2, (CE_CONT, "!udmf: _fini: called"));
	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		usbgem_mod_fini(&udmf_ops);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
