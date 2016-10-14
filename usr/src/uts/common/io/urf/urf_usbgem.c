/*
 * urf_usbgem.c : Realtek RTL8150 USB to Fast Ethernet Driver for Solaris
 *
 * Copyright (c) 2003-2012 Masayuki Murayama.  All rights reserved.
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
#include <sys/usb/usba.h>
#include "usbgem.h"
#include "usbgem_mii.h"
#include "rtl8150reg.h"

char	ident[] = "rtl8150 usbnic driver v" VERSION;

/*
 * Useful macros
 */
#define	ROUNDUP2(x, y)	(((x)+(y)-1) & ~((y)-1))
#define	CHECK_AND_JUMP(err, label)	if (err != USB_SUCCESS) goto label

/*
 * Debugging
 */
#ifdef DEBUG_LEVEL
static int urf_debug = DEBUG_LEVEL;
#define	DPRINTF(n, args)	if (urf_debug > (n)) cmn_err args
#else
#define	DPRINTF(n, args)
#endif

/*
 * Our configration for rtl8150
 */
/* timeouts */
#define	ONESEC			(drv_usectohz(1*1000000))

/*
 * Local device definitions
 */
struct chip_info {
	int		flags;
	char		*name;
	int		type;
};

#define	CHIPTABLESIZE	(sizeof (chiptbl_8150) / sizeof (struct chip_info))

struct urf_dev {
	/*
	 * Misc HW information
	 */
	struct chip_info	*chip;
	uint8_t			cr;
	uint8_t			tsr;
	uint16_t		rcr;
	uint8_t			txok_cnt;
};

/*
 * private functions
 */

/* mii operations */
static uint16_t  urf_mii_read(struct usbgem_dev *, uint_t, int *errp);
static void urf_mii_write(struct usbgem_dev *, uint_t, uint16_t, int *errp);

/* nic operations */
static int urf_attach_chip(struct usbgem_dev *);
static int urf_reset_chip(struct usbgem_dev *);
static int urf_init_chip(struct usbgem_dev *);
static int urf_start_chip(struct usbgem_dev *);
static int urf_stop_chip(struct usbgem_dev *);
static int urf_set_media(struct usbgem_dev *);
static int urf_set_rx_filter(struct usbgem_dev *);
static int urf_get_stats(struct usbgem_dev *);

/* packet operations */
static mblk_t *urf_tx_make_packet(struct usbgem_dev *, mblk_t *);
static mblk_t *urf_rx_make_packet(struct usbgem_dev *, mblk_t *);

/* =============================================================== */
/*
 * I/O functions
 */
/* =============================================================== */
#define	OUTB(dp, p, v, errp, label)	\
	if ((*(errp) = usbgem_ctrl_out_val((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_HOST_TO_DEV	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ USB_REQ_SET_ADDRESS,	\
	/* wValue */   (p),	\
	/* wIndex */   0,	\
	/* wLength */  1,	\
	/* value */   (v))) != USB_SUCCESS) goto label

#define	OUTW(dp, p, v, errp, label)	\
	if ((*(errp) = usbgem_ctrl_out_val((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_HOST_TO_DEV	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ USB_REQ_SET_ADDRESS,	\
	/* wValue */   (p),	\
	/* wIndex */   0,	\
	/* wLength */  2,	\
	/* value */   (v))) != USB_SUCCESS) goto label

/* BEGIN CSTYLED */
#define	OUTS(dp, p, buf, len, errp, label)	\
	if ((*(errp) = usbgem_ctrl_out((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_HOST_TO_DEV	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ USB_REQ_SET_ADDRESS,	\
	/* wValue */   (p),	\
	/* wIndex */   0,	\
	/* wLength */  (len),	\
	/* value */    (buf),	\
	/* size */     (len))) != USB_SUCCESS) goto label
/* END CSTYLED */

#define	IN(dp, p, vp, errp, label)	\
	if ((*(errp) = usbgem_ctrl_in_val((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_DEV_TO_HOST	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ USB_REQ_SET_ADDRESS,	\
	/* wValue */  (p),	\
	/* wIndex */  0,	\
	/* wLength */ sizeof ((*vp)),	\
	/* valuep */  (vp))) != USB_SUCCESS) goto label

#define	INS(dp, p, buf, len, errp, label)	\
	if ((*(errp) = usbgem_ctrl_in((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_DEV_TO_HOST	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ USB_REQ_SET_ADDRESS,	\
	/* wValue */   (p),	\
	/* wIndex */   0,	\
	/* wLength */  (len),	\
	/* valuep */  (buf),	\
	/* size   */  (len))) != USB_SUCCESS) goto label

/* =============================================================== */
/*
 * variables
 */
/* =============================================================== */
static int urf_ppa = 0;

/* =============================================================== */
/*
 * Hardware manupilation
 */
/* =============================================================== */
static int
urf_reset_chip(struct usbgem_dev *dp)
{
	int		i;
	int		err;
	uint8_t		reg;
	struct urf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	lp->cr = 0;
	OUTB(dp, CR, lp->cr | CR_SOFT_RST, &err, usberr);

	for (i = 0; i < 100; i++) {
		IN(dp, CR, &reg, &err, usberr);
		if ((reg & CR_SOFT_RST) == 0) {
			return (USB_SUCCESS);
		}
	}
	/* time out */
	cmn_err(CE_WARN, "%s: failed to reset: timeout", dp->name);
	return (USB_FAILURE);

usberr:
	cmn_err(CE_NOTE, "!%s: %s: usberr detected", dp->name, __func__);
	return (USB_FAILURE);
}

/*
 * Setup rtl8150
 */
static int
urf_init_chip(struct usbgem_dev *dp)
{
	int		i;
	uint32_t	val;
	int		err;
	struct urf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* ID registers: set later by urf_set_rx_filter */

	/* Multicast registers: set later by urf_set_rx_filter */

	/* Command register : Enable Tx and Rx before writing TCR and RCR */
	lp->cr |= CR_RE | CR_TE;
	OUTB(dp, CR, lp->cr, &err, usberr);

	/* Transmit configration register : */
	OUTB(dp, TCR, TCR_IFG_802_3, &err, usberr);

	/* Receive configuration register :  disable rx filter */
	lp->rcr = RCR_TAIL | RCR_AER | RCR_AR;
	OUTW(dp, RCR, lp->rcr, &err, usberr);
#ifdef notdef
	/* Media status register */
	err = urf_set_media(dp);
	CHECK_AND_JUMP(err, usberr);
#endif
	/* Configuration register 0: no need to change */

	DPRINTF(2, (CE_CONT, "!%s: %s: end (success)", dp->name, __func__));
	return (USB_SUCCESS);

usberr:
	cmn_err(CE_NOTE, "!%s: %s: usberr detected", dp->name, __func__);
	return (USB_FAILURE);
}

static int
urf_start_chip(struct usbgem_dev *dp)
{
	struct urf_dev	*lp = dp->private;

	/* do nothing */
	return (USB_SUCCESS);
}

static int
urf_stop_chip(struct usbgem_dev *dp)
{
	return (urf_reset_chip(dp));
}

static int
urf_get_stats(struct usbgem_dev *dp)
{
	/* do nothing */
	return (USB_SUCCESS);
}

static uint_t
urf_mcast_hash(struct usbgem_dev *dp, const uint8_t *addr)
{
	return (usbgem_ether_crc_be(addr));
}

static int
urf_set_rx_filter(struct usbgem_dev *dp)
{
	int		i;
	uint16_t	mode;
	uint8_t		mhash[8];
	int		err;
	int16_t		rcr;
	struct urf_dev	*lp = dp->private;

	DPRINTF(2, (CE_CONT, "!%s: %s: called, rxmode:%x",
	    dp->name, __func__, dp->rxmode));

	if (lp->rcr & (RCR_AB | RCR_AD | RCR_AAM | RCR_AAP | RCR_AM)) {
#ifdef notdef
		/* disable rx filter before changing it. */
		lp->rcr &= ~(RCR_AB | RCR_AD | RCR_AAM | RCR_AAP | RCR_AM);
		OUTW(dp, RCR, lp->rcr, &err, usberr);
#else
		/* receive all packets while we change rx filter */
		OUTW(dp, RCR, lp->rcr | RCR_AAM | RCR_AAP, &err, usberr);
#endif
	}

	mode = RCR_AB	/* accept broadcast */
	    | RCR_AD;	/* accept physical match  */
	bzero(mhash, sizeof (mhash));

	if (dp->rxmode & RXMODE_PROMISC) {
		/* promiscious mode implies all multicast and all physical */
		mode |= RCR_AAM | RCR_AAP;
	} else if ((dp->rxmode & RXMODE_ALLMULTI) || dp->mc_count > 64/2) {
		/* accept all multicast packets */
		mode |= RCR_AAM;
	} else if (dp->mc_count > 0) {
		/*
		 * make hash table to select interresting
		 * multicast address only.
		 */
		mode |= RCR_AM;
		for (i = 0; i < dp->mc_count; i++) {
			uint_t	h;
			/* hash table is 64 = 2^6 bit width */
			h = dp->mc_list[i].hash >> (32 - 6);
			mhash[h / 8] |= 1 << (h % 8);
		}
	}
	lp->rcr |= mode;

	/* set mac address */
	OUTS(dp, IDR, dp->cur_addr.ether_addr_octet, ETHERADDRL, &err, usberr);

	/* set multicast hash table */
	if (mode & RCR_AM) {
		/* need to set up multicast hash table */
		OUTS(dp, MAR, mhash, sizeof (mhash), &err, usberr);
	}

	OUTW(dp, RCR, lp->rcr, &err, usberr);

#if DEBUG_LEVEL > 2
	IN(dp, RCR, &rcr, &err, usberr);
	cmn_err(CE_CONT, "!%s: %s: rcr:%b returned",
	    dp->name, __func__, rcr, RCR_BITS);
#endif
	return (USB_SUCCESS);

usberr:
	cmn_err(CE_NOTE, "!%s: %s: usberr detected", dp->name, __func__);
	return (USB_FAILURE);
}

static int
urf_set_media(struct usbgem_dev *dp)
{
	uint8_t		new;
	uint8_t		old;
	int		err;
	struct urf_dev	*lp = dp->private;

	DPRINTF(2, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* select duplex: do nothing */

	/* select speed: do nothing */

	/* flow control */
	IN(dp, MSR, &old, &err, usberr);


	/* setup flow control */
	new = old & ~(MSR_TXFCE | MSR_RXFCE);
	switch (dp->flow_control) {
	case FLOW_CONTROL_SYMMETRIC:
		new |= MSR_TXFCE | MSR_RXFCE;
		break;

	case FLOW_CONTROL_TX_PAUSE:
		new |= MSR_TXFCE;
		break;

	case FLOW_CONTROL_RX_PAUSE:
		new |= MSR_RXFCE;
		break;

	case FLOW_CONTROL_NONE:
	default:
		break;
	}

	if (new != old) {
		OUTB(dp, MSR, new, &err, usberr);
	}
	DPRINTF(2, (CE_CONT, "!%s: %s: returned", dp->name, __func__));
	return (USB_SUCCESS);

usberr:
	cmn_err(CE_NOTE, "!%s: %s: usberr detected", dp->name, __func__);
	return (USB_FAILURE);
}

/*
 * send/receive packet check
 */
static mblk_t *
urf_tx_make_packet(struct usbgem_dev *dp, mblk_t *mp)
{
	size_t		len;
	mblk_t		*new;
	mblk_t		*tp;
	uint8_t		*bp;
	uint8_t		*last_pos;

	len = msgdsize(mp);

	if (len < ETHERMIN || mp->b_cont != NULL || (len & 0x3f) == 0) {
		/*
		 * re-allocate mp
		 */
		len = max(len, ETHERMIN);

		if ((len & 0x3f) == 0) {
			/* workaround for buggy USB hba */
			len++;
		}

		if ((new = allocb(len, 0)) == NULL) {
			return (NULL);
		}

		/* copy contents of the buffer */
		new->b_wptr = new->b_rptr + len;
		bp = new->b_rptr;
		for (tp = mp; tp; tp = tp->b_cont) {
			len = (uintptr_t)tp->b_wptr - (uintptr_t)tp->b_rptr;
			bcopy(tp->b_rptr, bp, len);
			bp += len;
		}

		last_pos = new->b_wptr;
		while (bp < last_pos) {
			*bp++ = 0;
		}

		mp = new;
	}

	return (mp);
}

static void
urf_dump_packet(struct usbgem_dev *dp, uint8_t *bp, int n)
{
	int	i;

	for (i = 0; i < n; i += 8, bp += 8) {
		cmn_err(CE_CONT, "%02x %02x %02x %02x %02x %02x %02x %02x",
		    bp[0], bp[1], bp[2], bp[3], bp[4], bp[5], bp[6], bp[7]);
	}
}

static mblk_t *
urf_rx_make_packet(struct usbgem_dev *dp, mblk_t *mp)
{
	uint8_t		*p;
	uint16_t	rxhd;
	uint_t		len;

	ASSERT(mp != NULL);
	len = msgdsize(mp);
#ifdef DEBUG_LEVEL
	DPRINTF(2, (CE_CONT, "!%s: time:%d %s: len:%d cont:%p",
	    dp->name, ddi_get_lbolt(), __func__, len, mp->b_cont));

	if (urf_debug > 2) {
		urf_dump_packet(dp, mp->b_rptr, max(6, len));
	}
#endif
	if (len < ETHERMIN + ETHERFCSL) {
		/* Too short */
		dp->stats.runt++;
		dp->stats.errrcv++;
		return (NULL);
	}

	/* get Rx header which is placed at tail of the packet. */
	p = mp->b_wptr - 4;
	rxhd = (p[1] << 8) | p[0];
	len = rxhd & RXHD_BYTECNT;

	DPRINTF(2, (CE_CONT, "!%s: %s: rsr:%b len:%d",
	    dp->name, __func__, rxhd, RXHD_BITS, len));

	/* check if error happen */
	if ((rxhd & (RXHD_VALID)) == 0) {
		DPRINTF(-1, (CE_CONT, "!%s: %s: rxhd:%b",
		    dp->name, __func__, rxhd, RXHD_BITS));
		if (rxhd & RXHD_RUNT) {
			dp->stats.runt++;
		}

		dp->stats.errrcv++;
		return (NULL);
	}
#ifdef notdef
	/* check packet size */
	if (len > ETHERMAX + ETHERFCSL) {
		/* too long */
		dp->stats.frame_too_long++;
		dp->stats.errrcv++;
		return (NULL);
	} else if (len < ETHERMIN + ETHERFCSL) {
		dp->stats.runt++;
		dp->stats.errrcv++;
		return (NULL);
	}
#endif
	/* remove tailing crc field */
	mp->b_wptr -= ETHERFCSL;
	return (mp);
}

/*
 * MII Interfaces
 */
static uint16_t
urf_mii_read(struct usbgem_dev *dp, uint_t index, int *errp)
{
	int		reg;
	uint16_t	val;

	DPRINTF(4, (CE_CONT, "!%s: %s: called, ix:%d",
	    dp->name, __func__, index));

	*errp = USB_SUCCESS;

	switch (index) {
	case MII_CONTROL:
		reg = BMCR;
		break;

	case MII_STATUS:
		reg = BMSR;
		break;

	case MII_AN_ADVERT:
		reg = ANAR;
		break;

	case MII_AN_LPABLE:
		reg = ANLP;
		break;

	case MII_AN_EXPANSION:
		reg = ANER;
		break;

	default:
		return (0);
	}

	IN(dp, reg, &val, errp, usberr);

	if (index == MII_STATUS) {
		uint8_t	msr;
		/*
		 * Fix MII status register as it does't have LINKUP and
		 * MFPRMBLSUPR bits.
		 */
		IN(dp, MSR, &msr, errp, usberr);

		val |= (MII_STATUS_MFPRMBLSUPR | MII_STATUS_LINKUP);
		if ((msr & MSR_LINK) == 0) {
			val &= ~MII_STATUS_LINKUP;
		}
	}

	return (val);

usberr:
	cmn_err(CE_CONT,
	    "!%s: %s: usberr(%d) detected", dp->name, __func__, *errp);

	return (0);
}

static void
urf_mii_write(struct usbgem_dev *dp, uint_t index, uint16_t val, int *errp)
{
	int	reg;

	DPRINTF(5, (CE_CONT, "!%s: %s called", dp->name, __func__));

	*errp = USB_SUCCESS;

	switch (index) {
	case MII_CONTROL:
		reg = BMCR;
		break;

	case MII_STATUS:
		reg = BMSR;
		break;

	case MII_AN_ADVERT:
		reg = ANAR;
		break;

	case MII_AN_LPABLE:
		reg = ANLP;
		break;

	case MII_AN_EXPANSION:
		reg = ANER;
		break;

	default:
		return;
	}

	OUTW(dp, reg, val, errp, usberr);
usberr:
	;
}

/* ======================================================== */
/*
 * OS depend (device driver DKI) routine
 */
/* ======================================================== */
static void
urf_eeprom_dump(struct usbgem_dev *dp, int size)
{
	int		i;
	int		err;
	uint16_t	w0, w1, w2, w3;

	cmn_err(CE_CONT, "!%s: eeprom dump:", dp->name);
	for (i = URF_EEPROM_BASE; i < size + URF_EEPROM_BASE; i += 8) {
		IN(dp, i + 0, &w0, &err, usberr);
		IN(dp, i + 2, &w1, &err, usberr);
		IN(dp, i + 4, &w2, &err, usberr);
		IN(dp, i + 6, &w3, &err, usberr);
		cmn_err(CE_CONT, "!0x%02x: 0x%04x 0x%04x 0x%04x 0x%04x",
		    i - URF_EEPROM_BASE, w0, w1, w2, w3);
	}
usberr:
	;
}

static int
urf_attach_chip(struct usbgem_dev *dp)
{
	int		i;
	uint8_t		old;
	uint_t		new;
	uint8_t		reg;
	int		err;
	struct urf_dev	*lp = dp->private;

	/*
	 * setup flow control bit in eeprom
	 */
	IN(dp, URF_EEPROM_BASE + 9, &old, &err, usberr);

	DPRINTF(0, (CE_CONT, "!%s: eeprom offset 9: %02x", dp->name, old));

	if (dp->ugc.usbgc_flow_control != FLOW_CONTROL_NONE) {
		/* enable PAUSE bit */
		new = old | 0x04;
	} else {
		/* clear PAUSE bit */
		new = old & ~0x04;
	}
	if (new != old) {
		/* make eeprom writable */
		OUTB(dp, CR, lp->cr | CR_WEPROM, &err, usberr);

		/* eerom allows only word access for writing */
		IN(dp, URF_EEPROM_BASE + 8, &reg, &err, usberr);
		new = (new << 8) | reg;

		OUTW(dp, URF_EEPROM_BASE + 8, new, &err, usberr);

		/* make eeprom non-writable */
		OUTB(dp, CR, lp->cr, &err, usberr);
	}

	/*
	 * load EEPROM contents into nic
	 */
	OUTB(dp, CR, lp->cr | CR_AUTOLOAD, &err, usberr);
	CHECK_AND_JUMP(err, usberr);

	for (i = 0; i < 100; i++) {
		IN(dp, CR, &reg, &err, usberr);
		if ((reg & CR_AUTOLOAD) == 0) {
			goto autoload_done;
		}
	}
	/* timeout */
	cmn_err(CE_WARN, "%s: %s: failed to autoload: timeout",
	    dp->name, __func__);
	goto usberr;

autoload_done:
	/*
	 * mac address in EEPROM has loaded to ID registers.
	 */
	INS(dp, IDR, dp->dev_addr.ether_addr_octet, ETHERADDRL, &err, usberr);

	/* no need to scan phy */
	dp->mii_phy_addr = -1;

#if DEBUG_LEVEL > 2
	urf_eeprom_dump(dp, 0x80);
#endif

#ifdef CONFIG_VLAN
	dp->misc_flag = USBGEM_VLAN;
#endif
	return (USB_SUCCESS);

usberr:
	cmn_err(CE_WARN, "%s: urf_attach_chip: usb error detected", dp->name);
	return (USB_FAILURE);
}

static int
urfattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			i;
	ddi_iblock_cookie_t	c;
	int			ret;
	int			unit;
	struct chip_info	*p;
	const char		*drv_name;
	struct usbgem_dev	*dp;
	void			*base;
	struct usbgem_conf	*ugcp;
	struct urf_dev		*lp;

	unit =  ddi_get_instance(dip);
	drv_name = ddi_driver_name(dip);

	DPRINTF(3, (CE_CONT, "!%s%d: %s: called, cmd:%d",
	    drv_name, __func__, unit, cmd));

	if (cmd == DDI_ATTACH) {
		/*
		 * Check if the chip is supported.
		 */

		/*
		 * Check the chip if it is really realtek rtl8150
		 */

		/*
		 * construct usbgem configration
		 */
		ugcp = kmem_zalloc(sizeof (*ugcp), KM_SLEEP);

		/* name */
		(void) sprintf(ugcp->usbgc_name,
		    "%s%d(ppa=%d)", drv_name, unit, urf_ppa);
#ifdef USBGEM_CONFIG_GLDv3
		ugcp->usbgc_ppa = urf_ppa;
#else
		ugcp->usbgc_ppa = unit;
#endif
		ugcp->usbgc_ifnum = 0;
		ugcp->usbgc_alt = 0;

		ugcp->usbgc_tx_list_max = 16;

		/* the rx status partially replaces FCS */
		ugcp->usbgc_rx_header_len = 0;
		ugcp->usbgc_rx_list_max = 64;

		/* time out parameters */
		ugcp->usbgc_tx_timeout = USBGEM_TX_TIMEOUT;
		ugcp->usbgc_tx_timeout_interval = ONESEC;

		/* flow control */
		ugcp->usbgc_flow_control = FLOW_CONTROL_RX_PAUSE;

		/* MII timeout parameters */
		ugcp->usbgc_mii_link_watch_interval = ONESEC;
		ugcp->usbgc_mii_an_watch_interval = ONESEC/5;
		ugcp->usbgc_mii_reset_timeout = MII_RESET_TIMEOUT; /* 1 sec */
		ugcp->usbgc_mii_an_timeout = MII_AN_TIMEOUT;	/* 5 sec */
		ugcp->usbgc_mii_an_wait = (25*ONESEC)/10;
		ugcp->usbgc_mii_linkdown_timeout = MII_LINKDOWN_TIMEOUT;

		ugcp->usbgc_mii_an_delay = ONESEC/10;
		ugcp->usbgc_mii_linkdown_action = MII_ACTION_RSA;
		ugcp->usbgc_mii_linkdown_timeout_action = MII_ACTION_RESET;
		ugcp->usbgc_mii_dont_reset = B_FALSE;

		/* I/O methods */

		/* mac operation */
		ugcp->usbgc_attach_chip = &urf_attach_chip;
		ugcp->usbgc_reset_chip = &urf_reset_chip;
		ugcp->usbgc_init_chip = &urf_init_chip;
		ugcp->usbgc_start_chip = &urf_start_chip;
		ugcp->usbgc_stop_chip = &urf_stop_chip;
		ugcp->usbgc_multicast_hash = &urf_mcast_hash;

		ugcp->usbgc_set_rx_filter = &urf_set_rx_filter;
		ugcp->usbgc_set_media = &urf_set_media;
		ugcp->usbgc_get_stats = &urf_get_stats;
#ifdef notdef
		ugcp->usbgc_interrupt = &urf_interrupt;
#else
		ugcp->usbgc_interrupt = NULL;
#endif
		/* packet operation */
		ugcp->usbgc_tx_make_packet = &urf_tx_make_packet;
		ugcp->usbgc_rx_make_packet = &urf_rx_make_packet;

		/* mii operations */
		ugcp->usbgc_mii_probe = &usbgem_mii_probe_default;
		ugcp->usbgc_mii_init = &usbgem_mii_init_default;
		ugcp->usbgc_mii_config = &usbgem_mii_config_default;
		ugcp->usbgc_mii_read = &urf_mii_read;
		ugcp->usbgc_mii_write = &urf_mii_write;

		/* mtu */
		ugcp->usbgc_min_mtu = ETHERMTU;
		ugcp->usbgc_max_mtu = ETHERMTU;
		ugcp->usbgc_default_mtu = ETHERMTU;

		lp = kmem_zalloc(sizeof (struct urf_dev), KM_SLEEP);
		lp->chip = NULL;

		ddi_set_driver_private(dip, NULL);

		dp = usbgem_do_attach(dip, ugcp, lp, sizeof (struct urf_dev));

		kmem_free(ugcp, sizeof (*ugcp));

		if (dp != NULL) {
			urf_ppa++;
			return (DDI_SUCCESS);
		}

err_free_mem:
		kmem_free(lp, sizeof (struct urf_dev));
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
urfdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	ret;

	if (cmd == DDI_DETACH) {
		ret = usbgem_do_detach(dip);
		if (ret != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		urf_ppa--;
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
USBGEM_STREAM_OPS(urf_ops, urfattach, urfdetach);
#else
static	struct module_info urfminfo = {
	0,			/* mi_idnum */
	"urf",			/* mi_idname */
	0,			/* mi_minpsz */
	ETHERMTU,		/* mi_maxpsz */
	ETHERMTU*128,		/* mi_hiwat */
	1,			/* mi_lowat */
};

static	struct qinit urfrinit = {
	(int (*)()) NULL,	/* qi_putp */
	usbgem_rsrv,		/* qi_srvp */
	usbgem_open,		/* qi_qopen */
	usbgem_close,		/* qi_qclose */
	(int (*)()) NULL,	/* qi_qadmin */
	&urfminfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct qinit urfwinit = {
	usbgem_wput,		/* qi_putp */
	usbgem_wsrv,		/* qi_srvp */
	(int (*)()) NULL,	/* qi_qopen */
	(int (*)()) NULL,	/* qi_qclose */
	(int (*)()) NULL,	/* qi_qadmin */
	&urfminfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct streamtab	urf_info = {
	&urfrinit,	/* st_rdinit */
	&urfwinit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

static	struct cb_ops cb_urf_ops = {
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
	&urf_info,	/* cb_stream */
	D_NEW|D_MP	/* cb_flag */
};

static	struct dev_ops urf_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	usbgem_getinfo,	/* devo_getinfo */
	nulldev,	/* devo_identify */
	nulldev,	/* devo_probe */
	urfattach,	/* devo_attach */
	urfdetach,	/* devo_detach */
	nodev,		/* devo_reset */
	&cb_urf_ops,	/* devo_cb_ops */
	NULL,		/* devo_bus_ops */
	usbgem_power,	/* devo_power */
#if DEVO_REV >= 4
	usbgem_quiesce, /* devo_quiesce */
#endif

};
#endif

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	ident,
	&urf_ops,	/* driver ops */
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

	DPRINTF(2, (CE_CONT, "!urf: _init: called"));

	status = usbgem_mod_init(&urf_ops, "urf");
	if (status != DDI_SUCCESS) {
		return (status);
	}
	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS) {
		usbgem_mod_fini(&urf_ops);
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

	DPRINTF(2, (CE_CONT, "!urf: _fini: called"));
	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		usbgem_mod_fini(&urf_ops);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
