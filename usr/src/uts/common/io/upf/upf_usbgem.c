/*
 * upf_usbgem.c : ADMtek an986/adm8511/adm8513/adm8515 USB to
 * Fast Ethernet Driver for Solaris
 */

/*
 * Copyright (c) 2004-2011 Masayuki Murayama.  All rights reserved.
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

/* hardware stuff */
#include "usbgem_mii.h"
#include "adm8511reg.h"

char	ident[] = "pegasus usbnic driver v" VERSION;

/*
 * Useful macros
 */
#define	CHECK_AND_JUMP(val, label)	\
	if ((val) != USB_SUCCESS) { goto label; }

/*
 * Debugging
 */
#ifdef DEBUG_LEVEL
static int upf_debug = DEBUG_LEVEL;
#define	DPRINTF(n, args)	if (upf_debug > (n)) cmn_err args
#else
#define	DPRINTF(n, args)
#endif

/*
 * Our configration for ADMtek Pegasus/PegasusII
 */
/* timeouts */
#define	ONESEC		(drv_usectohz(1*1000000))

/*
 * Local device definitions
 */
struct upf_dev {
	/*
	 * Misc HW information
	 */
	uint8_t		ec[3];
	uint8_t		mac_addr[ETHERADDRL];
	int		chip_type;
#define	CHIP_AN986	1	/* avoid 0 */
#define	CHIP_ADM8511	2	/* including adm8515 */
#define	CHIP_ADM8513	3
	boolean_t	phy_init_done;
	uint8_t		last_link_state;

	uint16_t	vid;	/* vendor id */
	uint16_t	pid;	/* product id */
};

/*
 * private functions
 */

/* mii operations */
static uint16_t upf_mii_read(struct usbgem_dev *, uint_t, int *errp);
static void upf_mii_write(struct usbgem_dev *, uint_t, uint16_t, int *errp);

/* nic operations */
static int upf_attach_chip(struct usbgem_dev *);
static int upf_reset_chip(struct usbgem_dev *);
static int upf_init_chip(struct usbgem_dev *);
static int upf_start_chip(struct usbgem_dev *);
static int upf_stop_chip(struct usbgem_dev *);
static int upf_set_media(struct usbgem_dev *);
static int upf_set_rx_filter(struct usbgem_dev *);
static int upf_get_stats(struct usbgem_dev *);

/* packet operations */
static mblk_t *upf_tx_make_packet(struct usbgem_dev *, mblk_t *);
static mblk_t *upf_rx_make_packet(struct usbgem_dev *, mblk_t *);

/* interrupt handler */
static void upf_interrupt(struct usbgem_dev *, mblk_t *);

/* =============================================================== */
/*
 * I/O functions
 */
/* =============================================================== */
#define	UPF_REQ_GET_REGISTER	0xf0
#define	UPF_REQ_SET_REGISTER	0xf1
#define	OUTB(dp, p, v, errp, label)	\
	if ((*(errp) = usbgem_ctrl_out((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_HOST_TO_DEV	\
		| USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */	UPF_REQ_SET_REGISTER,	\
	/* wValue */	(v),	\
	/* wIndex */	(p),	\
	/* wLength */	1,	\
	/* buf */	NULL,	\
	/* size */	0)) != USB_SUCCESS) goto label;

#define	OUTW(dp, p, v, errp, label)	\
	if ((*(errp) = usbgem_ctrl_out_val((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_HOST_TO_DEV	\
		| USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */	UPF_REQ_SET_REGISTER,	\
	/* wValue */	0,	\
	/* wIndex */	(p),	\
	/* wLength */	2,	\
	/* value */	(v))) != USB_SUCCESS) goto label

#define	OUTS(dp, p, buf, len, errp, label)	\
	if ((*(errp) = usbgem_ctrl_out((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_HOST_TO_DEV	\
		| USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */	UPF_REQ_SET_REGISTER,	\
	/* wValue */	0,	\
	/* wIndex */	(p),	\
	/* wLength */	(len),	\
	/* buf */	(buf),	\
	/* size */	(len))) != USB_SUCCESS) goto label

#define	INB(dp, p, vp, errp, label)	\
	if ((*(errp) = usbgem_ctrl_in_val((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_DEV_TO_HOST	\
		| USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ UPF_REQ_GET_REGISTER,	\
	/* wValue */	0,	\
	/* wIndex */	(p),	\
	/* wLength */	1,	\
	/* valuep */	(vp))) != USB_SUCCESS) goto label

#define	INW(dp, p, vp, errp, label)	\
	if ((*(errp) = usbgem_ctrl_in_val((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_DEV_TO_HOST	\
		| USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ UPF_REQ_GET_REGISTER,	\
	/* wValue */	0,	\
	/* wIndex */	(p),	\
	/* wLength */	2,	\
	/* valuep */	(vp))) != USB_SUCCESS) goto label

#define	INS(dp, p, buf, len, errp, label)	\
	if ((*(errp) = usbgem_ctrl_in((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_DEV_TO_HOST	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ UPF_REQ_GET_REGISTER,	\
	/* wValue */	0,	\
	/* wIndex */	(p),	\
	/* wLength */	(len),	\
	/* buf */	(buf),	\
	/* size */	(len))) != USB_SUCCESS) goto label

/* =============================================================== */
/*
 * Hardware manupilation
 */
/* =============================================================== */
static int
upf_reset_chip(struct usbgem_dev *dp)
{
	int		i;
	uint8_t		val;
	int		err;
	struct upf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));
	bzero(lp->mac_addr, sizeof (lp->mac_addr));

	lp->ec[1] = 0;
	OUTB(dp, EC1, EC1_RM, &err, usberr);

	for (i = 0; i < 1000; i++) {
		INB(dp, EC1, &val, &err, usberr);
		if ((val & EC1_RM) == 0) {
			lp->ec[1] = val;
			return (USB_SUCCESS);
		}
		drv_usecwait(10);
	}

	/* time out */
	cmn_err(CE_WARN, "!%s: failed to reset: timeout", dp->name);
	return (USB_FAILURE);

usberr:
	cmn_err(CE_NOTE, "!%s: %s: usberr detected", dp->name, __func__);
	return (USB_FAILURE);
}

/*
 * Setup an986/adm8511/adm8513/adm8515
 */
static int
upf_init_chip(struct usbgem_dev *dp)
{
	uint64_t	zero64 = 0;
	int	err = USB_SUCCESS;
	struct upf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* ethernet control register 0 */
	lp->ec[0] |= EC0_RXSA | EC0_RXCS;
	OUTB(dp, EC0, lp->ec[0], &err, usberr);

	/* ethernet control reg1: will be set later in set_rx_filter() */

	/* ethernet control register 2: will be set later in set_rx_filter() */
	INB(dp, EC2, &lp->ec[2], &err, usberr);
	lp->ec[2] |= EC2_RXBP | EC2_EP3RC;
#ifdef CONFIG_VLAN
	if (dp->misc_flag & USBGEM_VLAN) {
		lp->ec[2] |= EC2_MEPL;
	}
#endif
	OUTB(dp, EC2, lp->ec[2], &err, usberr);

	/* Multicast address hash: clear */
	OUTS(dp, MA, &zero64, 8, &err, usberr);

	/* Ethernet ID : will be set later in upf_set_rx_filter() */

	/* PAUSE timer */
	OUTB(dp, PAUSETIMER, 0x1f, &err, usberr);

	/* receive packet number based pause control:set in upf_set_media() */

	/* occupied receive FIFO based pause control:set in upf_set_media() */

	/* EP1 control: default */

	/* Rx FIFO control */
	if (lp->chip_type != CHIP_AN986) {
		/* use 24K internal sram, 16pkts in fifo */
		OUTB(dp, RXFC, 0, &err, usberr);
	}

	/* BIST contror: do nothing */
	err = upf_set_media(dp);
	CHECK_AND_JUMP(err, usberr);

	DPRINTF(2, (CE_CONT, "!%s: %s: end (success)", dp->name, __func__));
	return (USB_SUCCESS);

usberr:
	cmn_err(CE_NOTE, "!%s: %s: usberr(%d) detected",
	    dp->name, __func__, err);
	return (err);
}

static int
upf_start_chip(struct usbgem_dev *dp)
{
	int	err = USB_SUCCESS;
	struct upf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* enable RX and TX */
	lp->ec[0] |= EC0_TXE | EC0_RXE;
	OUTB(dp, EC0, lp->ec[0], &err, usberr);
	return (USB_SUCCESS);

usberr:
	cmn_err(CE_WARN, "!%s: %s: usberr(%d) detected",
	    dp->name, __func__, err);
	return (err);
}

static int
upf_stop_chip(struct usbgem_dev *dp)
{
	int	err;
	struct upf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* disable RX and TX */
	lp->ec[0] &= ~(EC0_TXE | EC0_RXE);
	OUTB(dp, EC0, lp->ec[0], &err, usberr);

	return (USB_SUCCESS);

usberr:
	cmn_err(CE_WARN, "!%s: %s: usberr(%d) detected",
	    dp->name, __func__, err);
	return (err);
}

static int
upf_get_stats(struct usbgem_dev *dp)
{
	/* do nothing */
	return (USB_SUCCESS);
}

static uint_t
upf_mcast_hash(struct usbgem_dev *dp, const uint8_t *addr)
{
	/* hash table is 64 = 2^6 bit width */
	return (usbgem_ether_crc_le(addr) & 0x3f);
}

static int
upf_set_rx_filter(struct usbgem_dev *dp)
{
	int		i;
	int		err;
#ifdef DEBUG_LEVEL
	uint8_t		reg0;
	uint8_t		reg1;
	uint8_t		reg2;
#endif
	struct upf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called, rxmode:%b",
	    dp->name, __func__, dp->rxmode, RXMODE_BITS));

	/* reset rx mode */
	lp->ec[0] &= ~EC0_RXMA;
	lp->ec[2] &= ~EC2_PROM;

	if (dp->rxmode & RXMODE_PROMISC) {
		/* promiscious mode implies all multicast and all physical */
		lp->ec[0] |= EC0_RXMA;
		lp->ec[2] |= EC2_PROM;
	} else if ((dp->rxmode & RXMODE_ALLMULTI) || dp->mc_count > 0) {
		/* XXX - multicast hash table didin't work */
		/* accept all multicast packets */
		lp->ec[0] |= EC0_RXMA;
	}

	if (bcmp(dp->cur_addr.ether_addr_octet,
	    lp->mac_addr, ETHERADDRL) != 0) {

		/* need to update mac address */
		bcopy(dp->cur_addr.ether_addr_octet,
		    lp->mac_addr, ETHERADDRL);
		OUTS(dp, EID,
		    lp->mac_addr, ETHERADDRL, &err, usberr);
	}

	/* update rx mode */
	OUTS(dp, EC0, lp->ec, 3, &err, usberr);

#if DEBUG_LEVEL > 0
	INB(dp, EC0, &reg0, &err, usberr);
	INB(dp, EC1, &reg1, &err, usberr);
	INB(dp, EC2, &reg2, &err, usberr);

	cmn_err(CE_CONT, "!%s: %s: returned, ec:%b %b %b",
	    dp->name, __func__,
	    reg0, EC0_BITS, reg1, EC1_BITS, reg2, EC2_BITS);
#endif
	return (USB_SUCCESS);

usberr:
	cmn_err(CE_NOTE, "!%s: %s: usberr detected", dp->name, __func__);
	return (err);
}

static int
upf_set_media(struct usbgem_dev *dp)
{
	int	err;
	struct upf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	lp->ec[1] &= ~(EC1_FD | EC1_100M);

	/* select duplex */
	if (dp->full_duplex) {
		lp->ec[1] |= EC1_FD;
	}

	/* select speed */
	if (dp->speed == USBGEM_SPD_100) {
		lp->ec[1] |= EC1_100M;
	}

	/* rx flow control */
	switch (dp->flow_control) {
	case FLOW_CONTROL_SYMMETRIC:
	case FLOW_CONTROL_RX_PAUSE:
		lp->ec[0] |= EC0_RXFCE;
		break;

	default:
		lp->ec[0] &= ~EC0_RXFCE;
		break;
	}

	/* tx flow control */
	switch (dp->flow_control) {
	case FLOW_CONTROL_SYMMETRIC:
	case FLOW_CONTROL_TX_PAUSE:
		if (lp->chip_type != CHIP_AN986) {
			/* pegasus II has internal 24k fifo */
			OUTB(dp, ORFBFC,
			    (12 << ORFBFC_RXS_SHIFT) |  ORFBFC_FCRXS,
			    &err, usberr);

			/* 16 packts can be stored in rx fifo */
			OUTB(dp, RPNBFC_PN,
			    (8 << RPNBFC_PN_SHIFT) |  RPNBFC_FCP,
			    &err, usberr);
		} else {
			/* an986 has external 32k fifo */
			OUTB(dp, ORFBFC,
			    (16 << ORFBFC_RXS_SHIFT) |  ORFBFC_FCRXS,
			    &err, usberr);

			/* AN986 fails to link up when RPNBFC is enabled */
			OUTB(dp, RPNBFC, 0, &err, usberr);
		}
		break;

	default:
		OUTB(dp, ORFBFC, 0, &err, usberr);
		OUTB(dp, RPNBFC, 0, &err, usberr);
		break;
	}

	/* update ether control registers */
	OUTS(dp, EC0, lp->ec, 2, &err, usberr);
	DPRINTF(0, (CE_CONT, "!%s: %s: returned, ec0:%b, ec1:%b",
	    dp->name, __func__, lp->ec[0], EC0_BITS, lp->ec[1], EC1_BITS));

	return (USB_SUCCESS);

usberr:
	cmn_err(CE_WARN, "%s: %s: failed to write ec1", dp->name, __func__);
	return (err);
}

/*
 * send/receive packet check
 */
static mblk_t *
upf_tx_make_packet(struct usbgem_dev *dp, mblk_t *mp)
{
	size_t		len;
	mblk_t		*new;
	mblk_t		*tp;
	uint8_t		*bp;
	uint8_t		*last_pos;
	int		msglen;

	DPRINTF(3, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	len = msgdsize(mp);
	if (len < ETHERMIN) {
		len = ETHERMIN;
	}

	/* allocate msg block */
	msglen = len + sizeof (uint16_t);

	/* avoid usb controller bug */
	if ((msglen & 0x3f) == 0) {
		/* add a header for additional 0-length usb message */
		msglen += sizeof (uint16_t);
	}

	if ((new = allocb(msglen, 0)) == NULL) {
		return (NULL);
	}

	/* copy contents of the buffer */
	new->b_wptr = new->b_rptr + msglen;
	bp = new->b_rptr;

	/* the nic requires a two byte header of the packet size */
	bp[0] = (uint8_t)len;
	bp[1] = (uint8_t)(len >> 8);
	bp += sizeof (uint16_t);

	/* copy the payload */
	for (tp = mp; tp; tp = tp->b_cont) {
		len = (uintptr_t)tp->b_wptr - (uintptr_t)tp->b_rptr;
		if (len > 0) {
			bcopy(tp->b_rptr, bp, len);
			bp += len;
		}
	}

	/* clear ethernet pads and additional usb header if we have */
	last_pos = new->b_wptr;
	while (bp < last_pos) {
		*bp++ = 0;
	}

	return (new);
}

static void
upf_dump_packet(struct usbgem_dev *dp, uint8_t *bp, int n)
{
	int	i;

	for (i = 0; i < n; i += 8, bp += 8) {
		cmn_err(CE_CONT, "%02x %02x %02x %02x %02x %02x %02x %02x",
		    bp[0], bp[1], bp[2], bp[3], bp[4], bp[5], bp[6], bp[7]);
	}
}

static mblk_t *
upf_rx_make_packet(struct usbgem_dev *dp, mblk_t *mp)
{
	uint8_t		*p;
	uint16_t	rxhd;
	uint_t		len;
	uint8_t		rsr;
	struct upf_dev	*lp = dp->private;

	ASSERT(mp != NULL);

#ifdef DEBUG_LEVEL
	len = msgdsize(mp);
	DPRINTF(2, (CE_CONT, "!%s: time:%d %s: cont:%p",
	    dp->name, ddi_get_lbolt(), __func__, len, mp->b_cont));

	if (upf_debug > 3) {
		upf_dump_packet(dp, mp->b_rptr, max(6, len));
	}
#endif
	/* get the length of Rx packet */
	p = mp->b_wptr - 4;
	rsr = p[3];
	if (lp->chip_type == CHIP_ADM8513) {
		/* As Rx packets from ADM8513 have two byte header, remove it */
		p = mp->b_rptr;
		len = ((p[1] << 8) | p[0]) & 0x0fff;
		mp->b_rptr += 2;
	} else {
		len = (((p[1] << 8) | p[0]) & 0x0fff) - ETHERFCSL - 4;
	}

	DPRINTF(2, (CE_CONT, "!%s: %s: rsr:%b len:%d",
	    dp->name, __func__, rsr, RSR_BITS, len));

	/* check if error happen */
	if (rsr & RSR_ERRORS) {
		DPRINTF(0, (CE_CONT, "!%s: rsr:%b", dp->name, rsr, RSR_BITS));
		if (rsr & (RSR_CRC | RSR_DRIBBLE)) {
			dp->stats.frame++;
		}
		if (rsr & RSR_LONG) {
			dp->stats.frame_too_long++;
		}
		if (rsr & RSR_RUNT) {
			dp->stats.runt++;
		}

		dp->stats.errrcv++;
		return (NULL);
	}
#ifndef CONFIG_VLAN
	/* check packet size */
	if (len > ETHERMAX) {
		/* too long */
		dp->stats.frame_too_long++;
		dp->stats.errrcv++;
		return (NULL);
	} else if (len < ETHERMIN) {
		dp->stats.runt++;
		dp->stats.errrcv++;
		return (NULL);
	}
#endif
	/* remove tailing crc and rx status fields */
	mp->b_wptr = mp->b_rptr + len;
	ASSERT(mp->b_next == NULL);
	return (mp);
}

/*
 * Device depend interrupt handler
 */
static void
upf_interrupt(struct usbgem_dev *dp, mblk_t *mp)
{
	uint8_t	*bp;
	struct upf_dev	*lp = dp->private;

	bp = mp->b_rptr;

	DPRINTF(2, (CE_CONT,
	    "!%s: %s: size:%d, %02x %02x %02x %02x %02x %02x %02x %02x",
	    dp->name, __func__, mp->b_wptr - mp->b_rptr,
	    bp[0], bp[1], bp[2], bp[3], bp[4], bp[5], bp[6], bp[7]));

	if ((lp->last_link_state ^ bp[5]) & 1) {
		DPRINTF(1, (CE_CONT, "!%s:%s link status changed:",
		    dp->name, __func__));
		usbgem_mii_update_link(dp);
	}

	lp->last_link_state = bp[5] & 1;
}

/*
 * MII Interfaces
 */
static uint16_t
upf_mii_read(struct usbgem_dev *dp, uint_t index, int *errp)
{
	uint8_t		phyctrl;
	uint16_t	val;
	int		i;

	DPRINTF(4, (CE_CONT, "!%s: %s: called, ix:%d",
	    dp->name, __func__, index));
	ASSERT(index >= 0 && index < 32);

	*errp = USB_SUCCESS;

	/* set PHYADDR */
	OUTB(dp, PHYA, dp->mii_phy_addr, errp, usberr);

	/* Initiate MII read transaction */
	OUTB(dp, PHYAC, index | PHYAC_RDPHY, errp, usberr);

	for (i = 0; i < 100; i++) {
		INB(dp, PHYAC, &phyctrl, errp, usberr);
		if (phyctrl & PHYAC_DO) {
			/* done */
			INW(dp, PHYD, &val, errp, usberr);
			DPRINTF(4, (CE_CONT, "!%s: %s: return %04x",
			    dp->name, __func__, val));
			return (val);
		}
		drv_usecwait(10);
	}
	/* timeout */
	cmn_err(CE_WARN, "!%s: %s: timeout detected", dp->name, __func__);
	*errp = USB_FAILURE;
	return (0);

usberr:
	cmn_err(CE_CONT,
	    "!%s: %s: usberr(%d) detected", dp->name, __func__, *errp);
	return (0);
}

static void
upf_mii_write(struct usbgem_dev *dp, uint_t index, uint16_t val, int *errp)
{
	int		i;
	uint8_t		phyctrl;

	DPRINTF(4, (CE_CONT, "!%s: %s called index:%d val:0x%04x",
	    dp->name, __func__, index, val));
	ASSERT(index >= 0 && index < 32);

	*errp = USB_SUCCESS;

	OUTW(dp, PHYD, val, errp, usberr);
	OUTB(dp, PHYA, dp->mii_phy_addr, errp, usberr);
	OUTB(dp, PHYAC, index | PHYAC_WRPHY, errp, usberr);

	for (i = 0; i < 100; i++) {
		INB(dp, PHYAC, &phyctrl, errp, usberr);
		if (phyctrl & PHYAC_DO) {
			/* done */
			return;
		}
		drv_usecwait(10);
	}

	/* time out */
	cmn_err(CE_WARN, "!%s: %s: timeout detected", dp->name, __func__);
	*errp = USB_FAILURE;
	return;

usberr:
	cmn_err(CE_CONT,
	    "!%s: %s: usberr(%d) detected", dp->name, __func__, *errp);
}


static int
upf_enable_phy(struct usbgem_dev *dp)
{
	uint8_t	val;
	int	err;
	struct upf_dev	*lp = dp->private;

	/*
	 * first, try to enable internal phy
	 */
	INB(dp, IPHYC, &val, &err, usberr);
	val = (val | IPHYC_EPHY) & ~IPHYC_PHYR;
	OUTB(dp, IPHYC, val, &err, usberr);

	INB(dp, IPHYC, &val, &err, usberr);
	DPRINTF(0, (CE_CONT, "!%s: %s: IPHYC: %b",
	    dp->name, __func__, val, IPHYC_BITS));
	if (val) {
		/* reset internal phy */
		OUTB(dp, IPHYC, val | IPHYC_PHYR, &err, usberr);
		OUTB(dp, IPHYC, val, &err, usberr);
		delay(drv_usectohz(10000));

		/* identify the chip generation */
		OUTB(dp, 0x83, 0xa5, &err, usberr);
		INB(dp, 0x83, &val, &err, usberr);
		if (val == 0xa5) {
			lp->chip_type = CHIP_ADM8513;
		} else {
			/* adm8511 or adm8515 */
			lp->chip_type = CHIP_ADM8511;
		}
		dp->ugc.usbgc_mii_hw_link_detection = B_TRUE;
	} else {
		/*
		 * It should be AN986 which doesn't have an internal PHY.
		 * We need to setup gpio ports in AN986, which are
		 * connected to external PHY control pins.
		 */
		lp->chip_type = CHIP_AN986;

		/* reset external phy */
		/* output port#0 L, port#1 L */
		OUTB(dp, GPIO10, GPIO10_0O | GPIO10_0OE, &err, usberr);

		/* output port#0 H, port#1 L */
		OUTB(dp, GPIO10,
		    GPIO10_0O | GPIO10_0OE | GPIO10_1OE, &err, usberr);

		/* hw link detection doesn't work correctly */
		dp->ugc.usbgc_mii_hw_link_detection = B_FALSE;
	}

	return (USB_SUCCESS);

usberr:
	cmn_err(CE_NOTE, "!%s: %s: usberr detected", dp->name, __func__);
	return (USB_FAILURE);
}

static int
upf_mii_probe(struct usbgem_dev *dp)
{
	int	err;
	uint16_t	val;
	struct upf_dev	*lp = dp->private;

	if (!lp->phy_init_done) {
		upf_enable_phy(dp);
		lp->phy_init_done = B_TRUE;
	}

	return (usbgem_mii_probe_default(dp));
}

static int
upf_mii_init(struct usbgem_dev *dp)
{
	uint16_t	val;
	int		err = USB_SUCCESS;
	struct upf_dev	*lp = dp->private;

	if (!lp->phy_init_done) {
		upf_enable_phy(dp);
	}
	lp->phy_init_done = B_FALSE;

	if (lp->chip_type == CHIP_AN986 &&
	    (lp->vid == 0x0db7 /* elecom */ ||
	    lp->vid == 0x066b /* linksys */ ||
	    lp->vid == 0x077b /* linksys */ ||
	    lp->vid == 0x2001 /* dlink */)) {
		/* special treatment for Linksys products */
		val = upf_mii_read(dp, 0x1b, &err) | 0x4;
		upf_mii_write(dp, 0x1b, val, &err);
	}
	return (err);
}

/* ======================================================== */
/*
 * OS depend (device driver DKI) routine
 */
/* ======================================================== */
static uint16_t
upf_read_eeprom(struct usbgem_dev *dp, int index, int *errp)
{
	int		i;
	uint8_t		eectrl;
	uint16_t	data;

	*errp = USB_SUCCESS;

	OUTB(dp, EECTRL, 0, errp, usberr);

	OUTB(dp, EEOFFSET, index, errp, usberr);
	OUTB(dp, EECTRL, EECTRL_RD, errp, usberr);

	for (i = 0; i < 100; i++) {
		INB(dp, EECTRL, &eectrl, errp, usberr);
		if (eectrl & EECTRL_DONE) {
			INW(dp, EEDATA, &data, errp, usberr);
			return (data);
		}
		drv_usecwait(10);
	}

	/* time out */
	*errp = USB_FAILURE;
	return (0);

usberr:
	cmn_err(CE_CONT,
	    "!%s: %s: usberr(%d) detected", dp->name, __func__, *errp);
	return (0);
}

static void
upf_eeprom_dump(struct usbgem_dev *dp, int size)
{
	int	i;
	int	err;

	cmn_err(CE_CONT, "!%s: %s dump:", dp->name, __func__);

	for (i = 0; i < size; i += 4) {
		cmn_err(CE_CONT, "!0x%02x: 0x%04x 0x%04x 0x%04x 0x%04x",
		    i*2,
		    upf_read_eeprom(dp, i + 0, &err),
		    upf_read_eeprom(dp, i + 1, &err),
		    upf_read_eeprom(dp, i + 2, &err),
		    upf_read_eeprom(dp, i + 3, &err));
	}
}

static int
upf_attach_chip(struct usbgem_dev *dp)
{
	int		i;
	int		err;
	uint16_t	val;
	uint8_t		*mac;
	struct upf_dev	*lp = dp->private;

	/*
	 * Read mac address from EEPROM
	 */
	mac = dp->dev_addr.ether_addr_octet;
	for (i = 0; i < 3; i++) {
		val = upf_read_eeprom(dp, i, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
		mac[i*2+0] = (uint8_t)val;
		mac[i*2+1] = (uint8_t)(val >> 8);
	}

	DPRINTF(0, (CE_CONT,
	    "%s: %s: mac: %02x:%02x:%02x:%02x:%02x:%02x",
	    dp->name, __func__,
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]));

	dp->misc_flag = 0;
#ifdef CONFIG_VLAN
	dp->misc_flag |= USBGEM_VLAN;
#endif
#if DEBUG_LEVEL > 3
	upf_eeprom_dump(dp, 0x80);
#endif
	return (USB_SUCCESS);

usberr:
	cmn_err(CE_WARN, "!%s: %s: usb error detected", dp->name, __func__);
	return (USB_FAILURE);
}

static int
upfattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			i;
	ddi_iblock_cookie_t	c;
	int			ret;
	int			unit;
	uint32_t		tcr;
	int			len;
	const char		*drv_name;
	struct usbgem_dev	*dp;
	void			*base;
	struct usbgem_conf	*ugcp;
	struct upf_dev		*lp;

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
		(void) sprintf(ugcp->usbgc_name, "%s%d", drv_name, unit);
		ugcp->usbgc_ppa = unit;

		ugcp->usbgc_ifnum = 0;
		ugcp->usbgc_alt = 0;

		ugcp->usbgc_tx_list_max = 16;

		ugcp->usbgc_rx_header_len = 4;
		ugcp->usbgc_rx_list_max = 64;

		/* time out parameters */
		ugcp->usbgc_tx_timeout = USBGEM_TX_TIMEOUT;
		ugcp->usbgc_tx_timeout_interval = USBGEM_TX_TIMEOUT_INTERVAL;

		/* flow control */
		ugcp->usbgc_flow_control = FLOW_CONTROL_NONE;
		ugcp->usbgc_flow_control = FLOW_CONTROL_RX_PAUSE;

		/* MII timeout parameters */
		ugcp->usbgc_mii_link_watch_interval = ONESEC;
		ugcp->usbgc_mii_an_watch_interval = ONESEC/5;
		ugcp->usbgc_mii_reset_timeout = MII_RESET_TIMEOUT; /* 1 sec */
		ugcp->usbgc_mii_an_timeout = MII_AN_TIMEOUT;	/* 5 sec */
		ugcp->usbgc_mii_an_wait = MII_AN_TIMEOUT/2;
		ugcp->usbgc_mii_linkdown_timeout = MII_LINKDOWN_TIMEOUT;
		ugcp->usbgc_mii_an_delay = ONESEC/10;

		ugcp->usbgc_mii_linkdown_action = MII_ACTION_RESET;
		ugcp->usbgc_mii_linkdown_timeout_action = MII_ACTION_RESET;
		ugcp->usbgc_mii_dont_reset = B_FALSE;

		/* I/O methods */

		/* mac operation */
		ugcp->usbgc_attach_chip = &upf_attach_chip;
		ugcp->usbgc_reset_chip = &upf_reset_chip;
		ugcp->usbgc_init_chip = &upf_init_chip;
		ugcp->usbgc_start_chip = &upf_start_chip;
		ugcp->usbgc_stop_chip = &upf_stop_chip;
		ugcp->usbgc_multicast_hash = &upf_mcast_hash;

		ugcp->usbgc_set_rx_filter = &upf_set_rx_filter;
		ugcp->usbgc_set_media = &upf_set_media;
		ugcp->usbgc_get_stats = &upf_get_stats;
		ugcp->usbgc_interrupt = &upf_interrupt;

		/* packet operation */
		ugcp->usbgc_tx_make_packet = &upf_tx_make_packet;
		ugcp->usbgc_rx_make_packet = &upf_rx_make_packet;

		/* mii operations */
		ugcp->usbgc_mii_probe = &upf_mii_probe;
		ugcp->usbgc_mii_init = &upf_mii_init;
		ugcp->usbgc_mii_config = &usbgem_mii_config_default;
		ugcp->usbgc_mii_read = &upf_mii_read;
		ugcp->usbgc_mii_write = &upf_mii_write;

		/* mtu */
		ugcp->usbgc_min_mtu = ETHERMTU;
		ugcp->usbgc_max_mtu = ETHERMTU;
		ugcp->usbgc_default_mtu = ETHERMTU;

		lp = kmem_zalloc(sizeof (struct upf_dev), KM_SLEEP);

		lp->vid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "usb-vendor-id", -1);
		lp->pid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "usb-product-id", -1);

		dp = usbgem_do_attach(dip, ugcp, lp, sizeof (struct upf_dev));

		kmem_free(ugcp, sizeof (*ugcp));

		if (dp != NULL) {
			return (DDI_SUCCESS);
		}

err_free_mem:
		kmem_free(lp, sizeof (struct upf_dev));
err_close_pipe:
err:
		return (DDI_FAILURE);
	}
	if (cmd == DDI_RESUME) {
		dp = USBGEM_GET_DEV(dip);
		lp = dp->private;
		lp->phy_init_done = B_FALSE;

		return (usbgem_resume(dip));
	}
	return (DDI_FAILURE);
}

static int
upfdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
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
USBGEM_STREAM_OPS(upf_ops, upfattach, upfdetach);
#else
static	struct module_info upfminfo = {
	0,			/* mi_idnum */
	"upf",			/* mi_idname */
	0,			/* mi_minpsz */
	ETHERMTU,		/* mi_maxpsz */
	32*1024,		/* mi_hiwat */
	1,			/* mi_lowat */
};

static	struct qinit upfrinit = {
	(int (*)()) NULL,	/* qi_putp */
	usbgem_rsrv,		/* qi_srvp */
	usbgem_open,		/* qi_qopen */
	usbgem_close,		/* qi_qclose */
	(int (*)()) NULL,	/* qi_qadmin */
	&upfminfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct qinit upfwinit = {
	usbgem_wput,		/* qi_putp */
	usbgem_wsrv,		/* qi_srvp */
	(int (*)()) NULL,	/* qi_qopen */
	(int (*)()) NULL,	/* qi_qclose */
	(int (*)()) NULL,	/* qi_qadmin */
	&upfminfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct streamtab	upf_info = {
	&upfrinit,	/* st_rdinit */
	&upfwinit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

static	struct cb_ops cb_upf_ops = {
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
	&upf_info,	/* cb_stream */
	D_MP		/* cb_flag */
};

static	struct dev_ops upf_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	usbgem_getinfo,	/* devo_getinfo */
	nulldev,	/* devo_identify */
	nulldev,	/* devo_probe */
	upfattach,	/* devo_attach */
	upfdetach,	/* devo_detach */
	nodev,		/* devo_reset */
	&cb_upf_ops,	/* devo_cb_ops */
	NULL,		/* devo_bus_ops */
	usbgem_power,	/* devo_power */
#if DEVO_REV >= 4
	usbgem_quiesce,	/* devo_quiesce */
#endif

};
#endif
static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	ident,
	&upf_ops,	/* driver ops */
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

	DPRINTF(2, (CE_CONT, "!upf: _init: called"));

	status = usbgem_mod_init(&upf_ops, "upf");
	if (status != DDI_SUCCESS) {
		return (status);
	}
	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS) {
		usbgem_mod_fini(&upf_ops);
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

	DPRINTF(2, (CE_CONT, "!upf: _fini: called"));
	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		usbgem_mod_fini(&upf_ops);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
