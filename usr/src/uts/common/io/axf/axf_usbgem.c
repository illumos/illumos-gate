/*
 * axf_usbgem.c : ASIX AX88172/772 USB to Fast Ethernet Driver for Solaris
 *
 * Copyright (c) 2004-2012 Masayuki Murayama.  All rights reserved.
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

#pragma ident "@(#)axf_usbgem.c	1.3 12/02/09"

/*
 *  Changelog:
 */

/*
 * TODO
 * handle RXMODE_ENABLE in set_rx_filter()
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

/* hardware stuff */
#include "usbgem_mii.h"
#include "ax88172reg.h"

char	ident[] = "ax88x72 usbnic driver v" VERSION;

/*
 * Useful macros
 */
#define	CHECK_AND_JUMP(err, label)	if (err != USB_SUCCESS) goto label
#define	LE16P(p)	((((uint8_t *)(p))[1] << 8) | ((uint8_t *)(p))[0])

#define	AX88172(dp)	\
	(((struct axf_dev *)(dp)->private)->chip->type == CHIP_TYPE_AX88172)

#define	AX88772(dp)	\
	(((struct axf_dev *)(dp)->private)->chip->type == CHIP_TYPE_AX88772)

/*
 * Debugging
 */
#ifdef DEBUG_LEVEL
static int axf_debug = DEBUG_LEVEL;
#define	DPRINTF(n, args)	if (axf_debug > (n)) cmn_err args
#else
#define	DPRINTF(n, args)
#endif

/*
 * Our configration for ax88172
 */
/* timeouts */
#define	ONESEC		(drv_usectohz(1*1000000))

/*
 * RX/TX buffer size
 */

/*
 * Local device definitions
 */
struct chip_info {
	uint16_t	vid;	/* usb vendor id */
	uint16_t	pid;	/* usb product id */
	int		type;
	uint8_t		gpio_reset[2];
	uint8_t		gpio_speed[2];
	uint8_t		gpio_duplex[2];
	char		*name;
#define	CHIP_TYPE_AX88172	0
#define	CHIP_TYPE_AX88772	1
#define	CHIP_TYPE_AX88178	2
};

#define	GPIO_DEFAULT	{0x00, 0x15}, {0, 0}, {0, 0}
struct chip_info chiptbl_88x7x[] = {
/* AX88172 */
{
	/* Planex UE2-100TX, Hawking UF200, TrendNet TU2-ET100 */
	0x07b8, 0x420a, CHIP_TYPE_AX88172,

	/*
	 * the default setting covers below:
	 * gpio bit2 has to be 0 and gpio bit0 has to be 1
	 */
	{0, 0},
	{GPIO_EN1, GPIO_DATA1 | GPIO_EN1},
	{0, 0},
	"Planex UE2-100TX",	/* tested */
},
{
	0x2001, 0x1a00, CHIP_TYPE_AX88172,
	{0x9f, 0x9e}, {0, 0}, {0, 0},
	"D-Link dube100",	/* XXX */
},
{
	0x077b, 0x2226, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"Linksys USB200M",
},
{
	0x0846, 0x1040, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"Netgear FA120",
},
{
	0x0b95, 0x1720, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"Intellinet, ST Lab USB Ethernet",
},
{
	0x08dd, 0x90ff, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"Billionton Systems, USB2AR",
},
{
	0x0557, 0x2009, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"ATEN UC210T",
},
{
	0x0411, 0x003d, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"Buffalo LUA-U2-KTX",
},
{
	0x6189, 0x182d, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"Sitecom LN-029 USB 2.0 10/100 Ethernet adapter",
},
{
	0x07aa, 0x0017, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"corega FEther USB2-TX",
},
{
	0x1189, 0x0893, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"Surecom EP-1427X-2",
},
{
	0x1631, 0x6200, CHIP_TYPE_AX88172,
	GPIO_DEFAULT,
	"goodway corp usb gwusb2e",
},
/* AX88772 and AX88178 */
{
	0x13b1, 0x0018, CHIP_TYPE_AX88772,
	{0, 0}, {0, 0}, {0, 0},
	"Linksys USB200M rev.2",
},
{
	0x1557, 0x7720, CHIP_TYPE_AX88772,
	{0, 0}, {0, 0}, {0, 0},
	"0Q0 cable ethernet",
},
{
	0x07d1, 0x3c05, CHIP_TYPE_AX88772,
	{0, 0}, {0, 0}, {0, 0},
	"DLink DUB E100 ver B1",
},
{
	0x2001, 0x3c05, CHIP_TYPE_AX88772,
	{0, 0}, {0, 0}, {0, 0},
	"DLink DUB E100 ver B1(2)",
},
{
	0x05ac, 0x1402, CHIP_TYPE_AX88772,
	{0, 0}, {0, 0}, {0, 0},
	"Apple Ethernet USB Adapter",
},
{
	0x1737, 0x0039, CHIP_TYPE_AX88178,
	{0, 0}, {0, 0}, {0, 0},
	"Linksys USB1000",
},
{
	0x0411, 0x006e, CHIP_TYPE_AX88178,
	{0, 0}, {0, 0}, {0, 0},
	"Buffalo LUA-U2-KGT/LUA-U2-GT",
},
{
	0x04bb, 0x0930, CHIP_TYPE_AX88178,
	{0, 0}, {0, 0}, {0, 0},
	"I/O DATA ETG-US2",
},
{
	0x050d, 0x5055, CHIP_TYPE_AX88178,
	{0, 0}, {0, 0}, {0, 0},
	"Belkin F5D5055",
},
{
	/* generic ax88772 must be the last entry */
	/* planex UE-200TX-G */
	0x0b95, 0x7720, CHIP_TYPE_AX88772,
	{0, 0}, {0, 0}, {0, 0},
	"ASIX AX88772/AX88178",	/* tested */
},
};

#define	CHIPTABLESIZE	(sizeof (chiptbl_88x7x) / sizeof (struct chip_info))

struct axf_dev {
	/*
	 * Misc HW information
	 */
	struct chip_info	*chip;
	uint8_t			ipg[3];
	uint8_t			gpio;
	uint16_t		rcr;
	uint16_t		msr;
	uint8_t			last_link_state;
	boolean_t		phy_has_reset;
};

/*
 * private functions
 */

/* mii operations */
static uint16_t axf_mii_read(struct usbgem_dev *, uint_t, int *errp);
static void axf_mii_write(struct usbgem_dev *, uint_t, uint16_t, int *errp);

/* nic operations */
static int axf_reset_chip(struct usbgem_dev *);
static int axf_init_chip(struct usbgem_dev *);
static int axf_start_chip(struct usbgem_dev *);
static int axf_stop_chip(struct usbgem_dev *);
static int axf_set_media(struct usbgem_dev *);
static int axf_set_rx_filter(struct usbgem_dev *);
static int axf_get_stats(struct usbgem_dev *);
static void  axf_interrupt(struct usbgem_dev *, mblk_t *);

/* packet operations */
static mblk_t *axf_tx_make_packet(struct usbgem_dev *, mblk_t *);
static mblk_t *axf_rx_make_packet(struct usbgem_dev *, mblk_t *);

/* =============================================================== */
/*
 * I/O functions
 */
/* =============================================================== */
/* BEGIN CSTYLED */
#define	OUT(dp, req, val, ix, len, buf, errp, label)	\
	if ((*(errp) = usbgem_ctrl_out((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_HOST_TO_DEV	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ (req),	\
	/* wValue */   (val),	\
	/* wIndex */   (ix),	\
	/* wLength */  (len),	\
	/* value */    (buf),	\
	/* size */     (len))) != USB_SUCCESS) goto label

#define	IN(dp, req, val, ix, len, buf, errp, label)	\
	if ((*(errp) = usbgem_ctrl_in((dp), 	\
	/* bmRequestType */ USB_DEV_REQ_DEV_TO_HOST	\
		    | USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_RCPT_DEV,	\
	/* bRequest */ (req),	\
	/* wValue */   (val),	\
	/* wIndex */   (ix),	\
	/* wLength */  (len),	\
	/* valuep */   (buf),	\
	/* size */     (len))) != USB_SUCCESS) goto label
/* END CSTYLED */

/* =============================================================== */
/*
 * Hardware manupilation
 */
/* =============================================================== */
static int
axf_reset_phy(struct usbgem_dev *dp)
{
	uint8_t	phys[2];
	uint8_t	val8;
	int	err;
	struct axf_dev	*lp = dp->private;

	DPRINTF(2, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	if (AX88172(dp)) {
		delay(drv_usectohz(5000));
		IN(dp, VCMD_READ_GPIO, 0, 0, 1, &val8, &err, usberr);

		DPRINTF(0, (CE_CONT, "!%s: %s: gpio 0x%b",
		    dp->name, __func__, val8, GPIO_BITS));

		/* reset MII PHY */
		val8 = lp->chip->gpio_reset[1]
		    | lp->chip->gpio_speed[dp->speed]
		    | lp->chip->gpio_duplex[dp->full_duplex];

		OUT(dp, VCMD_WRITE_GPIO,
		    val8, 0, 0, NULL, &err, usberr);
		delay(drv_usectohz(5000));

		val8 = lp->chip->gpio_reset[0]
		    | lp->chip->gpio_speed[dp->speed]
		    | lp->chip->gpio_duplex[dp->full_duplex];

		OUT(dp, VCMD_WRITE_GPIO,
		    val8, 0, 0, NULL, &err, usberr);
		delay(drv_usectohz(5000));
	} else {
		lp->gpio = GPIO_RSE | GPIO_DATA2 | GPIO_EN2;
		OUT(dp, VCMD_WRITE_GPIO, lp->gpio, 0,
		    0, NULL, &err, usberr);
		drv_usecwait(1000);

		OUT(dp, VCMD_WRITE_PHY_SELECT_88772,
		    dp->mii_phy_addr == 16 ? 1 : 0, 0, 0, NULL, &err, usberr);

		OUT(dp, VCMD_SOFTWARE_RESET_88772,
		    SWRST_IPPD | SWRST_PRL, 0, 0, NULL, &err, usberr);
		delay(drv_usectohz(150*1000));
		OUT(dp, VCMD_SOFTWARE_RESET_88772,
		    0, 0, 0, NULL, &err, usberr);

		OUT(dp, VCMD_SOFTWARE_RESET_88772,
		    dp->mii_phy_addr == 16 ? SWRST_IPRL : SWRST_PRTE,
		    0, 0, NULL, &err, usberr);
		delay(drv_usectohz(150*1000));
	}


	return (USB_SUCCESS);

usberr:
	return (USB_FAILURE);
}

static int
axf_reset_chip(struct usbgem_dev *dp)
{
	int	err = USB_SUCCESS;

	if (AX88172(dp)) {
		/* there are no ways to reset nic */
		return (USB_SUCCESS);
	}
#ifdef NEVER
	OUT(dp, VCMD_SOFTWARE_RESET_88772,
	    SWRST_RR | SWRST_RT, 0, 0, NULL, &err, usberr);
	OUT(dp, VCMD_SOFTWARE_RESET_88772,
	    0, 0, 0, NULL, &err, usberr);
usberr:
#endif
	return (err);
}

/*
 * Setup ax88172
 */
static int
axf_init_chip(struct usbgem_dev *dp)
{
	int		i;
	uint32_t	val;
	int		err = USB_SUCCESS;
	uint16_t	reg;
	uint8_t		buf[2];
	uint16_t	tmp16;
	struct axf_dev	*lp = dp->private;

	DPRINTF(2, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* rx conrol register: read default value */
	if (!AX88172(dp)) {
		/* clear rx control */
		OUT(dp, VCMD_WRITE_RXCTRL, 0, 0, 0, NULL, &err, usberr);
	}

	IN(dp, VCMD_READ_RXCTRL, 0, 0, 2, buf, &err, usberr);
	lp->rcr = LE16P(buf);
	DPRINTF(0, (CE_CONT, "!%s: %s: rcr(default):%b",
	    dp->name, __func__, lp->rcr, RCR_BITS));

	lp->rcr &= ~RCR_SO;

	/* Media status register */
	if (AX88172(dp)) {
#ifdef notdef
		lp->msr = MSR_TXABT;
#else
		lp->msr = 0;
#endif
	} else {
		lp->msr = MSR_RE | MSR_TXABT;
	}
	DPRINTF(0, (CE_CONT, "!%s: %s: msr:%b",
	    dp->name, __func__, lp->msr, MSR_BITS));
	err = axf_set_media(dp);
	CHECK_AND_JUMP(err, usberr);

	/* write IPG0-2 registers */
	if (AX88172(dp)) {
		OUT(dp, VCMD_WRITE_IPG, lp->ipg[0], 0, 0, NULL, &err, usberr);
		OUT(dp, VCMD_WRITE_IPG1, lp->ipg[1], 0, 0, NULL, &err, usberr);
		OUT(dp, VCMD_WRITE_IPG2, lp->ipg[2], 0, 0, NULL, &err, usberr);
	} else {
		/* EMPTY */
	}
#ifdef ENABLE_RX_IN_INIT_CHIP
	/* enable Rx */
	lp->rcr |= RCR_SO;
	OUT(dp, VCMD_WRITE_RXCTRL, lp->rcr, 0, 0, NULL, &err, usberr);
#endif
usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end (%s)",
	    dp->name, __func__,
	    err, err == USB_SUCCESS ? "success" : "error"));
	return (err);
}

static int
axf_start_chip(struct usbgem_dev *dp)
{
	int	err = USB_SUCCESS;
	struct axf_dev	*lp = dp->private;
#ifndef ENABLE_RX_IN_INIT_CHIP
	/* enable Rx */
	lp->rcr |= RCR_SO;
	OUT(dp, VCMD_WRITE_RXCTRL, lp->rcr, 0, 0, NULL, &err, usberr);

usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end (%s)",
	    dp->name, __func__,
	    err, err == USB_SUCCESS ? "success" : "error"));
#endif
	return (err);
}

static int
axf_stop_chip(struct usbgem_dev *dp)
{
	int	err = USB_SUCCESS;
	struct axf_dev	*lp = dp->private;

	/* Disable Rx */
	lp->rcr &= ~RCR_SO;
	OUT(dp, VCMD_WRITE_RXCTRL, lp->rcr, 0, 0, NULL, &err, usberr);

	/*
	 * Restore factory mac address
	 * if we have changed current mac address
	 */
	if (!AX88172(dp) &&
	    bcmp(dp->dev_addr.ether_addr_octet,
	    dp->cur_addr.ether_addr_octet,
	    ETHERADDRL) != 0) {
		OUT(dp, VCMD_WRITE_NODE_ID_88772, 0, 0,
		    ETHERADDRL, dp->cur_addr.ether_addr_octet, &err, usberr);
	}
usberr:
	return (axf_reset_chip(dp));
}

static int
axf_get_stats(struct usbgem_dev *dp)
{
	/* empty */
	return (USB_SUCCESS);
}

static uint_t
axf_mcast_hash(struct usbgem_dev *dp, const uint8_t *addr)
{
	return (usbgem_ether_crc_be(addr) >> (32 - 6));
}

static int
axf_set_rx_filter(struct usbgem_dev *dp)
{
	int		i;
	uint8_t		mode;
	uint8_t		mhash[8];
	uint8_t		buf[2];
	uint_t		h;
	int		err = USB_SUCCESS;
	struct axf_dev	*lp = dp->private;

	DPRINTF(2, (CE_CONT, "!%s: %s: called, rxmode:%x",
	    dp->name, __func__, dp->rxmode));

	if (lp->rcr & RCR_SO) {
		/* set promiscuous mode  before changing it. */
		OUT(dp, VCMD_WRITE_RXCTRL,
		    lp->rcr | RCR_PRO, 0, 0, NULL, &err, usberr);
	}

	lp->rcr &= ~(RCR_AP_88772 | RCR_AM | RCR_SEP | RCR_AMALL | RCR_PRO);
	mode = RCR_AB;	/* accept broadcast packets */

	bzero(mhash, sizeof (mhash));

	if (dp->rxmode & RXMODE_PROMISC) {
		/* promiscious mode implies all multicast and all physical */
		mode |= RCR_PRO;
	} else if ((dp->rxmode & RXMODE_ALLMULTI) || dp->mc_count > 32) {
		/* accept all multicast packets */
		mode |= RCR_AMALL;
	} else if (dp->mc_count > 0) {
		/*
		 * make hash table to select interresting
		 * multicast address only.
		 */
		mode |= RCR_AM;
		for (i = 0; i < dp->mc_count; i++) {
			h = dp->mc_list[i].hash;
			mhash[h / 8] |= 1 << (h % 8);
		}
	}
	if (AX88172(dp)) {
		if (bcmp(dp->dev_addr.ether_addr_octet,
		    dp->cur_addr.ether_addr_octet, ETHERADDRL) != 0) {
			/*
			 * we use promiscious mode instead of changing the
			 * mac address in ax88172
			 */
			mode |= RCR_PRO;
		}
	} else {
		OUT(dp, VCMD_WRITE_NODE_ID_88772, 0, 0,
		    ETHERADDRL, dp->cur_addr.ether_addr_octet, &err, usberr);
	}
	lp->rcr |= mode;

	/* set multicast hash table */
	if (mode & RCR_AM) {
		/* need to set up multicast hash table */
		OUT(dp, VCMD_WRITE_MCAST_FILTER, 0, 0,
		    sizeof (mhash), mhash, &err, usberr);
	}

	/* update rcr */
	OUT(dp, VCMD_WRITE_RXCTRL, lp->rcr, 0,
	    0, NULL, &err, usberr);

#if DEBUG_LEVEL > 1
	/* verify rxctrl reg */
	IN(dp, VCMD_READ_RXCTRL, 0, 0, 2, buf, &err, usberr);
	cmn_err(CE_CONT, "!%s: %s: rcr:%b returned",
	    dp->name, __func__, LE16P(buf), RCR_BITS);
#endif
usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end (%s)",
	    dp->name, __func__,
	    err, err == USB_SUCCESS ? "success" : "error"));
	return (err);
}

static int
axf_set_media(struct usbgem_dev *dp)
{
	uint8_t	val8;
	uint8_t	gpio;
	uint8_t	gpio_old;
	int	err = USB_SUCCESS;
	uint16_t	msr;
	struct axf_dev	*lp = dp->private;

	IN(dp, VCMD_READ_GPIO, 0, 0, 1, &gpio, &err, usberr);

	DPRINTF(0, (CE_CONT, "!%s: %s: called, gpio:%b",
	    dp->name, __func__, gpio, GPIO_BITS));

	msr = lp->msr;
	gpio_old = gpio;
	gpio = lp->chip->gpio_reset[0];

	/* setup speed */
	if (AX88172(dp)) {
		/* EMPTY */
	} else {
		msr &= ~(MSR_PS | MSR_GM | MSR_ENCK);

		switch (dp->speed) {
		case USBGEM_SPD_1000:
			msr |= MSR_GM | MSR_ENCK;
			break;

		case USBGEM_SPD_100:
			msr |= MSR_PS;
			break;

		case USBGEM_SPD_10:
			break;
		}
	}
	gpio |= lp->chip->gpio_speed[dp->speed == USBGEM_SPD_100 ? 1 : 0];

	/* select duplex */
	msr &= ~MSR_FDPX;
	if (dp->full_duplex) {
		msr |= MSR_FDPX;

		/* select flow control */
		if (AX88172(dp)) {
			msr &= ~MSR_FCEN;
			switch (dp->flow_control) {
			case FLOW_CONTROL_TX_PAUSE:
			case FLOW_CONTROL_SYMMETRIC:
			case FLOW_CONTROL_RX_PAUSE:
				msr |= MSR_FCEN;
				break;
			}
		} else {
			msr &= ~(MSR_RFC | MSR_TFC);
			switch (dp->flow_control) {
			case FLOW_CONTROL_TX_PAUSE:
				msr |= MSR_TFC;
				break;

			case FLOW_CONTROL_SYMMETRIC:
				msr |= MSR_TFC | MSR_RFC;
				break;

			case FLOW_CONTROL_RX_PAUSE:
				msr |= MSR_RFC;
				break;
			}
		}
	}
	gpio |= lp->chip->gpio_duplex[dp->full_duplex ? 1 : 0];

	/* update medium status register */
	lp->msr = msr;
	OUT(dp, VCMD_WRITE_MEDIUM_STATUS, lp->msr, 0,
	    0, NULL, &err, usberr);

	if (gpio != gpio_old) {
		/* LED control required for some products */
		OUT(dp, VCMD_WRITE_GPIO,
		    gpio, 0, 0, NULL, &err, usberr);
	}

usberr:
	DPRINTF(2, (CE_CONT, "!%s: %s: end (%s)",
	    dp->name, __func__,
	    err, err == USB_SUCCESS ? "success" : "error"));
	return (err);
}

#define	FILL_PKT_HEADER(bp, len)	{	\
	(bp)[0] = (uint8_t)(len);	\
	(bp)[1] = (uint8_t)((len) >> 8);	\
	(bp)[2] = (uint8_t)(~(len));	\
	(bp)[3] = (uint8_t)((~(len)) >> 8);	\
}

#define	PKT_HEADER_SIZE	4

/*
 * send/receive packet check
 */
static mblk_t *
axf_tx_make_packet(struct usbgem_dev *dp, mblk_t *mp)
{
	int		n;
	size_t		len;
	size_t		pkt_size;
	mblk_t		*new;
	mblk_t		*tp;
	uint8_t		*bp;
	uint8_t		*last_pos;
	uint_t		align_mask;
	size_t		header_size;
	int		pad_size;

	len = msgdsize(mp);

	if (AX88172(dp)) {
#ifdef notdef
		align_mask = 63;
#else
		align_mask = 511;
#endif
		header_size = 0;

		if (len >= ETHERMIN && mp->b_cont == NULL &&
		    (len & align_mask) != 0) {
			/* use the mp "as is" */
			return (mp);
		}
	} else {
		align_mask = 511;
		header_size = PKT_HEADER_SIZE;
	}

	/*
	 * re-allocate the mp
	 */
	/* minimum ethernet packet size of ETHERMIN */
	pkt_size = max(len, ETHERMIN);

	if (((pkt_size + header_size) & align_mask) == 0) {
		/* padding is required in usb communication */
		pad_size = PKT_HEADER_SIZE;
	} else {
		pad_size = 0;
	}

	if ((new = allocb(header_size + pkt_size + pad_size, 0)) == NULL) {
		return (NULL);
	}

	bp = new->b_rptr;
	if (header_size) {
		uint16_t	tmp;

		/* add a header */
		tmp = (uint16_t)pkt_size;
		FILL_PKT_HEADER(bp, tmp);
		bp += header_size;
	}

	/* copy contents of the buffer */
	for (tp = mp; tp; tp = tp->b_cont) {
		n = (uintptr_t)tp->b_wptr - (uintptr_t)tp->b_rptr;
		bcopy(tp->b_rptr, bp, n);
		bp += n;
	}

	/* add pads for ethernet packets */
	last_pos = new->b_rptr + header_size + pkt_size;
	while (bp < last_pos) {
		*bp++ = 0;
	}

	/* add a zero-length pad segment for usb communications */
	if (pad_size) {
		/* add a dummy header for zero-length packet */
		FILL_PKT_HEADER(bp, 0);
		bp += pad_size;
	}

	/* close the payload of the packet */
	new->b_wptr = bp;

	return (new);
}

static void
axf_dump_packet(struct usbgem_dev *dp, uint8_t *bp, int n)
{
	int	i;

	for (i = 0; i < n; i += 8, bp += 8) {
		cmn_err(CE_CONT, "%02x %02x %02x %02x %02x %02x %02x %02x",
		    bp[0], bp[1], bp[2], bp[3], bp[4], bp[5], bp[6], bp[7]);
	}
}

static mblk_t *
axf_rx_make_packet(struct usbgem_dev *dp, mblk_t *mp)
{
	mblk_t	*tp;
	uintptr_t rest;

	if (AX88172(dp)) {
		return (mp);
	}

	tp = mp;
	rest = (uintptr_t)tp->b_wptr - (uintptr_t)tp->b_rptr;

	if (rest <= PKT_HEADER_SIZE) {
		/*
		 * the usb bulk-in frame doesn't include any valid
		 * ethernet packets.
		 */
		return (NULL);
	}

	for (; ; ) {
		uint16_t	len;
		uint16_t	cksum;

		/* analyse the header of the received usb frame */
		len = LE16P(tp->b_rptr + 0);
		cksum = LE16P(tp->b_rptr + 2);

		/* test if the header is valid */
		if (len + cksum != 0xffff) {
			/* discard whole the packet */
			cmn_err(CE_WARN,
			    "!%s: %s: corrupted header:%04x %04x",
			    dp->name, __func__, len, cksum);
			return (NULL);
		}
#if DEBUG_LEVEL > 0
		if (len < ETHERMIN || len > ETHERMAX) {
			cmn_err(CE_NOTE,
			    "!%s: %s: incorrect pktsize:%d",
			    dp->name, __func__, len);
		}
#endif
		/* extract a ethernet packet from the bulk-in frame */
		tp->b_rptr += PKT_HEADER_SIZE;
		tp->b_wptr = tp->b_rptr + len;

		if (len & 1) {
			/*
			 * skip a tailing pad byte if the packet
			 * length is odd
			 */
			len++;
		}
		rest -= len + PKT_HEADER_SIZE;

		if (rest <= PKT_HEADER_SIZE) {
			/* no more vaild ethernet packets */
			break;
		}

#if DEBUG_LEVEL > 10
		axf_dump_packet(dp, tp->b_wptr, 18);
#endif
		/* allocate a mblk_t header for the next ethernet packet */
		tp->b_next = dupb(mp);
		tp->b_next->b_rptr = tp->b_rptr + len;
		tp = tp->b_next;
	}

	return (mp);
}

/*
 * MII Interfaces
 */
static uint16_t
axf_mii_read(struct usbgem_dev *dp, uint_t index, int *errp)
{
	uint8_t		buf[2];
	uint16_t	val;

	DPRINTF(4, (CE_CONT, "!%s: %s: called, ix:%d",
	    dp->name, __func__, index));

	/* switch to software MII operation mode */
	OUT(dp, VCMD_SOFTWARE_MII_OP, 0, 0, 0, NULL, errp, usberr);

	/* Read MII register */
	IN(dp, VCMD_READ_MII_REG, dp->mii_phy_addr, index,
	    2, buf, errp, usberr);

	/* switch to hardware MII operation mode */
	OUT(dp, VCMD_HARDWARE_MII_OP, 0, 0, 0, NULL, errp, usberr);

	return (LE16P(buf));

usberr:
	cmn_err(CE_CONT,
	    "!%s: %s: usberr(%d) detected", dp->name, __func__, *errp);
	return (0);
}

static void
axf_mii_write(struct usbgem_dev *dp, uint_t index, uint16_t val, int *errp)
{
	uint8_t		buf[2];

	DPRINTF(4, (CE_CONT, "!%s: %s called, reg:%x val:%x",
	    dp->name, __func__, index, val));

	/* switch software MII operation mode */
	OUT(dp, VCMD_SOFTWARE_MII_OP, 0, 0, 0, NULL, errp, usberr);

	/* Write to the specified MII register */
	buf[0] = (uint8_t)val;
	buf[1] = (uint8_t)(val >> 8);
	OUT(dp, VCMD_WRITE_MII_REG, dp->mii_phy_addr, index,
	    2, buf, errp, usberr);

	/* switch to hardware MII operation mode */
	OUT(dp, VCMD_HARDWARE_MII_OP, 0, 0, 0, NULL, errp, usberr);

usberr:
	;
}

static void
axf_interrupt(struct usbgem_dev *dp, mblk_t *mp)
{
	uint8_t	*bp;
	struct axf_dev	*lp = dp->private;

	bp = mp->b_rptr;

	DPRINTF(2, (CE_CONT,
	    "!%s: %s: size:%d, %02x %02x %02x %02x %02x %02x %02x %02x",
	    dp->name, __func__, mp->b_wptr - mp->b_rptr,
	    bp[0], bp[1], bp[2], bp[3], bp[4], bp[5], bp[6], bp[7]));

	if (lp->last_link_state ^ bp[2]) {
		usbgem_mii_update_link(dp);
	}

	lp->last_link_state = bp[2];
}

/* ======================================================== */
/*
 * OS depend (device driver DKI) routine
 */
/* ======================================================== */
#ifdef DEBUG_LEVEL
static void
axf_eeprom_dump(struct usbgem_dev *dp, int size)
{
	int	i;
	int	err;
	uint8_t	w0[2], w1[2], w2[2], w3[2];

	cmn_err(CE_CONT, "!%s: eeprom dump:", dp->name);

	err = USB_SUCCESS;

	for (i = 0; i < size; i += 4) {
		IN(dp, VCMD_READ_SROM, i + 0, 0, 2, w0, &err, usberr);
		IN(dp, VCMD_READ_SROM, i + 1, 0, 2, w1, &err, usberr);
		IN(dp, VCMD_READ_SROM, i + 2, 0, 2, w2, &err, usberr);
		IN(dp, VCMD_READ_SROM, i + 3, 0, 2, w3, &err, usberr);
		cmn_err(CE_CONT, "!0x%02x: 0x%04x 0x%04x 0x%04x 0x%04x",
		    i,
		    (w0[1] << 8) | w0[0],
		    (w1[1] << 8) | w1[0],
		    (w2[1] << 8) | w2[0],
		    (w3[1] << 8) | w3[0]);
	}
usberr:
	;
}
#endif

static int
axf_attach_chip(struct usbgem_dev *dp)
{
	uint8_t	phys[2];
	int	err;
	uint_t	vcmd;
	int	ret;
#ifdef CONFIG_FULLSIZE_VLAN
	uint8_t	maxpktsize[2];
	uint16_t	vlan_pktsize;
#endif
#ifdef DEBUG_LEVEL
	uint8_t	val8;
#endif
	struct axf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s enter", dp->name, __func__));

	ret = USB_SUCCESS;
	/*
	 * mac address in EEPROM has loaded to ID registers.
	 */
	vcmd = AX88172(dp) ? VCMD_READ_NODE_ID : VCMD_READ_NODE_ID_88772;
	IN(dp, vcmd, 0, 0,
	    ETHERADDRL, dp->dev_addr.ether_addr_octet, &err, usberr);

	/*
	 * setup IPG values
	 */
	lp->ipg[0] = 0x15;
	lp->ipg[1] = 0x0c;
	lp->ipg[2] = 0x12;

	/*
	 * We cannot scan phy because the nic returns undefined
	 * value, i.e. remained garbage, when MII phy is not at the
	 * specified index.
	 */
#ifdef DEBUG_LEVELx
	if (lp->chip->vid == 0x07b8 && lp->chip->pid == 0x420a) {
		/*
		 * restore the original phy address of brain
		 * damaged Planex UE2-100TX
		 */
		OUT(dp, VCMD_WRITE_SROM_ENABLE, 0, 0, 0, NULL, &err, usberr);
		OUT(dp, VCMD_WRITE_SROM, 0x11, 0xe004, 0, NULL, &err, usberr);
		OUT(dp, VCMD_WRITE_SROM_DISABLE, 0, 0, 0, NULL, &err, usberr);
	}
#endif
	if (AX88172(dp)) {
		IN(dp, VCMD_READ_PHY_IDS, 0, 0, 2, &phys, &err, usberr);
		dp->mii_phy_addr = phys[1];
		DPRINTF(0, (CE_CONT, "!%s: %s: phys_addr:%d %d",
		    dp->name, __func__, phys[0], phys[1]));
	} else {
		/* use built-in phy */
		dp->mii_phy_addr = 0x10;
	}

	dp->misc_flag |= USBGEM_VLAN;
#ifdef CONFIG_FULLSIZE_VLAN
	if (AX88172(dp) || AX88772(dp)) {
		/* check max packet size in srom */
		IN(dp, VCMD_READ_SROM, 0x10, 0, 2, maxpktsize, &err, usberr);
		vlan_pktsize = ETHERMAX + ETHERFCSL + 4 /* VTAG_SIZE */;

		if (LE16P(maxpktsize) < vlan_pktsize) {
			cmn_err(CE_CONT,
			    "!%s: %s: max packet size in srom is too small, "
			    "changing %d -> %d, do power cycle for the device",
			    dp->name, __func__,
			    LE16P(maxpktsize), vlan_pktsize);
			OUT(dp, VCMD_WRITE_SROM_ENABLE,
			    0, 0, 0, NULL, &err, usberr);
			OUT(dp, VCMD_WRITE_SROM, 0x10,
			    vlan_pktsize, 0, NULL, &err, usberr);
			OUT(dp, VCMD_WRITE_SROM_DISABLE,
			    0, 0, 0, NULL, &err, usberr);

			/* need to power off the device */
			ret = USB_FAILURE;
		}
	}
#endif
#ifdef DEBUG_LEVEL
	IN(dp, VCMD_READ_GPIO, 0, 0, 1, &val8, &err, usberr);
	cmn_err(CE_CONT,
	    "!%s: %s: ipg 0x%02x 0x%02x 0x%02x, gpio 0x%b",
	    dp->name, __func__, lp->ipg[0], lp->ipg[1], lp->ipg[2],
	    val8, GPIO_BITS);
#endif
	/* fix rx buffer size */
	if (!AX88172(dp)) {
		dp->rx_buf_len = 2048;
	}

#if DEBUG_LEVEL > 0
	axf_eeprom_dump(dp, 0x20);
#endif
	return (ret);

usberr:
	cmn_err(CE_WARN, "%s: %s: usb error detected (%d)",
	    dp->name, __func__, err);
	return (USB_FAILURE);
}

static boolean_t
axf_scan_phy(struct usbgem_dev *dp)
{
	int	i;
	int	err;
	uint16_t	val;
	int	phy_addr_saved;
	struct axf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	phy_addr_saved = dp->mii_phy_addr;

	/* special probe routine for unreliable MII addr */
#define	PROBE_PAT	\
	(MII_ABILITY_100BASE_TX_FD |	\
	MII_ABILITY_100BASE_TX |	\
	MII_ABILITY_10BASE_T_FD |	\
	MII_ABILITY_10BASE_T)

	for (i = 0; i < 32; i++) {
		dp->mii_phy_addr = i;
		axf_mii_write(dp, MII_AN_ADVERT, 0, &err);
		if (err != USBGEM_SUCCESS) {
			break;
		}
		val = axf_mii_read(dp, MII_AN_ADVERT, &err);
		if (err != USBGEM_SUCCESS) {
			break;
		}
		if (val != 0) {
			DPRINTF(0, (CE_CONT, "!%s: %s: index:%d,  val %b != 0",
			    dp->name, __func__, i, val, MII_ABILITY_BITS));
			continue;
		}

		axf_mii_write(dp, MII_AN_ADVERT, PROBE_PAT, &err);
		if (err != USBGEM_SUCCESS) {
			break;
		}
		val = axf_mii_read(dp, MII_AN_ADVERT, &err);
		if (err != USBGEM_SUCCESS) {
			break;
		}
		if ((val & MII_ABILITY_TECH) != PROBE_PAT) {
			DPRINTF(0, (CE_CONT, "!%s: %s: "
			    "index:%d,  pat:%x != val:%b",
			    dp->name, __func__, i,
			    PROBE_PAT, val, MII_ABILITY_BITS));
			continue;
		}

		/* found */
		dp->mii_phy_addr = phy_addr_saved;
		return (i);
	}
#undef PROBE_PAT
	if (i == 32) {
		cmn_err(CE_CONT, "!%s: %s: no mii phy found",
		    dp->name, __func__);
	} else {
		cmn_err(CE_CONT, "!%s: %s: i/o error while scanning phy",
		    dp->name, __func__);
	}
	dp->mii_phy_addr = phy_addr_saved;
	return (-1);
}

static int
axf_mii_probe(struct usbgem_dev *dp)
{
	int	my_guess;
	int	err;
	uint8_t	old_11th[2];
	uint8_t	new_11th[2];
	struct axf_dev	*lp = dp->private;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));
	(void) axf_reset_phy(dp);
	lp->phy_has_reset = B_TRUE;

	if (AX88172(dp)) {
		my_guess = axf_scan_phy(dp);
		if (my_guess >= 0 && my_guess < 32 &&
		    my_guess != dp->mii_phy_addr) {
			/*
			 * phy addr in srom is wrong, need to fix it
			 */
			IN(dp, VCMD_READ_SROM,
			    0x11, 0, 2, old_11th, &err, usberr);

			new_11th[0] = my_guess;
			new_11th[1] = old_11th[1];

			OUT(dp, VCMD_WRITE_SROM_ENABLE,
			    0, 0, 0, NULL, &err, usberr);
			OUT(dp, VCMD_WRITE_SROM,
			    0x11, LE16P(new_11th), 0, NULL, &err, usberr);
			OUT(dp, VCMD_WRITE_SROM_DISABLE,
			    0, 0, 0, NULL, &err, usberr);
#if 1
			/* XXX - read back, but it doesn't work, why? */
			delay(drv_usectohz(1000*1000));
			IN(dp, VCMD_READ_SROM,
			    0x11, 0, 2, new_11th, &err, usberr);
#endif
			cmn_err(CE_NOTE, "!%s: %s: phy addr in srom fixed: "
			    "%04x -> %04x",
			    dp->name, __func__,
			    LE16P(old_11th), LE16P(new_11th));
			return (USBGEM_FAILURE);
usberr:
			cmn_err(CE_NOTE,
			    "!%s: %s:  failed to patch phy addr, "
			    "current: %04x",
			    dp->name, __func__, LE16P(old_11th));
			return (USBGEM_FAILURE);
		}
	}
	return (usbgem_mii_probe_default(dp));
}

static int
axf_mii_init(struct usbgem_dev *dp)
{
	struct axf_dev	*lp = dp->private;

	DPRINTF(2, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	if (!lp->phy_has_reset) {
		(void) axf_reset_phy(dp);
	}

	/* prepare to reset phy on the next reconnect or resume */
	lp->phy_has_reset = B_FALSE;

	return (USB_SUCCESS);
}

static int
axfattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			i;
	ddi_iblock_cookie_t	c;
	int			ret;
	int			revid;
	int			unit;
	int			vid;
	int			pid;
	struct chip_info	*p;
	int			len;
	const char		*drv_name;
	struct usbgem_dev	*dp;
	void			*base;
	struct usbgem_conf	*ugcp;
	struct axf_dev		*lp;

	unit = ddi_get_instance(dip);
	drv_name = ddi_driver_name(dip);

	DPRINTF(3, (CE_CONT, "!%s%d: %s: called, cmd:%d",
	    drv_name, unit, __func__, cmd));

	if (cmd == DDI_ATTACH) {
		/*
		 * Check if the chip is supported.
		 */
		vid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "usb-vendor-id", -1);
		pid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "usb-product-id", -1);
		revid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "usb-revision-id", -1);

		for (i = 0, p = chiptbl_88x7x; i < CHIPTABLESIZE; i++, p++) {
			if (p->vid == vid && p->pid == pid) {
				/* found */
				cmn_err(CE_CONT, "!%s%d: %s "
				    "(vid: 0x%04x, did: 0x%04x, revid: 0x%02x)",
				    drv_name, unit, p->name, vid, pid, revid);
				goto chip_found;
			}
		}

		/* Not found */
		cmn_err(CE_WARN, "!%s: %s: wrong usb venid/prodid (0x%x, 0x%x)",
		    drv_name, __func__, vid, pid);

		/* assume 88772 */
		p = &chiptbl_88x7x[CHIPTABLESIZE - 1];
chip_found:
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

		ugcp->usbgc_rx_header_len = 0;
		ugcp->usbgc_rx_list_max = 64;

		/* time out parameters */
		ugcp->usbgc_tx_timeout = USBGEM_TX_TIMEOUT;
		ugcp->usbgc_tx_timeout_interval = USBGEM_TX_TIMEOUT_INTERVAL;

		/* flow control */
		/*
		 * XXX - flow control caused link down frequently under
		 * heavy traffic
		 */
		ugcp->usbgc_flow_control = FLOW_CONTROL_RX_PAUSE;

		/* MII timeout parameters */
		ugcp->usbgc_mii_link_watch_interval = ONESEC;
		ugcp->usbgc_mii_an_watch_interval = ONESEC/5;
		ugcp->usbgc_mii_reset_timeout = MII_RESET_TIMEOUT; /* 1 sec */
		ugcp->usbgc_mii_an_timeout = MII_AN_TIMEOUT;	/* 5 sec */
		ugcp->usbgc_mii_an_wait = 0;
		ugcp->usbgc_mii_linkdown_timeout = MII_LINKDOWN_TIMEOUT;

		ugcp->usbgc_mii_an_delay = ONESEC/10;
		ugcp->usbgc_mii_linkdown_action = MII_ACTION_RSA;
		ugcp->usbgc_mii_linkdown_timeout_action = MII_ACTION_RESET;
		ugcp->usbgc_mii_dont_reset = B_FALSE;
		ugcp->usbgc_mii_hw_link_detection = B_TRUE;
		ugcp->usbgc_mii_stop_mac_on_linkdown = B_FALSE;

		/* I/O methods */

		/* mac operation */
		ugcp->usbgc_attach_chip = &axf_attach_chip;
		ugcp->usbgc_reset_chip = &axf_reset_chip;
		ugcp->usbgc_init_chip = &axf_init_chip;
		ugcp->usbgc_start_chip = &axf_start_chip;
		ugcp->usbgc_stop_chip = &axf_stop_chip;
		ugcp->usbgc_multicast_hash = &axf_mcast_hash;

		ugcp->usbgc_set_rx_filter = &axf_set_rx_filter;
		ugcp->usbgc_set_media = &axf_set_media;
		ugcp->usbgc_get_stats = &axf_get_stats;
		ugcp->usbgc_interrupt = &axf_interrupt;

		/* packet operation */
		ugcp->usbgc_tx_make_packet = &axf_tx_make_packet;
		ugcp->usbgc_rx_make_packet = &axf_rx_make_packet;

		/* mii operations */
		ugcp->usbgc_mii_probe = &axf_mii_probe;
		ugcp->usbgc_mii_init = &axf_mii_init;
		ugcp->usbgc_mii_config = &usbgem_mii_config_default;
		ugcp->usbgc_mii_read = &axf_mii_read;
		ugcp->usbgc_mii_write = &axf_mii_write;

		/* mtu */
		ugcp->usbgc_min_mtu = ETHERMTU;
		ugcp->usbgc_max_mtu = ETHERMTU;
		ugcp->usbgc_default_mtu = ETHERMTU;

		lp = kmem_zalloc(sizeof (struct axf_dev), KM_SLEEP);
		lp->chip = p;
		lp->last_link_state = 0;
		lp->phy_has_reset = B_FALSE;

		dp = usbgem_do_attach(dip, ugcp, lp, sizeof (struct axf_dev));

		kmem_free(ugcp, sizeof (*ugcp));

		if (dp != NULL) {
			return (DDI_SUCCESS);
		}

err_free_mem:
		kmem_free(lp, sizeof (struct axf_dev));
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
axfdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
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
USBGEM_STREAM_OPS(axf_ops, axfattach, axfdetach);
#else
static	struct module_info axfminfo = {
	0,			/* mi_idnum */
	"axf",			/* mi_idname */
	0,			/* mi_minpsz */
	ETHERMTU,		/* mi_maxpsz */
	ETHERMTU*128,		/* mi_hiwat */
	1,			/* mi_lowat */
};

static	struct qinit axfrinit = {
	(int (*)()) NULL,	/* qi_putp */
	usbgem_rsrv,		/* qi_srvp */
	usbgem_open,		/* qi_qopen */
	usbgem_close,		/* qi_qclose */
	(int (*)()) NULL,	/* qi_qadmin */
	&axfminfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct qinit axfwinit = {
	usbgem_wput,		/* qi_putp */
	usbgem_wsrv,		/* qi_srvp */
	(int (*)()) NULL,	/* qi_qopen */
	(int (*)()) NULL,	/* qi_qclose */
	(int (*)()) NULL,	/* qi_qadmin */
	&axfminfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct streamtab	axf_info = {
	&axfrinit,	/* st_rdinit */
	&axfwinit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

static	struct cb_ops cb_axf_ops = {
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
	&axf_info,	/* cb_stream */
	D_NEW|D_MP	/* cb_flag */
};

static	struct dev_ops axf_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	usbgem_getinfo,	/* devo_getinfo */
	nulldev,	/* devo_identify */
	nulldev,	/* devo_probe */
	axfattach,	/* devo_attach */
	axfdetach,	/* devo_detach */
	nodev,		/* devo_reset */
	&cb_axf_ops,	/* devo_cb_ops */
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
	&axf_ops,	/* driver ops */
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

	DPRINTF(2, (CE_CONT, "!axf: _init: called"));

	status = usbgem_mod_init(&axf_ops, "axf");
	if (status != DDI_SUCCESS) {
		return (status);
	}
	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS) {
		usbgem_mod_fini(&axf_ops);
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

	DPRINTF(2, (CE_CONT, "!axf: _fini: called"));
	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		usbgem_mod_fini(&axf_ops);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
