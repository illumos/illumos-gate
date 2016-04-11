/*
 * usbgem.c: General USB to Fast Ethernet mac driver framework
 *
 * Copyright (c) 2002-2012 Masayuki Murayama.  All rights reserved.
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

#pragma	ident	"@(#)usbgem.c 1.6     12/02/09"

/*
 * Change log
 */

/*
 * TODO:
 * 	implement DELAYED_START
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
#ifndef USBGEM_CONFIG_GLDv3
#include <sys/dlpi.h>
#include <sys/strsubr.h>
#endif
#include <sys/stream.h>		/* required for MBLK* */
#include <sys/strsun.h>		/* required for mionack() */
#include <sys/byteorder.h>

#include <sys/usb/usba.h>
#ifdef USBGEM_CONFIG_GLDv3
#include <inet/common.h>
#include <inet/led.h>
#include <inet/mi.h>
#include <inet/nd.h>
#endif

/* supplement definitions */
extern const char *usb_str_cr(usb_cr_t);

#ifndef USBGEM_CONFIG_GLDv3
#pragma weak	gld_linkstate
#endif
#include <sys/note.h>

#include "usbgem_mii.h"
#include "usbgem.h"

#ifdef MODULE
char	ident[] = "usb general ethernet mac driver v" VERSION;
#else
extern char	ident[];
#endif

/* Debugging support */
#ifdef USBGEM_DEBUG_LEVEL
static int usbgem_debug = USBGEM_DEBUG_LEVEL;
#define	DPRINTF(n, args)	if (usbgem_debug > (n)) cmn_err args
#else
#define	DPRINTF(n, args)
#endif

/*
 * Useful macros and typedefs
 */
#define	ROUNDUP(x, a)		(((x) + (a) - 1) & ~((a) - 1))
#define	DEFAULT_PIPE(dp)	((dp)->reg_data->dev_default_ph)
#define	VTAG_SIZE	4
#define	BOOLEAN(x)	((x) != 0)
/*
 * configuration parameters
 */
#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#define	ETHERHEADERL	(sizeof (struct ether_header))
#define	MAXPKTLEN(dp)	((dp)->mtu + ETHERHEADERL)
#define	MAXPKTBUF(dp)	((dp)->mtu + ETHERHEADERL + ETHERFCSL)

#define	WATCH_INTERVAL_FAST	drv_usectohz(100*1000)

#define	STOP_GRACEFUL	B_TRUE

/*
 * Private functions
 */
static int usbgem_open_pipes(struct usbgem_dev *dp);
static int usbgem_close_pipes(struct usbgem_dev *dp);
static void usbgem_intr_cb(usb_pipe_handle_t, usb_intr_req_t *);
static void usbgem_bulkin_cb(usb_pipe_handle_t, usb_bulk_req_t *);
static void usbgem_bulkout_cb(usb_pipe_handle_t, usb_bulk_req_t *);

static int usbgem_mii_start(struct usbgem_dev *);
static void usbgem_mii_stop(struct usbgem_dev *);

/* local buffer management */
static int usbgem_init_rx_buf(struct usbgem_dev *);

/* internal mac interfaces */
static void usbgem_tx_timeout(struct usbgem_dev *);
static void usbgem_mii_link_watcher(struct usbgem_dev *);
static int usbgem_mac_init(struct usbgem_dev *);
static int usbgem_mac_start(struct usbgem_dev *);
static int usbgem_mac_stop(struct usbgem_dev *, int, boolean_t);
static void usbgem_mac_ioctl(struct usbgem_dev *, queue_t *, mblk_t *);

int usbgem_speed_value[] = {10, 100, 1000};

static int usbgem_ctrl_retry = 5;

/* usb event support */
static int usbgem_disconnect_cb(dev_info_t *dip);
static int usbgem_reconnect_cb(dev_info_t *dip);
int usbgem_suspend(dev_info_t *dip);
int usbgem_resume(dev_info_t *dip);

static uint8_t usbgem_bcastaddr[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

#ifdef MODULE
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"usbgem v" VERSION,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};

/*
 * _init : done
 */
int
_init(void)
{
	int 	status;

	DPRINTF(2, (CE_CONT, "!usbgem: _init: called"));
	status = mod_install(&modlinkage);

	return (status);
}

/*
 * _fini : done
 */
int
_fini(void)
{
	int	status;

	DPRINTF(2, (CE_CONT, "!usbgem: _fini: called"));
	status = mod_remove(&modlinkage);
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
#endif /* MODULE */

/* ============================================================== */
/*
 * Ether CRC calculation utilities
 */
/* ============================================================== */
/*
 * Ether CRC calculation according to 21143 data sheet
 */
#define	CRC32_POLY_LE	0xedb88320
uint32_t
usbgem_ether_crc_le(const uint8_t *addr)
{
	int		idx;
	int		bit;
	uint_t		data;
	uint32_t	crc = 0xffffffff;

	crc = 0xffffffff;
	for (idx = 0; idx < ETHERADDRL; idx++) {
		for (data = *addr++, bit = 0; bit < 8; bit++, data >>= 1) {
			crc = (crc >> 1) ^
			    (((crc ^ data) & 1) ? CRC32_POLY_LE : 0);
		}
	}
	return	(crc);
}

#define	CRC32_POLY_BE	0x04c11db7
uint32_t
usbgem_ether_crc_be(const uint8_t *addr)
{
	int		idx;
	int		bit;
	uint_t		data;
	uint32_t	crc;

	crc = 0xffffffff;
	for (idx = 0; idx < ETHERADDRL; idx++) {
		for (data = *addr++, bit = 0; bit < 8; bit++, data >>= 1) {
			crc = (crc << 1) ^
			    ((((crc >> 31) ^ data) & 1) ? CRC32_POLY_BE : 0);
		}
	}
	return (crc);
}

int
usbgem_prop_get_int(struct usbgem_dev *dp, char *prop_template, int def_val)
{
	char	propname[32];

	(void) sprintf(propname, prop_template, dp->name);

	return (ddi_prop_get_int(DDI_DEV_T_ANY, dp->dip,
	    DDI_PROP_DONTPASS, propname, def_val));
}

static int
usbgem_population(uint32_t x)
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

static clock_t
usbgem_timestamp_nz()
{
	clock_t	now;
	now = ddi_get_lbolt();
	return (now ? now : (clock_t)1);
}

#ifdef USBGEM_DEBUG_LEVEL
#ifdef USBGEM_DEBUG_VLAN
#ifdef notdef
#include <netinet/in.h>
#endif
static void
usbgem_dump_packet(struct usbgem_dev *dp, char *title, mblk_t *mp,
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
#endif /* USBGEM_DEBUG_VLAN */
#endif /* USBGEM_DEBUG_LEVEL */

#ifdef GEM_GCC_RUNTIME
/*
 * gcc3 runtime routines
 */
#pragma weak memcmp
int
memcmp(const void *s1, const void *s2, size_t n)
{
	int	i;
	int	ret;

	ret = 0;
	for (i = 0; i < n; i++) {
		ret = (int)((uint8_t *)s1)[i] - (int)((uint8_t *)s2)[i];
		if (ret) {
			return (ret);
		}
	}
	return (0);
}

#pragma weak memset
void *
memset(void *s, int c, size_t n)
{
	if ((c & 0xff) == 0) {
		bzero(s, n);
	} else {
		while (n--) {
			((uint8_t *)s)[n] = c;
		}
	}
	return (s);
}

#pragma weak _memcpy = memcpy
#pragma weak memcpy
void *
memcpy(void *s1, const void *s2, size_t n)
{
	bcopy(s2, s1, n);
	return (s1);
}
#endif /* GEM_GCC_RUNTIME */
/* ============================================================== */
/*
 * hardware operations
 */
/* ============================================================== */
static int
usbgem_hal_reset_chip(struct usbgem_dev *dp)
{
	int	err;

	sema_p(&dp->hal_op_lock);
	err = (*dp->ugc.usbgc_reset_chip)(dp);
	sema_v(&dp->hal_op_lock);
	return (err);
}

static int
usbgem_hal_init_chip(struct usbgem_dev *dp)
{
	int	err;

	sema_p(&dp->hal_op_lock);
	err = (*dp->ugc.usbgc_init_chip)(dp);
	sema_v(&dp->hal_op_lock);
	return (err);
}

static int
usbgem_hal_attach_chip(struct usbgem_dev *dp)
{
	int	err;

	sema_p(&dp->hal_op_lock);
	err = (*dp->ugc.usbgc_attach_chip)(dp);
	sema_v(&dp->hal_op_lock);
	return (err);
}

static int
usbgem_hal_set_rx_filter(struct usbgem_dev *dp)
{
	int	err;

	sema_p(&dp->hal_op_lock);
	err = (*dp->ugc.usbgc_set_rx_filter)(dp);
	sema_v(&dp->hal_op_lock);
	return (err);
}

static int
usbgem_hal_set_media(struct usbgem_dev *dp)
{
	int	err;

	sema_p(&dp->hal_op_lock);
	err = (*dp->ugc.usbgc_set_media)(dp);
	sema_v(&dp->hal_op_lock);
	return (err);
}

static int
usbgem_hal_start_chip(struct usbgem_dev *dp)
{
	int	err;

	sema_p(&dp->hal_op_lock);
	err = (*dp->ugc.usbgc_start_chip)(dp);
	sema_v(&dp->hal_op_lock);
	return (err);
}

static int
usbgem_hal_stop_chip(struct usbgem_dev *dp)
{
	int	err;

	sema_p(&dp->hal_op_lock);
	err = (*dp->ugc.usbgc_stop_chip)(dp);
	sema_v(&dp->hal_op_lock);
	return (err);
}

static int
usbgem_hal_get_stats(struct usbgem_dev *dp)
{
	int	err;

	sema_p(&dp->hal_op_lock);
	err = (*dp->ugc.usbgc_get_stats)(dp);
	sema_v(&dp->hal_op_lock);
	return (err);
}


/* ============================================================== */
/*
 * USB pipe management
 */
/* ============================================================== */
static boolean_t
usbgem_rx_start_unit(struct usbgem_dev *dp, usb_bulk_req_t *req)
{
	mblk_t	*mp;
	int	err;
	usb_flags_t	flags;

	ASSERT(req);

	mp = allocb(dp->rx_buf_len, BPRI_MED);
	if (mp == NULL) {
		cmn_err(CE_WARN, "!%s: %s: failed to allocate mblk",
		    dp->name, __func__);
		goto err;
	}

	req->bulk_len = dp->rx_buf_len;
	req->bulk_data = mp;
	req->bulk_client_private = (usb_opaque_t)dp;
	req->bulk_timeout = 0;
	req->bulk_attributes = USB_ATTRS_SHORT_XFER_OK;
	req->bulk_cb = usbgem_bulkin_cb;
	req->bulk_exc_cb = usbgem_bulkin_cb;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags = 0;

	flags = 0;
	err = usb_pipe_bulk_xfer(dp->bulkin_pipe, req, flags);

	if (err != USB_SUCCESS) {
		cmn_err(CE_WARN, "%s: failed to bulk_xfer for rx, err:%d",
		    dp->name, err);

		/* free req and mp */
		usb_free_bulk_req(req);
		goto err;
	}
	return (B_TRUE);
err:
	return (B_FALSE);
}

/* ============================================================== */
/*
 * Rx/Tx buffer management
 */
/* ============================================================== */
static int
usbgem_init_rx_buf(struct usbgem_dev *dp)
{
	int	i;
	usb_bulk_req_t	*req;

	ASSERT(dp->mac_state == MAC_STATE_ONLINE);

	for (i = 0; i < dp->ugc.usbgc_rx_list_max; i++) {
		req = usb_alloc_bulk_req(dp->dip, 0, USB_FLAGS_SLEEP);
		if (req == NULL) {
			cmn_err(CE_WARN,
			    "!%s: %s: failed to allocate bulkreq for rx",
			    dp->name, __func__);
			return (USB_FAILURE);
		}
		if (!usbgem_rx_start_unit(dp, req)) {
			return (USB_FAILURE);
		}
		mutex_enter(&dp->rxlock);
		dp->rx_busy_cnt++;
		mutex_exit(&dp->rxlock);
	}
	return (USB_SUCCESS);
}

/* ============================================================== */
/*
 * memory resource management
 */
/* ============================================================== */
static int
usbgem_free_memory(struct usbgem_dev *dp)
{
	usb_bulk_req_t	*req;

	/* free all tx requst structure */
	while ((req = dp->tx_free_list) != NULL) {
		dp->tx_free_list =
		    (usb_bulk_req_t *)req->bulk_client_private;
		req->bulk_data = NULL;
		usb_free_bulk_req(req);
	}
	return (USB_SUCCESS);
}

static int
usbgem_alloc_memory(struct usbgem_dev *dp)
{
	int	i;
	usb_bulk_req_t	*req;

	/* allocate tx requests */
	dp->tx_free_list = NULL;
	for (i = 0; i < dp->ugc.usbgc_tx_list_max; i++) {
		req = usb_alloc_bulk_req(dp->dip, 0, USB_FLAGS_SLEEP);
		if (req == NULL) {
			cmn_err(CE_WARN,
			    "%s:%s failed to allocate tx requests",
			    dp->name, __func__);

			/* free partially allocated tx requests */
			(void) usbgem_free_memory(dp);
			return (USB_FAILURE);
		}

		/* add the new one allocated into tx free list */
		req->bulk_client_private = (usb_opaque_t)dp->tx_free_list;
		dp->tx_free_list = req;
	}

	return (USB_SUCCESS);
}

/* ========================================================== */
/*
 * Start transmission.
 * Return zero on success,
 */
/* ========================================================== */

#ifdef TXTIMEOUT_TEST
static int usbgem_send_cnt = 0;
#endif

/*
 * usbgem_send is used only to send data packet into ethernet line.
 */
static mblk_t *
usbgem_send_common(struct usbgem_dev *dp, mblk_t *mp, uint32_t flags)
{
	int		err;
	mblk_t		*new;
	usb_bulk_req_t	*req;
	int		mcast;
	int		bcast;
	int		len;
	boolean_t	intr;
	usb_flags_t	usb_flags = 0;
#ifdef USBGEM_DEBUG_LEVEL
	usb_pipe_state_t	p_state;
#endif
	DPRINTF(2, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	intr = (flags & 1) != 0;
	len = msgdsize(mp);
	bcast = 0;
	mcast = 0;
	if (mp->b_rptr[0] & 1) {
		if (bcmp(mp->b_rptr, &usbgem_bcastaddr, ETHERADDRL) == 0) {
			bcast = 1;
		} else {
			mcast = 1;
		}
	}
	new = (*dp->ugc.usbgc_tx_make_packet)(dp, mp);
	if (new == NULL) {
		/*
		 * no memory resource. we don't stop downstream,
		 * we just discard the packet.
		 */
		DPRINTF(0, (CE_CONT, "!%s: %s: no memory",
		    dp->name, __func__));
		freemsg(mp);

		mutex_enter(&dp->txlock);
		dp->stats.noxmtbuf++;
		dp->stats.errxmt++;
		mutex_exit(&dp->txlock);

		return (NULL);
	}

	ASSERT(new->b_cont == NULL);

	mutex_enter(&dp->txlock);
	if (dp->tx_free_list == NULL) {
		/*
		 * no tx free slot
		 */
		ASSERT(dp->tx_busy_cnt == dp->ugc.usbgc_tx_list_max);
		mutex_exit(&dp->txlock);

		DPRINTF(4, (CE_CONT, "!%s: %s: no free slot",
		    dp->name, __func__));
		if (new && new != mp) {
			/* free reallocated message */
			freemsg(new);
		}
		return (mp);
	}
	req = dp->tx_free_list;
	dp->tx_free_list = (usb_bulk_req_t *)req->bulk_client_private;
	dp->tx_busy_cnt++;

	if (dp->tx_free_list == NULL) {
		intr = B_TRUE;
	}
	if (intr) {
		dp->tx_intr_pended++;
	}
	DB_TCI(new) = intr;
#ifdef USBGEM_DEBUG_LEVEL
	new->b_datap->db_cksum32 = dp->tx_seq_num;
	dp->tx_seq_num++;
#endif
	dp->stats.obytes += len;
	dp->stats.opackets++;
	if (bcast | mcast) {
		dp->stats.obcast += bcast;
		dp->stats.omcast += mcast;
	}
	mutex_exit(&dp->txlock);

	DPRINTF(2, (CE_CONT, "!%s: %s: sending", dp->name, __func__));

	req->bulk_len = (long)new->b_wptr - (long)new->b_rptr;
	req->bulk_data = new;
	req->bulk_client_private = (usb_opaque_t)dp;
	req->bulk_timeout = dp->bulkout_timeout;	/* in second */
	req->bulk_attributes = 0;
	req->bulk_cb = usbgem_bulkout_cb;
	req->bulk_exc_cb = usbgem_bulkout_cb;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags = 0;

	if (intr) {
		usb_flags = USB_FLAGS_SLEEP;
	}
	if ((err = usb_pipe_bulk_xfer(dp->bulkout_pipe, req, usb_flags))
	    != USB_SUCCESS) {

		/* failed to transfer the packet, discard it. */
		freemsg(new);
		req->bulk_data = NULL;

		/* recycle the request block */
		mutex_enter(&dp->txlock);
		dp->tx_busy_cnt--;
		req->bulk_client_private = (usb_opaque_t)dp->tx_free_list;
		dp->tx_free_list = req;
		mutex_exit(&dp->txlock);

		cmn_err(CE_NOTE,
		    "%s: %s: usb_pipe_bulk_xfer: failed: err:%d",
		    dp->name, __func__, err);

		/* we use another flag to indicate error state. */
		if (dp->fatal_error == (clock_t)0) {
			dp->fatal_error = usbgem_timestamp_nz();
		}
	} else {
		/* record the start time */
		dp->tx_start_time = ddi_get_lbolt();
	}

	if (err == USB_SUCCESS && (usb_flags & USB_FLAGS_SLEEP)) {
		usbgem_bulkout_cb(dp->bulkout_pipe, req);
	}

	if (new != mp) {
		freemsg(mp);
	}
	return (NULL);
}

int
usbgem_restart_nic(struct usbgem_dev *dp)
{
	int	ret;
	int	flags = 0;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	ASSERT(dp->mac_state != MAC_STATE_DISCONNECTED);

	/*
	 * ensure to stop the nic
	 */
	if (dp->mac_state == MAC_STATE_ONLINE) {
		(void) usbgem_mac_stop(dp, MAC_STATE_STOPPED, STOP_GRACEFUL);
	}

	/* now the nic become quiescent, reset the chip */
	if (usbgem_hal_reset_chip(dp) != USB_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s: failed to reset chip",
		    dp->name, __func__);
		goto err;
	}

	/*
	 * restore the nic state step by step
	 */
	if (dp->nic_state < NIC_STATE_INITIALIZED) {
		goto done;
	}

	if (usbgem_mac_init(dp) != USB_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s: failed to initialize chip",
		    dp->name, __func__);
		goto err;
	}

	/* setup mac address and enable rx filter */
	sema_p(&dp->rxfilter_lock);
	dp->rxmode |= RXMODE_ENABLE;
	ret = usbgem_hal_set_rx_filter(dp);
	sema_v(&dp->rxfilter_lock);
	if (ret != USB_SUCCESS) {
		goto err;
	}

	/*
	 * update the link state asynchronously
	 */
	cv_signal(&dp->link_watcher_wait_cv);

	/*
	 * XXX - a panic happened because of linkdown.
	 * We must check mii_state here, because the link can be down just
	 * before the restart event happen. If the link is down now,
	 * gem_mac_start() will be called from gem_mii_link_check() when
	 * the link become up later.
	 */
	if (dp->mii_state == MII_STATE_LINKUP) {
		if (usbgem_hal_set_media(dp) != USB_SUCCESS) {
			goto err;
		}
		if (dp->nic_state < NIC_STATE_ONLINE) {
			goto done;
		}

		(void) usbgem_mac_start(dp);

	}
done:
	return (USB_SUCCESS);
err:
#ifdef GEM_CONFIG_FMA
	ddi_fm_service_impact(dp->dip, DDI_SERVICE_DEGRADED);
#endif
	return (USB_FAILURE);
}

static void
usbgem_tx_timeout(struct usbgem_dev *dp)
{
	int	ret;
	uint_t	rwlock;
	clock_t	now;

	for (; ; ) {
		mutex_enter(&dp->tx_watcher_lock);
		ret = cv_timedwait(&dp->tx_watcher_cv, &dp->tx_watcher_lock,
		    dp->tx_watcher_interval + ddi_get_lbolt());
		mutex_exit(&dp->tx_watcher_lock);

		if (dp->tx_watcher_stop) {
			break;
		}

		now = ddi_get_lbolt();

		rwlock = RW_READER;
again:
		rw_enter(&dp->dev_state_lock, rwlock);

		if ((dp->mac_state != MAC_STATE_DISCONNECTED &&
		    dp->fatal_error &&
		    now - dp->fatal_error >= dp->ugc.usbgc_tx_timeout) ||
		    (dp->mac_state == MAC_STATE_ONLINE &&
		    dp->mii_state == MII_STATE_LINKUP &&
		    dp->tx_busy_cnt != 0 &&
		    now - dp->tx_start_time >= dp->ugc.usbgc_tx_timeout)) {
			if (rwlock == RW_READER) {
				/*
				 * Upgrade dev_state_lock from shared mode
				 * to exclusive mode to restart nic
				 */
				rwlock = RW_WRITER;
				rw_exit(&dp->dev_state_lock);
				goto again;
			}
			cmn_err(CE_WARN, "%s: %s: restarting the nic:"
			    " fatal_error:%ld nic_state:%d"
			    " mac_state:%d starttime:%ld",
			    dp->name, __func__,
			    dp->fatal_error ? now - dp->fatal_error: 0,
			    dp->nic_state, dp->mac_state,
			    dp->tx_busy_cnt ? now - dp->tx_start_time : 0);

			(void) usbgem_restart_nic(dp);
		}

		rw_exit(&dp->dev_state_lock);
	}
}

static int
usbgem_tx_watcher_start(struct usbgem_dev *dp)
{
	int	err;
	kthread_t	*wdth;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* make a first call of uwgem_lw_link_check() */
	dp->tx_watcher_stop = 0;
	dp->tx_watcher_interval = drv_usectohz(1000*1000);

	wdth = thread_create(NULL, 0, usbgem_tx_timeout, dp, 0, &p0,
	    TS_RUN, minclsyspri);
	if (wdth == NULL) {
		cmn_err(CE_WARN,
		    "!%s: %s: failed to create a tx_watcher thread",
		    dp->name, __func__);
		return (USB_FAILURE);
	}
	dp->tx_watcher_did = wdth->t_did;

	return (USB_SUCCESS);
}

static void
usbgem_tx_watcher_stop(struct usbgem_dev *dp)
{
	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));
	if (dp->tx_watcher_did) {
		/* Ensure timer routine stopped */
		dp->tx_watcher_stop = 1;
		cv_signal(&dp->tx_watcher_cv);
		thread_join(dp->tx_watcher_did);
		dp->tx_watcher_did = NULL;
	}
}

/* ================================================================== */
/*
 * Callback handlers
 */
/* ================================================================== */
static void
usbgem_bulkin_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	mblk_t	*newmp;
	mblk_t	*mp;
	mblk_t	*tp;
	uint64_t	len = 0;
	int	pkts = 0;
	int	bcast = 0;
	int	mcast = 0;
	boolean_t	busy;
	struct usbgem_dev	*dp;

	dp = (struct usbgem_dev *)req->bulk_client_private;
	mp = req->bulk_data;
	req->bulk_data = NULL;

	DPRINTF(2, (CE_CONT, "!%s: %s: mp:%p, cr:%s(%d)",
	    dp->name, __func__, mp,
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason));

	/*
	 * we cannot acquire dev_state_lock because the routine
	 * must be executed during usbgem_mac_stop() to avoid
	 * dead lock.
	 * we use a simle membar operation to get the state correctly.
	 */
	membar_consumer();

	if (req->bulk_completion_reason == USB_CR_OK &&
	    dp->nic_state == NIC_STATE_ONLINE) {
		newmp = (*dp->ugc.usbgc_rx_make_packet)(dp, mp);

		if (newmp != mp) {
			/* the message has been reallocated, free old one */
			freemsg(mp);
		}

		/* the message may includes one or more ethernet packets */
		for (tp = newmp; tp; tp = tp->b_next) {
			len += (uintptr_t)tp->b_wptr - (uintptr_t)tp->b_rptr;
			pkts++;
			if (tp->b_rptr[0] & 1) {
				if (bcmp(tp->b_rptr, &usbgem_bcastaddr,
				    ETHERADDRL) == 0) {
					bcast++;
				} else {
					mcast++;
				}
			}
		}

		/* send up if it is a valid packet */
#ifdef USBGEM_CONFIG_GLDv3
		mac_rx(dp->mh, NULL, newmp);
#else
		while (newmp) {
			tp = newmp;
			newmp = newmp->b_next;
			tp->b_next = NULL;
			gld_recv(dp->macinfo, tp);
		}
#endif
	} else {
		freemsg(mp);
		len = 0;
	}

	mutex_enter(&dp->rxlock);
	/* update rx_active */
	if (dp->rx_active) {
		dp->rx_active = dp->mac_state == MAC_STATE_ONLINE;
	}

	dp->stats.rbytes += len;
	dp->stats.rpackets += pkts;
	if (bcast | mcast) {
		dp->stats.rbcast += bcast;
		dp->stats.rmcast += mcast;
	}
	mutex_exit(&dp->rxlock);

	if (dp->rx_active) {
		/* prepare to receive the next packets */
		if (usbgem_rx_start_unit(dp, req)) {
			/* we successed */
			goto done;
		}
		cmn_err(CE_WARN,
		    "!%s: %s: failed to fill next rx packet",
		    dp->name, __func__);
		/*
		 * we use another flag to indicate error state.
		 * if we acquire dev_state_lock for RW_WRITER here,
		 * usbgem_mac_stop() may hang.
		 */
		if (dp->fatal_error == (clock_t)0) {
			dp->fatal_error = usbgem_timestamp_nz();
		}
	} else {
		/* no need to prepare the next packets */
		usb_free_bulk_req(req);
	}

	mutex_enter(&dp->rxlock);
	dp->rx_active = B_FALSE;
	dp->rx_busy_cnt--;
	if (dp->rx_busy_cnt == 0) {
		/* wake up someone waits for me */
		cv_broadcast(&dp->rx_drain_cv);
	}
	mutex_exit(&dp->rxlock);
done:
	;
}

static void
usbgem_bulkout_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	boolean_t	intr;
	boolean_t	tx_sched;
	struct usbgem_dev	*dp;

	dp = (struct usbgem_dev *)req->bulk_client_private;
	tx_sched = B_FALSE;

	DPRINTF(2, (CE_CONT,
	    "!%s: %s: cr:%s(%d) cb_flags:0x%x head:%d tail:%d",
	    dp->name, __func__,
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    dp->tx_busy_cnt));

	/* we have finished to transfer the packet into tx fifo */
	intr = DB_TCI(req->bulk_data);
	freemsg(req->bulk_data);

	if (req->bulk_completion_reason != USB_CR_OK &&
	    dp->fatal_error == (clock_t)0) {
		dp->fatal_error = usbgem_timestamp_nz();
	}

	mutex_enter(&dp->txlock);

	if (intr) {
		ASSERT(dp->tx_intr_pended > 0);
		/* find the last interrupt we have scheduled */
		if (--(dp->tx_intr_pended) == 0) {
			tx_sched = B_TRUE;
		}
	}

	ASSERT(dp->tx_busy_cnt > 0);
	req->bulk_client_private = (usb_opaque_t)dp->tx_free_list;
	dp->tx_free_list = req;
	dp->tx_busy_cnt--;

#ifdef CONFIG_TX_LIMITER
	if (tx_sched) {
		dp->tx_max_packets =
		    min(dp->tx_max_packets + 1, dp->ugc.usbgc_tx_list_max);
	}
#endif
	if (dp->mac_state != MAC_STATE_ONLINE && dp->tx_busy_cnt == 0) {
		cv_broadcast(&dp->tx_drain_cv);
	}

	mutex_exit(&dp->txlock);

	if (tx_sched) {
#ifdef USBGEM_CONFIG_GLDv3
		mac_tx_update(dp->mh);
#else
		gld_sched(dp->macinfo);
#endif
	}
}

static void
usbgem_intr_cb(usb_pipe_handle_t ph, usb_intr_req_t *req)
{
	struct usbgem_dev	*dp;

	dp = (struct usbgem_dev *)req->intr_client_private;
	dp->stats.intr++;

	if (req->intr_completion_reason == USB_CR_OK) {
		(*dp->ugc.usbgc_interrupt)(dp, req->intr_data);
	}

	/* free the request and data */
	usb_free_intr_req(req);
}

/* ======================================================================== */
/*
 * MII support routines
 */
/* ======================================================================== */
static void
usbgem_choose_forcedmode(struct usbgem_dev *dp)
{
	/* choose media mode */
	if (dp->anadv_1000fdx || dp->anadv_1000hdx) {
		dp->speed = USBGEM_SPD_1000;
		dp->full_duplex = dp->anadv_1000fdx;
	} else if (dp->anadv_100fdx || dp->anadv_100t4) {
		dp->speed = USBGEM_SPD_100;
		dp->full_duplex = B_TRUE;
	} else if (dp->anadv_100hdx) {
		dp->speed = USBGEM_SPD_100;
		dp->full_duplex = B_FALSE;
	} else {
		dp->speed = USBGEM_SPD_10;
		dp->full_duplex = dp->anadv_10fdx;
	}
}

static uint16_t
usbgem_mii_read(struct usbgem_dev *dp, uint_t reg, int *errp)
{
	uint16_t	val;

	sema_p(&dp->hal_op_lock);
	val = (*dp->ugc.usbgc_mii_read)(dp, reg, errp);
	sema_v(&dp->hal_op_lock);

	return (val);
}

static void
usbgem_mii_write(struct usbgem_dev *dp, uint_t reg, uint16_t val, int *errp)
{
	sema_p(&dp->hal_op_lock);
	(*dp->ugc.usbgc_mii_write)(dp, reg, val, errp);
	sema_v(&dp->hal_op_lock);
}

static int
usbgem_mii_probe(struct usbgem_dev *dp)
{
	int	err;

	err = (*dp->ugc.usbgc_mii_probe)(dp);
	return (err);
}

static int
usbgem_mii_init(struct usbgem_dev *dp)
{
	int	err;

	err = (*dp->ugc.usbgc_mii_init)(dp);
	return (err);
}

#define	fc_cap_decode(x)	\
	((((x) & MII_ABILITY_PAUSE) != 0 ? 1 : 0) |	\
	(((x) & MII_ABILITY_ASM_DIR) != 0 ? 2 : 0))

int
usbgem_mii_config_default(struct usbgem_dev *dp, int *errp)
{
	uint16_t	mii_stat;
	uint16_t	val;

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
		return (USB_FAILURE);
	}

	/* Do not change the rest of ability bits in advert reg */
	val = usbgem_mii_read(dp, MII_AN_ADVERT, errp) & ~MII_ABILITY_ALL;
	if (*errp != USB_SUCCESS) {
		goto usberr;
	}

	DPRINTF(0, (CE_CONT,
	    "!%s: %s: 100T4:%d 100F:%d 100H:%d 10F:%d 10H:%d",
	    dp->name, __func__,
	    dp->anadv_100t4, dp->anadv_100fdx, dp->anadv_100hdx,
	    dp->anadv_10fdx, dp->anadv_10hdx));

	/* set technology bits */
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

	/* set flow control capabilities */
	if (dp->anadv_pause) {
		val |= MII_ABILITY_PAUSE;
	}
	if (dp->anadv_asmpause) {
		val |= MII_ABILITY_ASM_DIR;
	}

	DPRINTF(0, (CE_CONT,
	    "!%s: %s: setting MII_AN_ADVERT reg:%b, pause:%d, asmpause:%d",
	    dp->name, __func__, val, MII_ABILITY_BITS,
	    dp->anadv_pause, dp->anadv_asmpause));

	usbgem_mii_write(dp, MII_AN_ADVERT, val, errp);
	if (*errp != USB_SUCCESS) {
		goto usberr;
	}

	if (dp->mii_status & MII_STATUS_XSTATUS) {
		/*
		 * 1000Base-T GMII support
		 */
		if (!dp->anadv_autoneg) {
			/* enable manual configuration */
			val = MII_1000TC_CFG_EN;
			if (dp->anadv_1000t_ms == 2) {
				val |= MII_1000TC_CFG_VAL;
			}
		} else {
			val = 0;
			if (dp->anadv_1000fdx) {
				val |= MII_1000TC_ADV_FULL;
			}
			if (dp->anadv_1000hdx) {
				val |= MII_1000TC_ADV_HALF;
			}
			switch (dp->anadv_1000t_ms) {
			case 1:
				/* slave */
				val |= MII_1000TC_CFG_EN;
				break;

			case 2:
				/* master */
				val |= MII_1000TC_CFG_EN | MII_1000TC_CFG_VAL;
				break;

			default:
				/* auto: do nothing */
				break;
			}
		}
		DPRINTF(0, (CE_CONT,
		    "!%s: %s: setting MII_1000TC reg:%b",
		    dp->name, __func__, val, MII_1000TC_BITS));

		usbgem_mii_write(dp, MII_1000TC, val, errp);
		if (*errp != USB_SUCCESS) {
			goto usberr;
		}
	}
	return (USB_SUCCESS);

usberr:
	return (*errp);
}

static char *usbgem_fc_type[] = {
	"without",
	"with symmetric",
	"with tx",
	"with rx",
};

#ifdef USBGEM_CONFIG_GLDv3
#define	USBGEM_LINKUP(dp)	mac_link_update((dp)->mh, LINK_STATE_UP)
#define	USBGEM_LINKDOWN(dp)	mac_link_update((dp)->mh, LINK_STATE_DOWN)
#else
#define	USBGEM_LINKUP(dp)	\
	if (gld_linkstate) {	\
		gld_linkstate((dp)->macinfo, GLD_LINKSTATE_UP);	\
	}
#define	USBGEM_LINKDOWN(dp)	\
	if (gld_linkstate) {	\
		gld_linkstate((dp)->macinfo, GLD_LINKSTATE_DOWN);	\
	}
#endif

static uint8_t usbgem_fc_result[4 /* my cap */][4 /* lp cap */] = {
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

static boolean_t
usbgem_mii_link_check(struct usbgem_dev *dp, int *oldstatep, int *newstatep)
{
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
	int		err;
	uint_t		rwlock;

	DPRINTF(4, (CE_CONT, "!%s: %s: time:%d state:%d",
	    dp->name, __func__, ddi_get_lbolt(), dp->mii_state));

	if (dp->mii_state != MII_STATE_LINKUP) {
		rwlock = RW_WRITER;
	} else {
		rwlock = RW_READER;
	}
again:
	rw_enter(&dp->dev_state_lock, rwlock);

	/* save old mii state */
	*oldstatep = dp->mii_state;

	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		/* stop periodic execution of the link watcher */
		dp->mii_interval = 0;
		tx_sched = B_FALSE;
		goto next;
	}

	now = ddi_get_lbolt();
	diff = now - dp->mii_last_check;
	dp->mii_last_check = now;

	/*
	 * For NWAM, don't show linkdown state right
	 * when the device is attached.
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
		goto reset_phy;

	case MII_STATE_RESETTING:
		dp->mii_timer -= diff;
		if (dp->mii_timer > 0) {
			/* don't read phy registers in resetting */
			dp->mii_interval = WATCH_INTERVAL_FAST;
			goto next;
		}

		val = usbgem_mii_read(dp, MII_CONTROL, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
		if (val & MII_CONTROL_RESET) {
			cmn_err(CE_NOTE,
			    "!%s: time:%ld resetting phy not complete."
			    " mii_control:0x%b",
			    dp->name, ddi_get_lbolt(),
			    val, MII_CONTROL_BITS);
		}

		/* ensure neither isolated nor pwrdown nor auto-nego mode */
		usbgem_mii_write(dp, MII_CONTROL, 0, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
#if USBGEM_DEBUG_LEVEL > 10
		val = usbgem_mii_read(dp, MII_CONTROL, &err);
		cmn_err(CE_CONT, "!%s: readback control %b",
		    dp->name, val, MII_CONTROL_BITS);
#endif
		/* As resetting PHY has completed, configure PHY registers */
		if ((*dp->ugc.usbgc_mii_config)(dp, &err) != USB_SUCCESS) {
			/* we failed to configure PHY */
			goto usberr;
		}

		/* prepare for forced mode */
		usbgem_choose_forcedmode(dp);

		dp->mii_lpable = 0;
		dp->mii_advert = 0;
		dp->mii_exp = 0;
		dp->mii_ctl1000 = 0;
		dp->mii_stat1000 = 0;

		dp->flow_control = FLOW_CONTROL_NONE;

		if (!dp->anadv_autoneg) {
			/* skip auto-negotiation phase */
			dp->mii_state = MII_STATE_MEDIA_SETUP;
			dp->mii_timer = dp->ugc.usbgc_mii_linkdown_timeout;
			goto next_nowait;
		}

		/* issue an auto-negotiation command */
		goto autonego;

	case MII_STATE_AUTONEGOTIATING:
		/*
		 * Autonegotiation in progress
		 */
		dp->mii_timer -= diff;
		if (dp->mii_timer -
		    (dp->ugc.usbgc_mii_an_timeout - dp->ugc.usbgc_mii_an_wait)
		    > 0) {
			/* wait for minimum time (2.3 - 2.5 sec) */
			dp->mii_interval = WATCH_INTERVAL_FAST;
			goto next;
		}

		/* read PHY status */
		status = usbgem_mii_read(dp, MII_STATUS, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
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
				 * Auto-negotiation has been timed out,
				 * Reset PHY and try again.
				 */
				if (!dp->mii_supress_msg) {
					cmn_err(CE_WARN,
					    "!%s: auto-negotiation failed:"
					    " timeout",
					    dp->name);
					dp->mii_supress_msg = B_TRUE;
				}
				goto autonego;
			}
			/*
			 * Auto-negotiation is in progress. Wait for a while.
			 */
			dp->mii_interval = dp->ugc.usbgc_mii_an_watch_interval;
			goto next;
		}

		/*
		 * Auto-negotiation has been completed. Let's go to AN_DONE.
		 */
		dp->mii_state = MII_STATE_AN_DONE;
		dp->mii_supress_msg = B_FALSE;
		DPRINTF(0, (CE_CONT,
		    "!%s: auto-negotiation completed, MII_STATUS:%b",
		    dp->name, status, MII_STATUS_BITS));

		if (dp->ugc.usbgc_mii_an_delay > 0) {
			dp->mii_timer = dp->ugc.usbgc_mii_an_delay;
			dp->mii_interval = drv_usectohz(20*1000);
			goto next;
		}

		dp->mii_timer = 0;
		diff = 0;
		goto next_nowait;

	case MII_STATE_AN_DONE:
		/*
		 * Auto-negotiation has done. Now we can set up media.
		 */
		dp->mii_timer -= diff;
		if (dp->mii_timer > 0) {
			/* wait for a while */
			dp->mii_interval = WATCH_INTERVAL_FAST;
			goto next;
		}

		/*
		 * Setup speed and duplex mode according with
		 * the result of auto negotiation.
		 */

		/*
		 * Read registers required to determin current
		 * duplex mode and media speed.
		 */
		if (dp->ugc.usbgc_mii_an_delay > 0) {
			/* the 'status' variable is not initialized yet */
			status = usbgem_mii_read(dp, MII_STATUS, &err);
			if (err != USB_SUCCESS) {
				goto usberr;
			}
		}
		advert = usbgem_mii_read(dp, MII_AN_ADVERT, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
		lpable = usbgem_mii_read(dp, MII_AN_LPABLE, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
		exp = usbgem_mii_read(dp, MII_AN_EXPANSION, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
		if (exp == 0xffff) {
			/* some phys don't have exp register */
			exp = 0;
		}

		ctl1000 = 0;
		stat1000 = 0;
		if (dp->mii_status & MII_STATUS_XSTATUS) {
			ctl1000 = usbgem_mii_read(dp, MII_1000TC, &err);
			if (err != USB_SUCCESS) {
				goto usberr;
			}
			stat1000 = usbgem_mii_read(dp, MII_1000TS, &err);
			if (err != USB_SUCCESS) {
				goto usberr;
			}
		}
		dp->mii_lpable = lpable;
		dp->mii_advert = advert;
		dp->mii_exp = exp;
		dp->mii_ctl1000 = ctl1000;
		dp->mii_stat1000 = stat1000;

		cmn_err(CE_CONT,
		    "!%s: auto-negotiation done: "
		    "status:%b, advert:%b, lpable:%b, exp:%b",
		    dp->name,
		    status, MII_STATUS_BITS,
		    advert, MII_ABILITY_BITS,
		    lpable, MII_ABILITY_BITS,
		    exp, MII_AN_EXP_BITS);

		DPRINTF(0, (CE_CONT, "!%s: MII_STATUS:%b",
		    dp->name, status, MII_STATUS_BITS));

		if (dp->mii_status & MII_STATUS_XSTATUS) {
			cmn_err(CE_CONT,
			    "! MII_1000TC reg:%b, MII_1000TS reg:%b",
			    ctl1000, MII_1000TC_BITS,
			    stat1000, MII_1000TS_BITS);
		}

		if (usbgem_population(lpable) <= 1 &&
		    (exp & MII_AN_EXP_LPCANAN) == 0) {
			if ((advert & MII_ABILITY_TECH) != lpable) {
				cmn_err(CE_WARN,
				    "!%s: but the link partner doesn't seem"
				    " to have auto-negotiation capability."
				    " please check the link configuration.",
				    dp->name);
			}
			/*
			 * it should be a result of pararell detection,
			 * which cannot detect duplex mode.
			 */
			if ((advert & lpable) == 0 &&
			    lpable & MII_ABILITY_10BASE_T) {
				/* no common technology, try 10M half mode */
				lpable |= advert & MII_ABILITY_10BASE_T;
				fix_phy = B_TRUE;
			}
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
			dp->speed = USBGEM_SPD_1000;
			dp->full_duplex = B_TRUE;
		} else if ((ctl1000 & MII_1000TC_ADV_HALF) &&
		    (stat1000 & MII_1000TS_LP_HALF)) {
			/* 1000BaseT & half duplex */
			dp->speed = USBGEM_SPD_1000;
			dp->full_duplex = B_FALSE;
		} else if ((val & MII_ABILITY_100BASE_TX_FD)) {
			/* 100BaseTx & fullduplex */
			dp->speed = USBGEM_SPD_100;
			dp->full_duplex = B_TRUE;
		} else if ((val & MII_ABILITY_100BASE_T4)) {
			/* 100BaseTx & fullduplex */
			dp->speed = USBGEM_SPD_100;
			dp->full_duplex = B_TRUE;
		} else if ((val & MII_ABILITY_100BASE_TX)) {
			/* 100BaseTx & half duplex */
			dp->speed = USBGEM_SPD_100;
			dp->full_duplex = B_FALSE;
		} else if ((val & MII_ABILITY_10BASE_T_FD)) {
			/* 10BaseT & full duplex */
			dp->speed = USBGEM_SPD_10;
			dp->full_duplex = B_TRUE;
		} else if ((val & MII_ABILITY_10BASE_T)) {
			/* 10BaseT & half duplex */
			dp->speed = USBGEM_SPD_10;
			dp->full_duplex = B_FALSE;
		} else {
			/*
			 * the link partner doesn't seem to have
			 * auto-negotiation capability and our PHY
			 * could not report current mode correctly.
			 * We guess current mode by mii_control register.
			 */
			val = usbgem_mii_read(dp, MII_CONTROL, &err);
			if (err != USB_SUCCESS) {
				goto usberr;
			}

			/* select 100m half or 10m half */
			dp->speed = (val & MII_CONTROL_100MB) ?
			    USBGEM_SPD_100 : USBGEM_SPD_10;
			dp->full_duplex = B_FALSE;
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
			    usbgem_speed_value[dp->speed],
			    dp->full_duplex ? "full" : "half");
		}

		if (dp->full_duplex) {
			dp->flow_control =
			    usbgem_fc_result[fc_cap_decode(advert)]
			    [fc_cap_decode(lpable)];
		} else {
			dp->flow_control = FLOW_CONTROL_NONE;
		}
		dp->mii_state = MII_STATE_MEDIA_SETUP;
		dp->mii_timer = dp->ugc.usbgc_mii_linkdown_timeout;
		goto next_nowait;

	case MII_STATE_MEDIA_SETUP:
		DPRINTF(2, (CE_CONT, "!%s: setup midia mode", dp->name));

		/* assume the link state is down */
		dp->mii_state = MII_STATE_LINKDOWN;
		dp->mii_supress_msg = B_FALSE;

		/* use short interval */
		dp->mii_interval = WATCH_INTERVAL_FAST;

		if ((!dp->anadv_autoneg) ||
		    dp->ugc.usbgc_mii_an_oneshot || fix_phy) {

			/*
			 * write the result of auto negotiation back.
			 */
			val = usbgem_mii_read(dp, MII_CONTROL, &err);
			if (err != USB_SUCCESS) {
				goto usberr;
			}
			val &= ~(MII_CONTROL_SPEED | MII_CONTROL_FDUPLEX |
			    MII_CONTROL_ANE   | MII_CONTROL_RSAN);

			if (dp->full_duplex) {
				val |= MII_CONTROL_FDUPLEX;
			}

			switch (dp->speed) {
			case USBGEM_SPD_1000:
				val |= MII_CONTROL_1000MB;
				break;

			case USBGEM_SPD_100:
				val |= MII_CONTROL_100MB;
				break;

			default:
				cmn_err(CE_WARN, "%s: unknown speed:%d",
				    dp->name, dp->speed);
				/* FALLTHROUGH */

			case USBGEM_SPD_10:
				/* for USBGEM_SPD_10, do nothing */
				break;
			}

			if (dp->mii_status & MII_STATUS_XSTATUS) {
				usbgem_mii_write(dp,
				    MII_1000TC, MII_1000TC_CFG_EN, &err);
				if (err != USB_SUCCESS) {
					goto usberr;
				}
			}
			usbgem_mii_write(dp, MII_CONTROL, val, &err);
			if (err != USB_SUCCESS) {
				goto usberr;
			}
		}
		/*
		 * XXX -- nic state should be one of
		 * NIC_STATE_DISCONNECTED
		 * NIC_STATE_STOPPED
		 * NIC_STATE_INITIALIZED
		 * NIC_STATE_ONLINE
		 */
		if (dp->nic_state >= NIC_STATE_INITIALIZED) {
			/* notify the result of autonegotiation to mac */
			if (usbgem_hal_set_media(dp) != USB_SUCCESS) {
				goto usberr;
			}
		}
		goto next_nowait;

	case MII_STATE_LINKDOWN:
		status = usbgem_mii_read(dp, MII_STATUS, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
		if (status & MII_STATUS_LINKUP) {
			/*
			 * Link is going up
			 */
			dp->mii_state = MII_STATE_LINKUP;
			dp->mii_supress_msg = B_FALSE;

			DPRINTF(0, (CE_CONT,
			    "!%s: link up detected: status:%b",
			    dp->name, status, MII_STATUS_BITS));

			/*
			 * MII_CONTROL_100MB and  MII_CONTROL_FDUPLEX are
			 * ignored when MII_CONTROL_ANE is set.
			 */
			cmn_err(CE_CONT,
			    "!%s: Link up: %d Mbps %s duplex %s flow control",
			    dp->name,
			    usbgem_speed_value[dp->speed],
			    dp->full_duplex ? "full" : "half",
			    usbgem_fc_type[dp->flow_control]);

			dp->mii_interval =
			    dp->ugc.usbgc_mii_link_watch_interval;

			if (dp->ugc.usbgc_mii_hw_link_detection &&
			    dp->nic_state == NIC_STATE_ONLINE) {
				dp->mii_interval = 0;
			}

			if (dp->nic_state == NIC_STATE_ONLINE) {
				if (dp->mac_state == MAC_STATE_INITIALIZED) {
					(void) usbgem_mac_start(dp);
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
				 * the link down timer expired.
				 * need to restart auto-negotiation.
				 */
				linkdown_action =
				    dp->ugc.usbgc_mii_linkdown_timeout_action;
				goto restart_autonego;
			}
		}
		/* don't change mii_state */
		goto next;

	case MII_STATE_LINKUP:
		if (rwlock == RW_READER) {
			/* first pass, read mii status */
			status = usbgem_mii_read(dp, MII_STATUS, &err);
			if (err != USB_SUCCESS) {
				goto usberr;
			}
		}
		if ((status & MII_STATUS_LINKUP) == 0) {
			/*
			 * Link is going down
			 */
			cmn_err(CE_NOTE,
			    "!%s: link down detected: status:%b",
			    dp->name, status, MII_STATUS_BITS);
			/*
			 * Acquire exclusive lock to change mii_state
			 */
			if (rwlock == RW_READER) {
				rwlock = RW_WRITER;
				rw_exit(&dp->dev_state_lock);
				goto again;
			}

			dp->mii_state = MII_STATE_LINKDOWN;
			dp->mii_timer = dp->ugc.usbgc_mii_linkdown_timeout;

			/*
			 * As we may change the state of the device,
			 * let us acquire exclusive lock for the state.
			 */
			if (dp->nic_state == NIC_STATE_ONLINE &&
			    dp->mac_state == MAC_STATE_ONLINE &&
			    dp->ugc.usbgc_mii_stop_mac_on_linkdown) {
				(void) usbgem_restart_nic(dp);
				/* drain tx */
				tx_sched = B_TRUE;
			}

			if (dp->anadv_autoneg) {
				/* need to restart auto-negotiation */
				linkdown_action =
				    dp->ugc.usbgc_mii_linkdown_action;
				goto restart_autonego;
			}
			/*
			 * don't use hw link down detection until the link
			 * status become stable for a while.
			 */
			dp->mii_interval =
			    dp->ugc.usbgc_mii_link_watch_interval;

			goto next;
		}

		/*
		 * still link up, no need to change mii_state
		 */
		if (dp->ugc.usbgc_mii_hw_link_detection &&
		    dp->nic_state == NIC_STATE_ONLINE) {
			/*
			 * no need to check link status periodicly
			 * if nic can generate interrupts when link go down.
			 */
			dp->mii_interval = 0;
		}
		goto next;
	}
	/* NOTREACHED */
	cmn_err(CE_PANIC, "!%s: %s: not reached", dp->name, __func__);

	/*
	 * Actions for new state.
	 */
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
		if (dp->ugc.usbgc_mii_an_oneshot) {
			goto autonego;
		}
		/* PHY will restart autonego automatically */
		dp->mii_state = MII_STATE_AUTONEGOTIATING;
		dp->mii_timer = dp->ugc.usbgc_mii_an_timeout;
		dp->mii_interval = dp->ugc.usbgc_mii_an_watch_interval;
		goto next;

	case MII_ACTION_RSA:
		if (!dp->mii_supress_msg) {
			cmn_err(CE_CONT, "!%s: restarting auto-negotiation",
			    dp->name);
		}
		dp->mii_supress_msg = B_TRUE;
		goto autonego;

	default:
		cmn_err(CE_PANIC, "!%s: unknowm linkdown action: %d",
		    dp->name, dp->ugc.usbgc_mii_linkdown_action);
		dp->mii_supress_msg = B_TRUE;
	}
	/* NOTREACHED */

reset_phy:
	if (!dp->mii_supress_msg) {
		cmn_err(CE_CONT, "!%s: resetting PHY", dp->name);
	}
	dp->mii_state = MII_STATE_RESETTING;
	dp->mii_timer = dp->ugc.usbgc_mii_reset_timeout;
	if (!dp->ugc.usbgc_mii_dont_reset) {
		usbgem_mii_write(dp, MII_CONTROL, MII_CONTROL_RESET, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
	}
	dp->mii_interval = WATCH_INTERVAL_FAST;
	goto next;

autonego:
	if (!dp->mii_supress_msg) {
		cmn_err(CE_CONT, "!%s: auto-negotiation started", dp->name);
	}
	dp->mii_state = MII_STATE_AUTONEGOTIATING;
	dp->mii_timer = dp->ugc.usbgc_mii_an_timeout;

	/* start/restart autoneg */
	val = usbgem_mii_read(dp, MII_CONTROL, &err) &
	    ~(MII_CONTROL_ISOLATE | MII_CONTROL_PWRDN | MII_CONTROL_RESET);
	if (err != USB_SUCCESS) {
		goto usberr;
	}
	if (val & MII_CONTROL_ANE) {
		val |= MII_CONTROL_RSAN;
	}
	usbgem_mii_write(dp, MII_CONTROL,
	    val | dp->ugc.usbgc_mii_an_cmd | MII_CONTROL_ANE, &err);
	if (err != USB_SUCCESS) {
		goto usberr;
	}

	dp->mii_interval = dp->ugc.usbgc_mii_an_watch_interval;
	goto next;

usberr:
	dp->mii_state = MII_STATE_UNKNOWN;
	dp->mii_interval = dp->ugc.usbgc_mii_link_watch_interval;
	tx_sched = B_TRUE;

next:
	*newstatep = dp->mii_state;
	rw_exit(&dp->dev_state_lock);
	return (tx_sched);
}

static void
usbgem_mii_link_watcher(struct usbgem_dev *dp)
{
	int		old_mii_state;
	int		new_mii_state;
	boolean_t	tx_sched;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	for (; ; ) {

		mutex_enter(&dp->link_watcher_lock);
		if (dp->mii_interval) {
			(void) cv_timedwait(&dp->link_watcher_wait_cv,
			    &dp->link_watcher_lock,
			    dp->mii_interval + ddi_get_lbolt());
		} else {
			cv_wait(&dp->link_watcher_wait_cv,
			    &dp->link_watcher_lock);
		}
		mutex_exit(&dp->link_watcher_lock);

		if (dp->link_watcher_stop) {
			break;
		}

		/* we block callbacks from disconnect/suspend and restart */
		tx_sched = usbgem_mii_link_check(dp,
		    &old_mii_state, &new_mii_state);

		/*
		 * gld v2 notifier functions are not able to
		 * be called with any locks in this layer.
		 */
		if (tx_sched) {
			/* kick potentially stopped downstream */
#ifdef USBGEM_CONFIG_GLDv3
			mac_tx_update(dp->mh);
#else
			gld_sched(dp->macinfo);
#endif
		}

		if (old_mii_state != new_mii_state) {
			/* notify new mii link state */
			if (new_mii_state == MII_STATE_LINKUP) {
				dp->linkup_delay = 0;
				USBGEM_LINKUP(dp);
			} else if (dp->linkup_delay <= 0) {
				USBGEM_LINKDOWN(dp);
			}
		} else if (dp->linkup_delay < 0) {
			/* first linkup timeout */
			dp->linkup_delay = 0;
			USBGEM_LINKDOWN(dp);
		}
	}

	thread_exit();
}

void
usbgem_mii_update_link(struct usbgem_dev *dp)
{
	cv_signal(&dp->link_watcher_wait_cv);
}

int
usbgem_mii_probe_default(struct usbgem_dev *dp)
{
	int		phy;
	uint16_t	status;
	uint16_t	xstatus;
	int		err;
	uint16_t	adv;
	uint16_t	adv_org;

	DPRINTF(3, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/*
	 * Scan PHY
	 */
	dp->mii_status = 0;

	/* Try default phy first */
	if (dp->mii_phy_addr) {
		status = usbgem_mii_read(dp, MII_STATUS, &err);
		if (err != USB_SUCCESS) {
			goto usberr;
		}
		if (status != 0xffff && status != 0x0000) {
			goto PHY_found;
		}

		if (dp->mii_phy_addr < 0) {
			cmn_err(CE_NOTE,
		    "!%s: failed to probe default internal and/or non-MII PHY",
			    dp->name);
			return (USB_FAILURE);
		}

		cmn_err(CE_NOTE,
		    "!%s: failed to probe default MII PHY at %d",
		    dp->name, dp->mii_phy_addr);
	}

	/* Try all possible address */
	for (phy = dp->ugc.usbgc_mii_addr_min; phy < 32; phy++) {
		dp->mii_phy_addr = phy;
		status = usbgem_mii_read(dp, MII_STATUS, &err);
		if (err != USB_SUCCESS) {
			DPRINTF(0, (CE_CONT,
			    "!%s: %s: mii_read(status) failed",
			    dp->name, __func__));
			goto usberr;
		}

		if (status != 0xffff && status != 0x0000) {
			usbgem_mii_write(dp, MII_CONTROL, 0, &err);
			if (err != USB_SUCCESS) {
				DPRINTF(0, (CE_CONT,
				    "!%s: %s: mii_write(control) failed",
				    dp->name, __func__));
				goto usberr;
			}
			goto PHY_found;
		}
	}
	for (phy = dp->ugc.usbgc_mii_addr_min; phy < 32; phy++) {
		dp->mii_phy_addr = phy;
		usbgem_mii_write(dp, MII_CONTROL, 0, &err);
		if (err != USB_SUCCESS) {
			DPRINTF(0, (CE_CONT,
			    "!%s: %s: mii_write(control) failed",
			    dp->name, __func__));
			goto usberr;
		}
		status = usbgem_mii_read(dp, MII_STATUS, &err);
		if (err != USB_SUCCESS) {
			DPRINTF(0, (CE_CONT,
			    "!%s: %s: mii_read(status) failed",
			    dp->name, __func__));
			goto usberr;
		}

		if (status != 0xffff && status != 0) {
			goto PHY_found;
		}
	}

	cmn_err(CE_NOTE, "!%s: no MII PHY found", dp->name);
	return (USB_FAILURE);

PHY_found:
	dp->mii_status = status;
	dp->mii_status_ro = ~status;
	dp->mii_phy_id = usbgem_mii_read(dp, MII_PHYIDH, &err) << 16;
	if (err != USB_SUCCESS) {
		DPRINTF(0, (CE_CONT,
		    "!%s: %s: mii_read(PHYIDH) failed",
		    dp->name, __func__));
		goto usberr;
	}
	dp->mii_phy_id |= usbgem_mii_read(dp, MII_PHYIDL, &err);
	if (err != USB_SUCCESS) {
		DPRINTF(0, (CE_CONT,
		    "!%s: %s: mii_read(PHYIDL) failed",
		    dp->name, __func__));
		goto usberr;
	}

	if (dp->mii_phy_addr < 0) {
		cmn_err(CE_CONT, "!%s: using internal/non-MII PHY(0x%08x)",
		    dp->name, dp->mii_phy_id);
	} else {
		cmn_err(CE_CONT, "!%s: MII PHY (0x%08x) found at %d",
		    dp->name, dp->mii_phy_id, dp->mii_phy_addr);
	}

	cmn_err(CE_CONT,
	    "!%s: PHY control:%b, status:%b, advert:%b, lpar:%b, exp:%b",
	    dp->name,
	    usbgem_mii_read(dp, MII_CONTROL, &err), MII_CONTROL_BITS,
	    status, MII_STATUS_BITS,
	    usbgem_mii_read(dp, MII_AN_ADVERT, &err), MII_ABILITY_BITS,
	    usbgem_mii_read(dp, MII_AN_LPABLE, &err), MII_ABILITY_BITS,
	    usbgem_mii_read(dp, MII_AN_EXPANSION, &err), MII_AN_EXP_BITS);

	dp->mii_xstatus = 0;
	if (status & MII_STATUS_XSTATUS) {
		dp->mii_xstatus = usbgem_mii_read(dp, MII_XSTATUS, &err);

		cmn_err(CE_CONT, "!%s: xstatus:%b",
		    dp->name, dp->mii_xstatus, MII_XSTATUS_BITS);
	}
	dp->mii_xstatus_ro = ~dp->mii_xstatus;

	/* check if the phy can advertize pause abilities */
	adv_org = usbgem_mii_read(dp, MII_AN_ADVERT, &err);
	if (err != USB_SUCCESS) {
		goto usberr;
	}

	usbgem_mii_write(dp, MII_AN_ADVERT,
	    MII_ABILITY_PAUSE | MII_ABILITY_ASM_DIR, &err);
	if (err != USB_SUCCESS) {
		goto usberr;
	}

	adv = usbgem_mii_read(dp, MII_AN_ADVERT, &err);
	if (err != USB_SUCCESS) {
		goto usberr;
	}

	if ((adv & MII_ABILITY_PAUSE) == 0) {
		dp->ugc.usbgc_flow_control &= ~1;
	}

	if ((adv & MII_ABILITY_ASM_DIR) == 0) {
		dp->ugc.usbgc_flow_control &= ~2;
	}

	usbgem_mii_write(dp, MII_AN_ADVERT, adv_org, &err);
	if (err != USB_SUCCESS) {
		goto usberr;
	}
	return (USB_SUCCESS);

usberr:
	return (USB_FAILURE);
}

int
usbgem_mii_init_default(struct usbgem_dev *dp)
{
	/* ENPTY */
	return (USB_SUCCESS);
}

static int
usbgem_mii_start(struct usbgem_dev *dp)
{
	int	err;
	kthread_t	*lwth;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* make a first call of usbgem_mii_link_check() */
	dp->link_watcher_stop = 0;
	dp->mii_state = MII_STATE_UNKNOWN;
	dp->mii_interval = drv_usectohz(1000*1000); /* 1sec */
	dp->mii_last_check = ddi_get_lbolt();
	dp->linkup_delay = 600 * drv_usectohz(1000*1000); /* 10 minutes */

	lwth = thread_create(NULL, 0, usbgem_mii_link_watcher, dp, 0, &p0,
	    TS_RUN, minclsyspri);
	if (lwth == NULL) {
		cmn_err(CE_WARN,
		    "!%s: %s: failed to create a link watcher thread",
		    dp->name, __func__);
		return (USB_FAILURE);
	}
	dp->link_watcher_did = lwth->t_did;

	return (USB_SUCCESS);
}

static void
usbgem_mii_stop(struct usbgem_dev *dp)
{
	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* Ensure timer routine stopped */
	dp->link_watcher_stop = 1;
	cv_signal(&dp->link_watcher_wait_cv);
	thread_join(dp->link_watcher_did);
}

/* ============================================================== */
/*
 * internal mac register operation interface
 */
/* ============================================================== */
/*
 * usbgem_mac_init: cold start
 */
static int
usbgem_mac_init(struct usbgem_dev *dp)
{
	int	err;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		/* pretend we succeeded */
		return (USB_SUCCESS);
	}

	ASSERT(dp->mac_state == MAC_STATE_STOPPED);

	/* reset fatal error timestamp */
	dp->fatal_error = (clock_t)0;

	/* reset tx side state */
	mutex_enter(&dp->txlock);
	dp->tx_busy_cnt = 0;
	dp->tx_max_packets = dp->ugc.usbgc_tx_list_max;
	mutex_exit(&dp->txlock);

	/* reset rx side state */
	mutex_enter(&dp->rxlock);
	dp->rx_busy_cnt = 0;
	mutex_exit(&dp->rxlock);

	err = usbgem_hal_init_chip(dp);
	if (err == USB_SUCCESS) {
		dp->mac_state = MAC_STATE_INITIALIZED;
	}

	return (err);
}

/*
 * usbgem_mac_start: warm start
 */
static int
usbgem_mac_start(struct usbgem_dev *dp)
{
	int	err;
	int	i;
	usb_flags_t	flags = 0;
	usb_intr_req_t	*req;
#ifdef USBGEM_DEBUG_LEVEL
	usb_pipe_state_t	p_state;
#endif
	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		/* do nothing but don't return failure */
		return (USB_SUCCESS);
	}

	if (dp->mac_state != MAC_STATE_INITIALIZED) {
		/* don't return failer */
		DPRINTF(0, (CE_CONT,
		    "!%s: %s: mac_state(%d) is not MAC_STATE_INITIALIZED",
		    dp->name, __func__, dp->mac_state));
		goto x;
	}

	dp->mac_state = MAC_STATE_ONLINE;

	if (usbgem_hal_start_chip(dp) != USB_SUCCESS) {
		cmn_err(CE_NOTE,
		    "!%s: %s: usb error was detected during start_chip",
		    dp->name, __func__);
		goto x;
	}

#ifdef USBGEM_DEBUG_LEVEL
	usb_pipe_get_state(dp->intr_pipe, &p_state, 0);
	ASSERT(p_state == USB_PIPE_STATE_IDLE);
#endif /* USBGEM_DEBUG_LEVEL */

	if (dp->ugc.usbgc_interrupt && dp->intr_pipe) {

		/* make a request for interrupt */

		req = usb_alloc_intr_req(dp->dip, 0, USB_FLAGS_SLEEP);
		if (req == NULL) {
			cmn_err(CE_WARN, "!%s: %s: failed to allocate intreq",
			    dp->name, __func__);
			goto x;
		}
		req->intr_data = NULL;
		req->intr_client_private = (usb_opaque_t)dp;
		req->intr_timeout = 0;
		req->intr_attributes =
		    USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;
		req->intr_len = dp->ep_intr->wMaxPacketSize;
		req->intr_cb = usbgem_intr_cb;
		req->intr_exc_cb = usbgem_intr_cb;
		req->intr_completion_reason = 0;
		req->intr_cb_flags = 0;

		err = usb_pipe_intr_xfer(dp->intr_pipe, req, flags);
		if (err != USB_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s: err:%d failed to start polling of intr pipe",
			    dp->name, err);
			goto x;
		}
	}

	/* kick to receive the first packet */
	if (usbgem_init_rx_buf(dp) != USB_SUCCESS) {
		goto err_stop_intr;
	}
	dp->rx_active = B_TRUE;

	return (USB_SUCCESS);

err_stop_intr:
	/* stop the interrupt pipe */
	DPRINTF(0, (CE_CONT, "!%s: %s: FAULURE", dp->name, __func__));
	if (dp->ugc.usbgc_interrupt && dp->intr_pipe) {
		usb_pipe_stop_intr_polling(dp->intr_pipe, USB_FLAGS_SLEEP);
	}
x:
	ASSERT(dp->mac_state == MAC_STATE_ONLINE);
	/* we use another flag to indicate error state. */
	if (dp->fatal_error == (clock_t)0) {
		dp->fatal_error = usbgem_timestamp_nz();
	}
	return (USB_FAILURE);
}

static int
usbgem_mac_stop(struct usbgem_dev *dp, int new_state, boolean_t graceful)
{
	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/*
	 * we must have writer lock for dev_state_lock
	 */
	ASSERT(new_state == MAC_STATE_STOPPED ||
	    new_state == MAC_STATE_DISCONNECTED);

	/* stop polling interrupt pipe */
	if (dp->ugc.usbgc_interrupt && dp->intr_pipe) {
		usb_pipe_stop_intr_polling(dp->intr_pipe, USB_FLAGS_SLEEP);
	}

	if (new_state == MAC_STATE_STOPPED || graceful) {
		/* stop the nic hardware completely */
		if (usbgem_hal_stop_chip(dp) != USB_SUCCESS) {
			(void) usbgem_hal_reset_chip(dp);
		}
	}

	/* stop preparing new rx packets and sending new packets */
	dp->mac_state = new_state;

	/* other processors must get mac_state correctly after here */
	membar_producer();

	/* cancel all requests we have sent */
	usb_pipe_reset(dp->dip, dp->bulkin_pipe, USB_FLAGS_SLEEP, NULL, 0);
	usb_pipe_reset(dp->dip, dp->bulkout_pipe, USB_FLAGS_SLEEP, NULL, 0);

	DPRINTF(0, (CE_CONT,
	    "!%s: %s: rx_busy_cnt:%d tx_busy_cnt:%d",
	    dp->name, __func__, dp->rx_busy_cnt, dp->tx_busy_cnt));

	/*
	 * Here all rx packets has been cancelled and their call back
	 * function has been exeuted, because we called usb_pipe_reset
	 * synchronously.
	 * So actually we just ensure rx_busy_cnt == 0.
	 */
	mutex_enter(&dp->rxlock);
	while (dp->rx_busy_cnt > 0) {
		cv_wait(&dp->rx_drain_cv, &dp->rxlock);
	}
	mutex_exit(&dp->rxlock);

	DPRINTF(0, (CE_CONT, "!%s: %s: rx_busy_cnt is %d now",
	    dp->name, __func__, dp->rx_busy_cnt));

	mutex_enter(&dp->txlock);
	while (dp->tx_busy_cnt > 0) {
		cv_wait(&dp->tx_drain_cv, &dp->txlock);
	}
	mutex_exit(&dp->txlock);

	DPRINTF(0, (CE_CONT, "!%s: %s: tx_busy_cnt is %d now",
	    dp->name, __func__, dp->tx_busy_cnt));

	return (USB_SUCCESS);
}

static int
usbgem_add_multicast(struct usbgem_dev *dp, const uint8_t *ep)
{
	int	cnt;
	int	err;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	sema_p(&dp->rxfilter_lock);
	if (dp->mc_count_req++ < USBGEM_MAXMC) {
		/* append the new address at the end of the mclist */
		cnt = dp->mc_count;
		bcopy(ep, dp->mc_list[cnt].addr.ether_addr_octet,
		    ETHERADDRL);
		if (dp->ugc.usbgc_multicast_hash) {
			dp->mc_list[cnt].hash =
			    (*dp->ugc.usbgc_multicast_hash)(dp, ep);
		}
		dp->mc_count = cnt + 1;
	}

	if (dp->mc_count_req != dp->mc_count) {
		/* multicast address list overflow */
		dp->rxmode |= RXMODE_MULTI_OVF;
	} else {
		dp->rxmode &= ~RXMODE_MULTI_OVF;
	}

	if (dp->mac_state != MAC_STATE_DISCONNECTED) {
		/* tell new multicast list to the hardware */
		err = usbgem_hal_set_rx_filter(dp);
	}
	sema_v(&dp->rxfilter_lock);

	return (err);
}

static int
usbgem_remove_multicast(struct usbgem_dev *dp, const uint8_t *ep)
{
	size_t		len;
	int		i;
	int		cnt;
	int		err;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	sema_p(&dp->rxfilter_lock);
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

	if (dp->mac_state != MAC_STATE_DISCONNECTED) {
		err = usbgem_hal_set_rx_filter(dp);
	}
	sema_v(&dp->rxfilter_lock);

	return (err);
}


/* ============================================================== */
/*
 * ioctl
 */
/* ============================================================== */
enum ioc_reply {
	IOC_INVAL = -1,				/* bad, NAK with EINVAL	*/
	IOC_DONE,				/* OK, reply sent	*/
	IOC_ACK,				/* OK, just send ACK	*/
	IOC_REPLY,				/* OK, just send reply	*/
	IOC_RESTART_ACK,			/* OK, restart & ACK	*/
	IOC_RESTART_REPLY			/* OK, restart & reply	*/
};


#ifdef USBGEM_CONFIG_MAC_PROP
static int
usbgem_get_def_val(struct usbgem_dev *dp, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	link_flowctrl_t fl;
	int err = 0;

	ASSERT(pr_valsize > 0);
	switch (pr_num) {
	case MAC_PROP_AUTONEG:
		*(uint8_t *)pr_val =
		    BOOLEAN(dp->mii_status & MII_STATUS_CANAUTONEG);
		break;

	case MAC_PROP_FLOWCTRL:
		if (pr_valsize < sizeof (link_flowctrl_t)) {
			return (EINVAL);
		}
		switch (dp->ugc.usbgc_flow_control) {
		case FLOW_CONTROL_NONE:
			fl = LINK_FLOWCTRL_NONE;
			break;
		case FLOW_CONTROL_SYMMETRIC:
			fl = LINK_FLOWCTRL_BI;
			break;
		case FLOW_CONTROL_TX_PAUSE:
			fl = LINK_FLOWCTRL_TX;
			break;
		case FLOW_CONTROL_RX_PAUSE:
			fl = LINK_FLOWCTRL_RX;
			break;
		}
		bcopy(&fl, pr_val, sizeof (fl));
		break;

	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
		*(uint8_t *)pr_val =
		    (dp->mii_xstatus & MII_XSTATUS_1000BASET_FD) ||
		    (dp->mii_xstatus & MII_XSTATUS_1000BASEX_FD);
		break;

	case MAC_PROP_ADV_1000HDX_CAP:
	case MAC_PROP_EN_1000HDX_CAP:
		*(uint8_t *)pr_val =
		    (dp->mii_xstatus & MII_XSTATUS_1000BASET) ||
		    (dp->mii_xstatus & MII_XSTATUS_1000BASEX);
		break;

	case MAC_PROP_ADV_100T4_CAP:
	case MAC_PROP_EN_100T4_CAP:
		*(uint8_t *)pr_val =
		    BOOLEAN(dp->mii_status & MII_STATUS_100_BASE_T4);
		break;

	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
		*(uint8_t *)pr_val =
		    BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX_FD);
		break;

	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_EN_100HDX_CAP:
		*(uint8_t *)pr_val =
		    BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX);
		break;

	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_EN_10FDX_CAP:
		*(uint8_t *)pr_val =
		    BOOLEAN(dp->mii_status & MII_STATUS_10_FD);
		break;

	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_EN_10HDX_CAP:
		*(uint8_t *)pr_val =
		    BOOLEAN(dp->mii_status & MII_STATUS_10);
		break;

	default:
		err = ENOTSUP;
		break;
	}
	return (err);
}

#ifdef MAC_VERSION_V1
static void
usbgem_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	struct usbgem_dev *dp = arg;
	link_flowctrl_t fl;

	/*
	 * By default permissions are read/write unless specified
	 * otherwise by the driver.
	 */

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_1000HDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_ADV_100T4_CAP:
	case MAC_PROP_EN_100T4_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_1000FDX_CAP:
		if ((dp->mii_xstatus_ro & MII_XSTATUS_1000BASET_FD) == 0) {
			mac_prop_info_set_default_uint8(prh,
			    BOOLEAN(
			    dp->mii_xstatus & MII_XSTATUS_1000BASET_FD));
		} else if ((dp->mii_xstatus_ro & MII_XSTATUS_1000BASEX_FD)
		    == 0) {
			mac_prop_info_set_default_uint8(prh,
			    BOOLEAN(
			    dp->mii_xstatus & MII_XSTATUS_1000BASEX_FD));
		} else {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		}
		break;

	case MAC_PROP_EN_1000HDX_CAP:
		if ((dp->mii_xstatus_ro & MII_XSTATUS_1000BASET) == 0) {
			mac_prop_info_set_default_uint8(prh,
			    BOOLEAN(
			    dp->mii_xstatus & MII_XSTATUS_1000BASET));
		} else if ((dp->mii_xstatus_ro & MII_XSTATUS_1000BASEX) == 0) {
			mac_prop_info_set_default_uint8(prh,
			    BOOLEAN(
			    dp->mii_xstatus & MII_XSTATUS_1000BASEX));
		} else {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		}
		break;

	case MAC_PROP_EN_100FDX_CAP:
		if ((dp->mii_status_ro & MII_STATUS_100_BASEX_FD) == 0) {
			mac_prop_info_set_default_uint8(prh,
			    BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX_FD));
		} else {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		}
		break;

	case MAC_PROP_EN_100HDX_CAP:
		if ((dp->mii_status_ro & MII_STATUS_100_BASEX) == 0) {
			mac_prop_info_set_default_uint8(prh,
			    BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX));
		} else {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		}
		break;

	case MAC_PROP_EN_10FDX_CAP:
		if ((dp->mii_status_ro & MII_STATUS_10_FD) == 0) {
			mac_prop_info_set_default_uint8(prh,
			    BOOLEAN(dp->mii_status & MII_STATUS_10_FD));
		} else {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		}
		break;

	case MAC_PROP_EN_10HDX_CAP:
		if ((dp->mii_status_ro & MII_STATUS_10) == 0) {
			mac_prop_info_set_default_uint8(prh,
			    BOOLEAN(dp->mii_status & MII_STATUS_10));
		} else {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		}
		break;

	case MAC_PROP_AUTONEG:
		if ((dp->mii_status_ro & MII_STATUS_CANAUTONEG) == 0) {
			mac_prop_info_set_default_uint8(prh,
			    BOOLEAN(dp->mii_status & MII_STATUS_CANAUTONEG));
		} else {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		}
		break;

	case MAC_PROP_FLOWCTRL:
		switch (dp->ugc.usbgc_flow_control) {
		case FLOW_CONTROL_NONE:
			fl = LINK_FLOWCTRL_NONE;
			break;
		case FLOW_CONTROL_SYMMETRIC:
			fl = LINK_FLOWCTRL_BI;
			break;
		case FLOW_CONTROL_TX_PAUSE:
			fl = LINK_FLOWCTRL_TX;
			break;
		case FLOW_CONTROL_RX_PAUSE:
			fl = LINK_FLOWCTRL_RX;
			break;
		}
		mac_prop_info_set_default_link_flowctrl(prh, fl);
		break;

	case MAC_PROP_MTU:
		mac_prop_info_set_range_uint32(prh,
		    dp->ugc.usbgc_min_mtu, dp->ugc.usbgc_max_mtu);
		break;

	case MAC_PROP_PRIVATE:
		break;
	}
}
#endif

static int
usbgem_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	struct usbgem_dev *dp = arg;
	int err = 0;
	boolean_t	update = B_FALSE;
	link_flowctrl_t flowctrl;
	uint32_t cur_mtu, new_mtu;

	rw_enter(&dp->dev_state_lock, RW_WRITER);
	switch (pr_num) {
	case MAC_PROP_EN_1000FDX_CAP:
		if ((dp->mii_xstatus_ro & MII_XSTATUS_1000BASET_FD) == 0 ||
		    (dp->mii_xstatus_ro & MII_XSTATUS_1000BASEX_FD) == 0) {
			if (dp->anadv_1000fdx != *(uint8_t *)pr_val) {
				dp->anadv_1000fdx = *(uint8_t *)pr_val;
				update = B_TRUE;
			}
		} else {
			err = ENOTSUP;
		}
		break;

	case MAC_PROP_EN_1000HDX_CAP:
		if ((dp->mii_xstatus_ro & MII_XSTATUS_1000BASET) == 0 ||
		    (dp->mii_xstatus_ro & MII_XSTATUS_1000BASEX) == 0) {
			if (dp->anadv_1000hdx != *(uint8_t *)pr_val) {
				dp->anadv_1000hdx = *(uint8_t *)pr_val;
				update = B_TRUE;
			}
		} else {
			err = ENOTSUP;
		}
		break;

	case MAC_PROP_EN_100FDX_CAP:
		if ((dp->mii_status_ro & MII_STATUS_100_BASEX_FD) == 0) {
			if (dp->anadv_100fdx != *(uint8_t *)pr_val) {
				dp->anadv_100fdx = *(uint8_t *)pr_val;
				update = B_TRUE;
			}
		} else {
			err = ENOTSUP;
		}
		break;

	case MAC_PROP_EN_100HDX_CAP:
		if ((dp->mii_status_ro & MII_STATUS_100_BASEX) == 0) {
			if (dp->anadv_100hdx != *(uint8_t *)pr_val) {
				dp->anadv_100hdx = *(uint8_t *)pr_val;
				update = B_TRUE;
			}
		} else {
			err = ENOTSUP;
		}
		break;

	case MAC_PROP_EN_10FDX_CAP:
		if ((dp->mii_status_ro & MII_STATUS_10_FD) == 0) {
			if (dp->anadv_10fdx != *(uint8_t *)pr_val) {
				dp->anadv_10fdx = *(uint8_t *)pr_val;
				update = B_TRUE;
			}
		} else {
			err = ENOTSUP;
		}
		break;

	case MAC_PROP_EN_10HDX_CAP:
		if ((dp->mii_status_ro & MII_STATUS_10_FD) == 0) {
			if (dp->anadv_10hdx != *(uint8_t *)pr_val) {
				dp->anadv_10hdx = *(uint8_t *)pr_val;
				update = B_TRUE;
			}
		} else {
			err = ENOTSUP;
		}
		break;

	case MAC_PROP_AUTONEG:
		if ((dp->mii_status_ro & MII_STATUS_CANAUTONEG) == 0) {
			if (dp->anadv_autoneg != *(uint8_t *)pr_val) {
				dp->anadv_autoneg = *(uint8_t *)pr_val;
				update = B_TRUE;
			}
		} else {
			err = ENOTSUP;
		}
		break;

	case MAC_PROP_FLOWCTRL:
		bcopy(pr_val, &flowctrl, sizeof (flowctrl));

		switch (flowctrl) {
		default:
			err = EINVAL;
			break;

		case LINK_FLOWCTRL_NONE:
			if (dp->flow_control != FLOW_CONTROL_NONE) {
				dp->flow_control = FLOW_CONTROL_NONE;
				update = B_TRUE;
			}
			break;

		case LINK_FLOWCTRL_RX:
			if (dp->flow_control != FLOW_CONTROL_RX_PAUSE) {
				dp->flow_control = FLOW_CONTROL_RX_PAUSE;
				update = B_TRUE;
			}
			break;

		case LINK_FLOWCTRL_TX:
			if (dp->flow_control != FLOW_CONTROL_TX_PAUSE) {
				dp->flow_control = FLOW_CONTROL_TX_PAUSE;
				update = B_TRUE;
			}
			break;

		case LINK_FLOWCTRL_BI:
			if (dp->flow_control != FLOW_CONTROL_SYMMETRIC) {
				dp->flow_control = FLOW_CONTROL_SYMMETRIC;
				update = B_TRUE;
			}
			break;
		}
		break;

	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_1000HDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_STATUS:
	case MAC_PROP_SPEED:
	case MAC_PROP_DUPLEX:
		err = ENOTSUP; /* read-only prop. Can't set this. */
		break;

	case MAC_PROP_MTU:
		bcopy(pr_val, &new_mtu, sizeof (new_mtu));
		if (new_mtu != dp->mtu) {
			err = EINVAL;
		}
		break;

	case MAC_PROP_PRIVATE:
		err = ENOTSUP;
		break;

	default:
		err = ENOTSUP;
		break;
	}

	if (update) {
		/* sync with PHY */
		usbgem_choose_forcedmode(dp);
		dp->mii_state = MII_STATE_UNKNOWN;
		cv_signal(&dp->link_watcher_wait_cv);
	}
	rw_exit(&dp->dev_state_lock);
	return (err);
}

static int
#ifdef MAC_VERSION_V1
usbgem_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
#else
usbgem_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_flags, uint_t pr_valsize, void *pr_val, uint_t *perm)
#endif
{
	struct usbgem_dev *dp = arg;
	int err = 0;
	link_flowctrl_t flowctrl;
	uint64_t tmp = 0;

	if (pr_valsize == 0) {
		return (EINVAL);
	}
#ifndef MAC_VERSION_V1
	*perm = MAC_PROP_PERM_RW;
#endif
	bzero(pr_val, pr_valsize);
#ifndef MAC_VERSION_V1
	if ((pr_flags & MAC_PROP_DEFAULT) && (pr_num != MAC_PROP_PRIVATE)) {
		return (usbgem_get_def_val(dp, pr_num, pr_valsize, pr_val));
	}
#endif
	rw_enter(&dp->dev_state_lock, RW_READER);
	switch (pr_num) {
	case MAC_PROP_DUPLEX:
#ifndef MAC_VERSION_V1
		*perm = MAC_PROP_PERM_READ;
#endif
		if (pr_valsize >= sizeof (link_duplex_t)) {
			if (dp->mii_state != MII_STATE_LINKUP) {
				*(link_duplex_t *)pr_val = LINK_DUPLEX_UNKNOWN;
			} else if (dp->full_duplex) {
				*(link_duplex_t *)pr_val = LINK_DUPLEX_FULL;
			} else {
				*(link_duplex_t *)pr_val = LINK_DUPLEX_HALF;
			}
		} else {
			err = EINVAL;
		}
		break;
	case MAC_PROP_SPEED:
#ifndef MAC_VERSION_V1
		*perm = MAC_PROP_PERM_READ;
#endif
		if (pr_valsize >= sizeof (uint64_t)) {
			switch (dp->speed) {
			case USBGEM_SPD_1000:
				tmp = 1000000000;
				break;
			case USBGEM_SPD_100:
				tmp = 100000000;
				break;
			case USBGEM_SPD_10:
				tmp = 10000000;
				break;
			default:
				tmp = 0;
			}
			bcopy(&tmp, pr_val, sizeof (tmp));
		} else {
			err = EINVAL;
		}
		break;

	case MAC_PROP_AUTONEG:
#ifndef MAC_VERSION_V1
		if (dp->mii_status_ro & MII_STATUS_CANAUTONEG) {
			*perm = MAC_PROP_PERM_READ;
		}
#endif
		*(uint8_t *)pr_val = dp->anadv_autoneg;
		break;

	case MAC_PROP_FLOWCTRL:
		if (pr_valsize >= sizeof (link_flowctrl_t)) {
			switch (dp->flow_control) {
			case FLOW_CONTROL_NONE:
				flowctrl = LINK_FLOWCTRL_NONE;
				break;
			case FLOW_CONTROL_RX_PAUSE:
				flowctrl = LINK_FLOWCTRL_RX;
				break;
			case FLOW_CONTROL_TX_PAUSE:
				flowctrl = LINK_FLOWCTRL_TX;
				break;
			case FLOW_CONTROL_SYMMETRIC:
				flowctrl = LINK_FLOWCTRL_BI;
				break;
			}
			bcopy(&flowctrl, pr_val, sizeof (flowctrl));
		} else {
			err = EINVAL;
		}
		break;

	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_1000HDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_ADV_100T4_CAP:
		usbgem_get_def_val(dp, pr_num, pr_valsize, pr_val);
		break;

	case MAC_PROP_EN_1000FDX_CAP:
#ifndef MAC_VERSION_V1
		if ((dp->mii_xstatus_ro & MII_XSTATUS_1000BASET_FD) &&
		    (dp->mii_xstatus_ro & MII_XSTATUS_1000BASEX_FD)) {
			*perm = MAC_PROP_PERM_READ;
		}
#endif
		*(uint8_t *)pr_val = dp->anadv_1000fdx;
		break;

	case MAC_PROP_EN_1000HDX_CAP:
#ifndef MAC_VERSION_V1
		if ((dp->mii_xstatus_ro & MII_XSTATUS_1000BASET) &&
		    (dp->mii_xstatus_ro & MII_XSTATUS_1000BASEX)) {
			*perm = MAC_PROP_PERM_READ;
		}
#endif
		*(uint8_t *)pr_val = dp->anadv_1000hdx;
		break;

	case MAC_PROP_EN_100FDX_CAP:
#ifndef MAC_VERSION_V1
		if (dp->mii_status_ro & MII_STATUS_100_BASEX_FD) {
			*perm = MAC_PROP_PERM_READ;
		}
#endif
		*(uint8_t *)pr_val = dp->anadv_100fdx;
		break;

	case MAC_PROP_EN_100HDX_CAP:
#ifndef MAC_VERSION_V1
		if (dp->mii_status_ro & MII_STATUS_100_BASEX) {
			*perm = MAC_PROP_PERM_READ;
		}
#endif
		*(uint8_t *)pr_val = dp->anadv_100hdx;
		break;

	case MAC_PROP_EN_10FDX_CAP:
#ifndef MAC_VERSION_V1
		if (dp->mii_status_ro & MII_STATUS_10_FD) {
			*perm = MAC_PROP_PERM_READ;
		}
#endif
		*(uint8_t *)pr_val = dp->anadv_10fdx;
		break;

	case MAC_PROP_EN_10HDX_CAP:
#ifndef MAC_VERSION_V1
		if (dp->mii_status_ro & MII_STATUS_10) {
			*perm = MAC_PROP_PERM_READ;
		}
#endif
		*(uint8_t *)pr_val = dp->anadv_10hdx;
		break;

	case MAC_PROP_EN_100T4_CAP:
#ifndef MAC_VERSION_V1
		if (dp->mii_status_ro & MII_STATUS_100_BASE_T4) {
			*perm = MAC_PROP_PERM_READ;
		}
#endif
		*(uint8_t *)pr_val = dp->anadv_100t4;
		break;

	case MAC_PROP_PRIVATE:
		err = ENOTSUP;
		break;

#ifndef MAC_VERSION_V1
	case MAC_PROP_MTU: {
		mac_propval_range_t range;
		if (!(pr_flags & MAC_PROP_POSSIBLE)) {
			err = ENOTSUP;
			break;
		}
		if (pr_valsize < sizeof (mac_propval_range_t)) {
			err = EINVAL;
			break;
		}
		range.mpr_count = 1;
		range.mpr_type = MAC_PROPVAL_UINT32;
		range.range_uint32[0].mpur_min = ETHERMTU;
		range.range_uint32[0].mpur_max = dp->mtu;
		bcopy(&range, pr_val, sizeof (range));
		break;
	}
#endif
	default:
		err = ENOTSUP;
		break;
	}

	rw_exit(&dp->dev_state_lock);
	return (err);
}
#endif /* USBGEM_CONFIG_MAC_PROP */

#ifdef USBGEM_CONFIG_ND
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
	PARAM_ADV_1000T_MS,

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

struct usbgem_nd_arg {
	struct usbgem_dev	*dp;
	int		item;
};

static int
usbgem_param_get(queue_t *q, mblk_t *mp, caddr_t arg, cred_t *credp)
{
	struct usbgem_dev	*dp = ((struct usbgem_nd_arg *)(void *)arg)->dp;
	int		item = ((struct usbgem_nd_arg *)(void *)arg)->item;
	long		val;

	DPRINTF(1, (CE_CONT, "!%s: %s: called, item:%d",
	    dp->name, __func__, item));

	switch (item) {
	case PARAM_AUTONEG_CAP:
		val = BOOLEAN(dp->mii_status & MII_STATUS_CANAUTONEG);
		DPRINTF(1, (CE_CONT, "autoneg_cap:%d", val));
		break;

	case PARAM_PAUSE_CAP:
		val = dp->ugc.usbgc_flow_control != FLOW_CONTROL_NONE;
		break;

	case PARAM_ASYM_PAUSE_CAP:
		val = dp->ugc.usbgc_flow_control > FLOW_CONTROL_SYMMETRIC;
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
		val = dp->anadv_pause;
		break;

	case PARAM_ADV_ASYM_PAUSE_CAP:
		val = dp->anadv_asmpause;
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

	case PARAM_ADV_1000T_MS:
		val = dp->anadv_1000t_ms;
		break;

	case PARAM_LP_AUTONEG_CAP:
		val = BOOLEAN(dp->mii_exp & MII_AN_EXP_LPCANAN);
		break;

	case PARAM_LP_PAUSE_CAP:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_PAUSE);
		break;

	case PARAM_LP_ASYM_PAUSE_CAP:
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_ASM_DIR);
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
		val = usbgem_speed_value[dp->speed];
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
usbgem_param_set(queue_t *q,
    mblk_t *mp, char *value, caddr_t arg, cred_t *credp)
{
	struct usbgem_dev	*dp = ((struct usbgem_nd_arg *)(void *)arg)->dp;
	int		item = ((struct usbgem_nd_arg *)(void *)arg)->item;
	long		val;
	char		*end;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));
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
		if (val && dp->ugc.usbgc_flow_control == FLOW_CONTROL_NONE) {
			goto err;
		}
		dp->anadv_pause = (int)val;
		break;

	case PARAM_ADV_ASYM_PAUSE_CAP:
		if (val != 0 && val != 1) {
			goto err;
		}
		if (val &&
		    dp->ugc.usbgc_flow_control <= FLOW_CONTROL_SYMMETRIC) {
			goto err;
		}
		dp->anadv_asmpause = (int)val;
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

	case PARAM_ADV_1000T_MS:
		if (val != 0 && val != 1 && val != 2) {
			goto err;
		}
		if (val && (dp->mii_xstatus &
		    (MII_XSTATUS_1000BASET | MII_XSTATUS_1000BASET_FD)) == 0) {
			goto err;
		}
		dp->anadv_1000t_ms = (int)val;
		break;

#ifdef DEBUG_RESUME
	case PARAM_RESUME_TEST:
		mutex_exit(&dp->xmitlock);
		mutex_exit(&dp->intrlock);
		gem_suspend(dp->dip);
		gem_resume(dp->dip);
		mutex_enter(&dp->intrlock);
		mutex_enter(&dp->xmitlock);
		break;
#endif
	}

	/* sync with PHY */
	usbgem_choose_forcedmode(dp);

	dp->mii_state = MII_STATE_UNKNOWN;
	if (dp->ugc.usbgc_mii_hw_link_detection) {
		/* wake up link watcher possiblely sleeps */
		cv_signal(&dp->link_watcher_wait_cv);
	}

	return (0);
err:
	return (EINVAL);
}

static void
usbgem_nd_load(struct usbgem_dev *dp,
    char *name, ndgetf_t gf, ndsetf_t sf, int item)
{
	struct usbgem_nd_arg	*arg;

	ASSERT(item >= 0);
	ASSERT(item < PARAM_COUNT);

	arg = &((struct usbgem_nd_arg *)(void *)dp->nd_arg_p)[item];
	arg->dp = dp;
	arg->item = item;

	DPRINTF(2, (CE_CONT, "!%s: %s: name:%s, item:%d",
	    dp->name, __func__, name, item));
	(void) nd_load(&dp->nd_data_p, name, gf, sf, (caddr_t)arg);
}

static void
usbgem_nd_setup(struct usbgem_dev *dp)
{
	DPRINTF(1, (CE_CONT, "!%s: %s: called, mii_status:0x%b",
	    dp->name, __func__, dp->mii_status, MII_STATUS_BITS));

	ASSERT(dp->nd_arg_p == NULL);

	dp->nd_arg_p =
	    kmem_zalloc(sizeof (struct usbgem_nd_arg) * PARAM_COUNT, KM_SLEEP);

#define	SETFUNC(x)	((x) ? usbgem_param_set : NULL)

	usbgem_nd_load(dp, "autoneg_cap",
	    usbgem_param_get, NULL, PARAM_AUTONEG_CAP);
	usbgem_nd_load(dp, "pause_cap",
	    usbgem_param_get, NULL, PARAM_PAUSE_CAP);
	usbgem_nd_load(dp, "asym_pause_cap",
	    usbgem_param_get, NULL, PARAM_ASYM_PAUSE_CAP);
	usbgem_nd_load(dp, "1000fdx_cap",
	    usbgem_param_get, NULL, PARAM_1000FDX_CAP);
	usbgem_nd_load(dp, "1000hdx_cap",
	    usbgem_param_get, NULL, PARAM_1000HDX_CAP);
	usbgem_nd_load(dp, "100T4_cap",
	    usbgem_param_get, NULL, PARAM_100T4_CAP);
	usbgem_nd_load(dp, "100fdx_cap",
	    usbgem_param_get, NULL, PARAM_100FDX_CAP);
	usbgem_nd_load(dp, "100hdx_cap",
	    usbgem_param_get, NULL, PARAM_100HDX_CAP);
	usbgem_nd_load(dp, "10fdx_cap",
	    usbgem_param_get, NULL, PARAM_10FDX_CAP);
	usbgem_nd_load(dp, "10hdx_cap",
	    usbgem_param_get, NULL, PARAM_10HDX_CAP);

	/* Our advertised capabilities */
	usbgem_nd_load(dp, "adv_autoneg_cap", usbgem_param_get,
	    SETFUNC(dp->mii_status & MII_STATUS_CANAUTONEG),
	    PARAM_ADV_AUTONEG_CAP);
	usbgem_nd_load(dp, "adv_pause_cap", usbgem_param_get,
	    SETFUNC(dp->ugc.usbgc_flow_control & 1),
	    PARAM_ADV_PAUSE_CAP);
	usbgem_nd_load(dp, "adv_asym_pause_cap", usbgem_param_get,
	    SETFUNC(dp->ugc.usbgc_flow_control & 2),
	    PARAM_ADV_ASYM_PAUSE_CAP);
	usbgem_nd_load(dp, "adv_1000fdx_cap", usbgem_param_get,
	    SETFUNC(dp->mii_xstatus &
	    (MII_XSTATUS_1000BASEX_FD | MII_XSTATUS_1000BASET_FD)),
	    PARAM_ADV_1000FDX_CAP);
	usbgem_nd_load(dp, "adv_1000hdx_cap", usbgem_param_get,
	    SETFUNC(dp->mii_xstatus &
	    (MII_XSTATUS_1000BASEX | MII_XSTATUS_1000BASET)),
	    PARAM_ADV_1000HDX_CAP);
	usbgem_nd_load(dp, "adv_100T4_cap", usbgem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_100_BASE_T4) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_100T4_CAP);
	usbgem_nd_load(dp, "adv_100fdx_cap", usbgem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_100_BASEX_FD) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_100FDX_CAP);
	usbgem_nd_load(dp, "adv_100hdx_cap", usbgem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_100_BASEX) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_100HDX_CAP);
	usbgem_nd_load(dp, "adv_10fdx_cap", usbgem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_10_FD) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_10FDX_CAP);
	usbgem_nd_load(dp, "adv_10hdx_cap", usbgem_param_get,
	    SETFUNC((dp->mii_status & MII_STATUS_10) &&
	    !dp->mii_advert_ro),
	    PARAM_ADV_10HDX_CAP);
	usbgem_nd_load(dp, "adv_1000t_ms", usbgem_param_get,
	    SETFUNC(dp->mii_xstatus &
	    (MII_XSTATUS_1000BASET_FD | MII_XSTATUS_1000BASET)),
	    PARAM_ADV_1000T_MS);


	/* Partner's advertised capabilities */
	usbgem_nd_load(dp, "lp_autoneg_cap",
	    usbgem_param_get, NULL, PARAM_LP_AUTONEG_CAP);
	usbgem_nd_load(dp, "lp_pause_cap",
	    usbgem_param_get, NULL, PARAM_LP_PAUSE_CAP);
	usbgem_nd_load(dp, "lp_asym_pause_cap",
	    usbgem_param_get, NULL, PARAM_LP_ASYM_PAUSE_CAP);
	usbgem_nd_load(dp, "lp_1000fdx_cap",
	    usbgem_param_get, NULL, PARAM_LP_1000FDX_CAP);
	usbgem_nd_load(dp, "lp_1000hdx_cap",
	    usbgem_param_get, NULL, PARAM_LP_1000HDX_CAP);
	usbgem_nd_load(dp, "lp_100T4_cap",
	    usbgem_param_get, NULL, PARAM_LP_100T4_CAP);
	usbgem_nd_load(dp, "lp_100fdx_cap",
	    usbgem_param_get, NULL, PARAM_LP_100FDX_CAP);
	usbgem_nd_load(dp, "lp_100hdx_cap",
	    usbgem_param_get, NULL, PARAM_LP_100HDX_CAP);
	usbgem_nd_load(dp, "lp_10fdx_cap",
	    usbgem_param_get, NULL, PARAM_LP_10FDX_CAP);
	usbgem_nd_load(dp, "lp_10hdx_cap",
	    usbgem_param_get, NULL, PARAM_LP_10HDX_CAP);

	/* Current operating modes */
	usbgem_nd_load(dp, "link_status",
	    usbgem_param_get, NULL, PARAM_LINK_STATUS);
	usbgem_nd_load(dp, "link_speed",
	    usbgem_param_get, NULL, PARAM_LINK_SPEED);
	usbgem_nd_load(dp, "link_duplex",
	    usbgem_param_get, NULL, PARAM_LINK_DUPLEX);
	usbgem_nd_load(dp, "link_autoneg",
	    usbgem_param_get, NULL, PARAM_LINK_AUTONEG);
	usbgem_nd_load(dp, "link_rx_pause",
	    usbgem_param_get, NULL, PARAM_LINK_RX_PAUSE);
	usbgem_nd_load(dp, "link_tx_pause",
	    usbgem_param_get, NULL, PARAM_LINK_TX_PAUSE);
#ifdef DEBUG_RESUME
	usbgem_nd_load(dp, "resume_test",
	    usbgem_param_get, usbgem_param_set, PARAM_RESUME_TEST);
#endif
#undef	SETFUNC
}

static
enum ioc_reply
usbgem_nd_ioctl(struct usbgem_dev *dp,
    queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	boolean_t	ok;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	switch (iocp->ioc_cmd) {
	case ND_GET:
		ok = nd_getset(wq, dp->nd_data_p, mp);
		DPRINTF(1, (CE_CONT,
		    "%s: get %s", dp->name, ok ? "OK" : "FAIL"));
		return (ok ? IOC_REPLY : IOC_INVAL);

	case ND_SET:
		ok = nd_getset(wq, dp->nd_data_p, mp);

		DPRINTF(1, (CE_CONT, "%s: set %s err %d",
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
usbgem_nd_cleanup(struct usbgem_dev *dp)
{
	ASSERT(dp->nd_data_p != NULL);
	ASSERT(dp->nd_arg_p != NULL);

	nd_free(&dp->nd_data_p);

	kmem_free(dp->nd_arg_p, sizeof (struct usbgem_nd_arg) * PARAM_COUNT);
	dp->nd_arg_p = NULL;
}
#endif /* USBGEM_CONFIG_ND */

static void
usbgem_mac_ioctl(struct usbgem_dev *dp, queue_t *wq, mblk_t *mp)
{
	struct iocblk	*iocp;
	enum ioc_reply	status;
	int		cmd;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/*
	 * Validate the command before bothering with the mutex ...
	 */
	iocp = (void *)mp->b_rptr;
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;

	DPRINTF(1, (CE_CONT, "%s: %s cmd:0x%x", dp->name, __func__, cmd));

#ifdef USBGEM_CONFIG_ND
	switch (cmd) {
	default:
		_NOTE(NOTREACHED)
		status = IOC_INVAL;
		break;

	case ND_GET:
	case ND_SET:
		status = usbgem_nd_ioctl(dp, wq, mp, iocp);
		break;
	}

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
#else
	miocnak(wq, mp, 0, EINVAL);
	return;
#endif /* USBGEM_CONFIG_GLDv3 */
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
usbgem_mac_xcvr_inuse(struct usbgem_dev *dp)
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

#ifdef USBGEM_CONFIG_GLDv3
/* ============================================================== */
/*
 * GLDv3 interface
 */
/* ============================================================== */
static int	usbgem_m_getstat(void *, uint_t, uint64_t *);
static int	usbgem_m_start(void *);
static void	usbgem_m_stop(void *);
static int	usbgem_m_setpromisc(void *, boolean_t);
static int	usbgem_m_multicst(void *, boolean_t, const uint8_t *);
static int	usbgem_m_unicst(void *, const uint8_t *);
static mblk_t	*usbgem_m_tx(void *, mblk_t *);
static void	usbgem_m_ioctl(void *, queue_t *, mblk_t *);
#ifdef GEM_CONFIG_MAC_PROP
static int	usbgem_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
#ifdef MAC_VERSION_V1
static int	usbgem_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
#else
static int	usbgem_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, uint_t, void *, uint_t *);
#endif
#endif

#ifdef _SYS_MAC_PROVIDER_H
#define	GEM_M_CALLBACK_FLAGS	(MC_IOCTL)
#else
#define	GEM_M_CALLBACK_FLAGS	(MC_IOCTL)
#endif

static mac_callbacks_t gem_m_callbacks = {
#ifdef USBGEM_CONFIG_MAC_PROP
#ifdef MAC_VERSION_V1
	GEM_M_CALLBACK_FLAGS | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
#else
	GEM_M_CALLBACK_FLAGS | MC_SETPROP | MC_GETPROP,
#endif
#else
	GEM_M_CALLBACK_FLAGS,
#endif
	usbgem_m_getstat,
	usbgem_m_start,
	usbgem_m_stop,
	usbgem_m_setpromisc,
	usbgem_m_multicst,
	usbgem_m_unicst,
	usbgem_m_tx,
#ifdef _SYS_MAC_PROVIDER_H
#ifdef MAC_VERSION_V1
	NULL,
#endif
#else
	NULL,	/* m_resources */
#endif
	usbgem_m_ioctl,
	NULL, /* m_getcapab */
#ifdef USBGEM_CONFIG_MAC_PROP
	NULL,
	NULL,
	usbgem_m_setprop,
	usbgem_m_getprop,
#endif
#ifdef MAC_VERSION_V1
	usbgem_m_propinfo,
#endif
};

static int
usbgem_m_start(void *arg)
{
	int	ret;
	int	err;
	struct usbgem_dev *dp = arg;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	err = EIO;

	rw_enter(&dp->dev_state_lock, RW_WRITER);
	dp->nic_state = NIC_STATE_ONLINE;

	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		err = 0;
		goto x;
	}
	if (usbgem_mac_init(dp) != USB_SUCCESS) {
		goto x;
	}

	/* initialize rx filter state */
	sema_p(&dp->rxfilter_lock);
	dp->mc_count = 0;
	dp->mc_count_req = 0;

	bcopy(dp->dev_addr.ether_addr_octet,
	    dp->cur_addr.ether_addr_octet, ETHERADDRL);
	dp->rxmode |= RXMODE_ENABLE;

	ret = usbgem_hal_set_rx_filter(dp);
	sema_v(&dp->rxfilter_lock);

	if (ret != USB_SUCCESS) {
		goto x;
	}

	if (dp->mii_state == MII_STATE_LINKUP) {
		/* setup media mode if the link have been up */
		if (usbgem_hal_set_media(dp) != USB_SUCCESS) {
			goto x;
		}
		if (usbgem_mac_start(dp) != USB_SUCCESS) {
			goto x;
		}
	}

	err = 0;
x:
	rw_exit(&dp->dev_state_lock);
	return (err);
}

static void
usbgem_m_stop(void *arg)
{
	struct usbgem_dev	*dp = arg;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* stop rx gracefully */
	rw_enter(&dp->dev_state_lock, RW_READER);
	sema_p(&dp->rxfilter_lock);
	dp->rxmode &= ~RXMODE_ENABLE;

	if (dp->mac_state != MAC_STATE_DISCONNECTED) {
		(void) usbgem_hal_set_rx_filter(dp);
	}
	sema_v(&dp->rxfilter_lock);
	rw_exit(&dp->dev_state_lock);

	/* make the nic state inactive */
	rw_enter(&dp->dev_state_lock, RW_WRITER);
	dp->nic_state = NIC_STATE_STOPPED;

	/* stop mac completely */
	if (dp->mac_state != MAC_STATE_DISCONNECTED) {
		(void) usbgem_mac_stop(dp, MAC_STATE_STOPPED, STOP_GRACEFUL);
	}
	rw_exit(&dp->dev_state_lock);
}

static int
usbgem_m_multicst(void *arg, boolean_t add, const uint8_t *ep)
{
	int	err;
	int	ret;
	struct usbgem_dev	*dp = arg;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	rw_enter(&dp->dev_state_lock, RW_READER);
	if (add) {
		ret = usbgem_add_multicast(dp, ep);
	} else {
		ret = usbgem_remove_multicast(dp, ep);
	}
	rw_exit(&dp->dev_state_lock);

	err = 0;
	if (ret != USB_SUCCESS) {
#ifdef GEM_CONFIG_FMA
		ddi_fm_service_impact(dp->dip, DDI_SERVICE_DEGRADED);
#endif
		err = EIO;
	}

	return (err);
}

static int
usbgem_m_setpromisc(void *arg, boolean_t on)
{
	int	err;
	struct usbgem_dev	*dp = arg;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	rw_enter(&dp->dev_state_lock, RW_READER);

	sema_p(&dp->rxfilter_lock);
	if (on) {
		dp->rxmode |= RXMODE_PROMISC;
	} else {
		dp->rxmode &= ~RXMODE_PROMISC;
	}

	err = 0;
	if (dp->mac_state != MAC_STATE_DISCONNECTED) {
		if (usbgem_hal_set_rx_filter(dp) != USB_SUCCESS) {
			err = EIO;
		}
	}
	sema_v(&dp->rxfilter_lock);

	rw_exit(&dp->dev_state_lock);

#ifdef GEM_CONFIG_FMA
	if (err != 0) {
		ddi_fm_service_impact(dp->dip, DDI_SERVICE_DEGRADED);
	}
#endif
	return (err);
}

int
usbgem_m_getstat(void *arg, uint_t stat, uint64_t *valp)
{
	int	ret;
	uint64_t	val;
	struct usbgem_dev	*dp = arg;
	struct usbgem_stats	*gstp = &dp->stats;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	rw_enter(&dp->dev_state_lock, RW_READER);
	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		rw_exit(&dp->dev_state_lock);
		return (0);
	}
	ret = usbgem_hal_get_stats(dp);
	rw_exit(&dp->dev_state_lock);

#ifdef GEM_CONFIG_FMA
	if (ret != USB_SUCCESS) {
		ddi_fm_service_impact(dp->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}
#endif

	switch (stat) {
	case MAC_STAT_IFSPEED:
		val = usbgem_speed_value[dp->speed] *1000000ull;
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
		val = usbgem_mac_xcvr_inuse(dp);
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
		val = dp->ugc.usbgc_flow_control > FLOW_CONTROL_SYMMETRIC;
		break;

	case ETHER_STAT_CAP_PAUSE:
		val = dp->ugc.usbgc_flow_control != FLOW_CONTROL_NONE;
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
		val = dp->anadv_asmpause;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		val = dp->anadv_pause;
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
		val = BOOLEAN(dp->mii_lpable & MII_ABILITY_ASM_DIR);
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
#ifdef NEVER	/* it doesn't make sense */
	case ETHER_STAT_CAP_REMFAULT:
		val = B_TRUE;
		break;

	case ETHER_STAT_ADV_REMFAULT:
		val = dp->anadv_remfault;
		break;
#endif
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
		*valp = 0;
		return (ENOTSUP);
	}

	*valp = val;

	return (0);
}

static int
usbgem_m_unicst(void *arg, const uint8_t *mac)
{
	int	err;
	struct usbgem_dev	*dp = arg;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	rw_enter(&dp->dev_state_lock, RW_READER);

	sema_p(&dp->rxfilter_lock);
	bcopy(mac, dp->cur_addr.ether_addr_octet, ETHERADDRL);
	dp->rxmode |= RXMODE_ENABLE;

	err = 0;
	if (dp->mac_state != MAC_STATE_DISCONNECTED) {
		if (usbgem_hal_set_rx_filter(dp) != USB_SUCCESS) {
			err = EIO;
		}
	}
	sema_v(&dp->rxfilter_lock);
	rw_exit(&dp->dev_state_lock);

#ifdef GEM_CONFIG_FMA
	if (err != 0) {
		ddi_fm_service_impact(dp->dip, DDI_SERVICE_DEGRADED);
	}
#endif
	return (err);
}

/*
 * usbgem_m_tx is used only for sending data packets into ethernet wire.
 */
static mblk_t *
usbgem_m_tx(void *arg, mblk_t *mp_head)
{
	int	limit;
	mblk_t	*mp;
	mblk_t	*nmp;
	uint32_t	flags;
	struct usbgem_dev	*dp = arg;

	DPRINTF(4, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	mp = mp_head;
	flags = 0;

	rw_enter(&dp->dev_state_lock, RW_READER);

	if (dp->mii_state != MII_STATE_LINKUP ||
	    dp->mac_state != MAC_STATE_ONLINE) {
		/* some nics hate to send packets during the link is down */
		for (; mp; mp = nmp) {
			nmp = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
		}
		goto x;
	}

	ASSERT(dp->nic_state == NIC_STATE_ONLINE);

	limit = dp->tx_max_packets;
	for (; limit-- && mp; mp = nmp) {
		nmp = mp->b_next;
		mp->b_next = NULL;
		if (usbgem_send_common(dp, mp,
		    (limit == 0 && nmp) ? 1 : 0)) {
			mp->b_next = nmp;
			break;
		}
	}
#ifdef CONFIG_TX_LIMITER
	if (mp == mp_head) {
		/* no packets were sent, descrease allocation limit */
		mutex_enter(&dp->txlock);
		dp->tx_max_packets = max(dp->tx_max_packets - 1, 1);
		mutex_exit(&dp->txlock);
	}
#endif
x:
	rw_exit(&dp->dev_state_lock);

	return (mp);
}

static void
usbgem_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct usbgem_dev	*dp = arg;

	DPRINTF(1, (CE_CONT, "!%s: %s: called",
	    ((struct usbgem_dev *)arg)->name, __func__));

	rw_enter(&dp->dev_state_lock, RW_READER);
	usbgem_mac_ioctl((struct usbgem_dev *)arg, wq, mp);
	rw_exit(&dp->dev_state_lock);
}

static void
usbgem_gld3_init(struct usbgem_dev *dp, mac_register_t *macp)
{
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = dp;
	macp->m_dip = dp->dip;
	macp->m_src_addr = dp->dev_addr.ether_addr_octet;
	macp->m_callbacks = &gem_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = dp->mtu;

	if (dp->misc_flag & USBGEM_VLAN) {
		macp->m_margin = VTAG_SIZE;
	}
}
#else
/* ============================================================== */
/*
 * GLDv2 interface
 */
/* ============================================================== */
static int usbgem_gld_reset(gld_mac_info_t *);
static int usbgem_gld_start(gld_mac_info_t *);
static int usbgem_gld_stop(gld_mac_info_t *);
static int usbgem_gld_set_mac_address(gld_mac_info_t *, uint8_t *);
static int usbgem_gld_set_multicast(gld_mac_info_t *, uint8_t *, int);
static int usbgem_gld_set_promiscuous(gld_mac_info_t *, int);
static int usbgem_gld_get_stats(gld_mac_info_t *, struct gld_stats *);
static int usbgem_gld_send(gld_mac_info_t *, mblk_t *);
static int usbgem_gld_send_tagged(gld_mac_info_t *, mblk_t *, uint32_t);

static int
usbgem_gld_reset(gld_mac_info_t *macinfo)
{
	int	err;
	struct usbgem_dev	*dp;

	err = GLD_SUCCESS;
	dp = (struct usbgem_dev *)macinfo->gldm_private;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	rw_enter(&dp->dev_state_lock, RW_WRITER);
	if (usbgem_mac_init(dp) != USB_SUCCESS) {
		err = GLD_FAILURE;
		goto x;
	}

	dp->nic_state = NIC_STATE_INITIALIZED;

	/* setup media mode if the link have been up */
	if (dp->mii_state == MII_STATE_LINKUP) {
		if (dp->mac_state != MAC_STATE_DISCONNECTED) {
			(void) usbgem_hal_set_media(dp);
		}
	}
x:
	rw_exit(&dp->dev_state_lock);
	return (err);
}

static int
usbgem_gld_start(gld_mac_info_t *macinfo)
{
	int	err;
	struct usbgem_dev *dp;

	dp = (struct usbgem_dev *)macinfo->gldm_private;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	rw_enter(&dp->dev_state_lock, RW_WRITER);

	dp->nic_state = NIC_STATE_ONLINE;

	if (dp->mii_state == MII_STATE_LINKUP) {
		if (usbgem_mac_start(dp) != USB_SUCCESS) {
			/* sema_v(&dp->mii_lock); */
			err = GLD_FAILURE;
			goto x;
		}
	}

	/*
	 * XXX - don't call gld_linkstate() here,
	 * otherwise it cause recursive mutex call.
	 */
	err = GLD_SUCCESS;
x:
	rw_exit(&dp->dev_state_lock);

	return (err);
}

static int
usbgem_gld_stop(gld_mac_info_t *macinfo)
{
	int	err = GLD_SUCCESS;
	struct usbgem_dev	*dp;

	dp = (struct usbgem_dev *)macinfo->gldm_private;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/* try to stop rx gracefully */
	rw_enter(&dp->dev_state_lock, RW_READER);
	sema_p(&dp->rxfilter_lock);
	dp->rxmode &= ~RXMODE_ENABLE;

	if (dp->mac_state != MAC_STATE_DISCONNECTED) {
		(void) usbgem_hal_set_rx_filter(dp);
	}
	sema_v(&dp->rxfilter_lock);
	rw_exit(&dp->dev_state_lock);

	/* make the nic state inactive */
	rw_enter(&dp->dev_state_lock, RW_WRITER);
	dp->nic_state = NIC_STATE_STOPPED;

	if (dp->mac_state != MAC_STATE_DISCONNECTED) {
		if (usbgem_mac_stop(dp, MAC_STATE_STOPPED, STOP_GRACEFUL)
		    != USB_SUCCESS) {
			err = GLD_FAILURE;
		}
	}
	rw_exit(&dp->dev_state_lock);

	return (err);
}

static int
usbgem_gld_set_multicast(gld_mac_info_t *macinfo, uint8_t *ep, int flag)
{
	int		err;
	int		ret;
	struct usbgem_dev	*dp;

	dp = (struct usbgem_dev *)macinfo->gldm_private;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	rw_enter(&dp->dev_state_lock, RW_READER);
	if (flag == GLD_MULTI_ENABLE) {
		ret = usbgem_add_multicast(dp, ep);
	} else {
		ret = usbgem_remove_multicast(dp, ep);
	}
	rw_exit(&dp->dev_state_lock);

	err = GLD_SUCCESS;
	if (ret != USB_SUCCESS) {
#ifdef GEM_CONFIG_FMA
		ddi_fm_service_impact(dp->dip, DDI_SERVICE_DEGRADED);
#endif
		err = GLD_FAILURE;
	}
	return (err);
}

static int
usbgem_gld_set_promiscuous(gld_mac_info_t *macinfo, int flag)
{
	boolean_t	need_to_change = B_TRUE;
	struct usbgem_dev	*dp;

	dp = (struct usbgem_dev *)macinfo->gldm_private;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	sema_p(&dp->rxfilter_lock);
	if (flag == GLD_MAC_PROMISC_NONE) {
		dp->rxmode &= ~(RXMODE_PROMISC | RXMODE_ALLMULTI_REQ);
	} else if (flag == GLD_MAC_PROMISC_MULTI) {
		dp->rxmode |= RXMODE_ALLMULTI_REQ;
	} else if (flag == GLD_MAC_PROMISC_PHYS) {
		dp->rxmode |= RXMODE_PROMISC;
	} else {
		/* mode unchanged */
		need_to_change = B_FALSE;
	}

	if (need_to_change) {
		if (dp->mac_state != MAC_STATE_DISCONNECTED) {
			(void) usbgem_hal_set_rx_filter(dp);
		}
	}
	sema_v(&dp->rxfilter_lock);

	return (GLD_SUCCESS);
}

static int
usbgem_gld_set_mac_address(gld_mac_info_t *macinfo, uint8_t *mac)
{
	struct usbgem_dev	*dp;
	dp = (struct usbgem_dev *)macinfo->gldm_private;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	sema_p(&dp->rxfilter_lock);
	bcopy(mac, dp->cur_addr.ether_addr_octet, ETHERADDRL);
	dp->rxmode |= RXMODE_ENABLE;

	if (dp->mac_state != MAC_STATE_DISCONNECTED) {
		(void) usbgem_hal_set_rx_filter(dp);
	}
	sema_v(&dp->rxfilter_lock);

	return (GLD_SUCCESS);
}

static	int
usbgem_gld_get_stats(gld_mac_info_t *macinfo, struct gld_stats *gs)
{
	struct usbgem_dev	*dp;
	struct usbgem_stats	*vs;

	dp = (struct usbgem_dev *)macinfo->gldm_private;

	if ((*dp->ugc.usbgc_get_stats)(dp) != USB_SUCCESS) {
#ifdef GEM_CONFIG_FMA
		ddi_fm_service_impact(dp->dip, DDI_SERVICE_DEGRADED);
#endif
		return (USB_FAILURE);
	}

	vs = &dp->stats;

	gs->glds_errxmt = vs->errxmt;
	gs->glds_errrcv = vs->errrcv;
	gs->glds_collisions = vs->collisions;

	gs->glds_excoll = vs->excoll;
	gs->glds_defer = vs->defer;
	gs->glds_frame = vs->frame;
	gs->glds_crc = vs->crc;

	gs->glds_overflow = vs->overflow; /* fifo err,underrun,rbufovf */
	gs->glds_underflow = vs->underflow;
	gs->glds_short = vs->runt;
	gs->glds_missed = vs->missed; /* missed pkts while rbuf ovf */
	gs->glds_xmtlatecoll = vs->xmtlatecoll;
	gs->glds_nocarrier = vs->nocarrier;
	gs->glds_norcvbuf = vs->norcvbuf;	/* OS resource exaust */
	gs->glds_intr = vs->intr;

	/* all before here must be kept in place for v0 compatibility */
	gs->glds_speed = usbgem_speed_value[dp->speed] * 1000000;
	gs->glds_media = GLDM_PHYMII;
	gs->glds_duplex = dp->full_duplex ? GLD_DUPLEX_FULL : GLD_DUPLEX_HALF;

	/* gs->glds_media_specific */
	gs->glds_dot3_first_coll = vs->first_coll;
	gs->glds_dot3_multi_coll = vs->multi_coll;
	gs->glds_dot3_sqe_error = 0;
	gs->glds_dot3_mac_xmt_error = 0;
	gs->glds_dot3_mac_rcv_error = 0;
	gs->glds_dot3_frame_too_long = vs->frame_too_long;

	return (GLD_SUCCESS);
}

static int
usbgem_gld_ioctl(gld_mac_info_t *macinfo, queue_t *wq, mblk_t *mp)
{
	struct usbgem_dev	*dp;

	dp = (struct usbgem_dev *)macinfo->gldm_private;
	usbgem_mac_ioctl(dp, wq, mp);

	return (GLD_SUCCESS);
}

/*
 * gem_gld_send is used only for sending data packets into ethernet wire.
 */
static int
usbgem_gld_send(gld_mac_info_t *macinfo, mblk_t *mp)
{
	int		ret;
	uint32_t	flags = 0;
	struct usbgem_dev	*dp;

	dp = (struct usbgem_dev *)macinfo->gldm_private;

	/* nic state must be online of suspended */
	rw_enter(&dp->dev_state_lock, RW_READER);

	ASSERT(dp->nic_state == NIC_STATE_ONLINE);
	ASSERT(mp->b_next == NULL);

	if (dp->mii_state != MII_STATE_LINKUP) {
		/* Some nics hate to send packets while the link is down. */
		/* we discard the untransmitted packets silently */
		rw_exit(&dp->dev_state_lock);

		freemsg(mp);
#ifdef GEM_CONFIG_FMA
		/* FIXME - should we ignore the error? */
		ddi_fm_service_impact(dp->dip, DDI_SERVICE_DEGRADED);
#endif
		return (GLD_SUCCESS);
	}

	ret = (usbgem_send_common(dp, mp, flags) == NULL)
	    ? GLD_SUCCESS : GLD_NORESOURCES;
	rw_exit(&dp->dev_state_lock);

	return (ret);
}

/*
 * usbgem_gld_send is used only for sending data packets into ethernet wire.
 */
static int
usbgem_gld_send_tagged(gld_mac_info_t *macinfo, mblk_t *mp, uint32_t vtag)
{
	uint32_t	flags;
	struct usbgem_dev	*dp;

	dp = (struct usbgem_dev *)macinfo->gldm_private;

	/*
	 * Some nics hate to send packets while the link is down.
	 */
	if (dp->mii_state != MII_STATE_LINKUP) {
		/* we dicard the untransmitted packets silently */
		freemsg(mp);
#ifdef GEM_CONFIG_FMA
		/* FIXME - should we ignore the error? */
		ddi_fm_service_impact(dp->dip, DDI_SERVICE_UNAFFECTED);
#endif
		return (GLD_SUCCESS);
	}
#ifdef notyet
	flags = GLD_VTAG_TCI(vtag) << GEM_SEND_VTAG_SHIFT;
#endif
	return ((usbgem_send_common(dp, mp, 0) == NULL) ?
	    GLD_SUCCESS : GLD_NORESOURCES);
}

static void
usbgem_gld_init(struct usbgem_dev *dp, gld_mac_info_t *macinfo, char *ident)
{
	/*
	 * configure GLD
	 */
	macinfo->gldm_devinfo = dp->dip;
	macinfo->gldm_private = (caddr_t)dp;

	macinfo->gldm_reset = usbgem_gld_reset;
	macinfo->gldm_start = usbgem_gld_start;
	macinfo->gldm_stop = usbgem_gld_stop;
	macinfo->gldm_set_mac_addr = usbgem_gld_set_mac_address;
	macinfo->gldm_send = usbgem_gld_send;
	macinfo->gldm_set_promiscuous = usbgem_gld_set_promiscuous;
	macinfo->gldm_get_stats = usbgem_gld_get_stats;
	macinfo->gldm_ioctl = usbgem_gld_ioctl;
	macinfo->gldm_set_multicast = usbgem_gld_set_multicast;
	macinfo->gldm_intr = NULL;
	macinfo->gldm_mctl = NULL;

	macinfo->gldm_ident = ident;
	macinfo->gldm_type = DL_ETHER;
	macinfo->gldm_minpkt = 0;
	macinfo->gldm_maxpkt = dp->mtu;
	macinfo->gldm_addrlen = ETHERADDRL;
	macinfo->gldm_saplen = -2;
	macinfo->gldm_ppa = ddi_get_instance(dp->dip);
#ifdef GLD_CAP_LINKSTATE
	macinfo->gldm_capabilities = GLD_CAP_LINKSTATE;
#endif
	macinfo->gldm_vendor_addr = dp->dev_addr.ether_addr_octet;
	macinfo->gldm_broadcast_addr = usbgem_bcastaddr;
}
#endif /* USBGEM_CONFIG_GLDv3 */


/* ======================================================================== */
/*
 * .conf interface
 */
/* ======================================================================== */
void
usbgem_generate_macaddr(struct usbgem_dev *dp, uint8_t *mac)
{
	extern char	hw_serial[];
	char		*hw_serial_p;
	int		i;
	uint64_t	val;
	uint64_t	key;

	cmn_err(CE_NOTE,
	    "!%s: using temp ether address,"
	    " do not use this for long time",
	    dp->name);

	/* prefer a fixed address for DHCP */
	hw_serial_p = &hw_serial[0];
	val = stoi(&hw_serial_p);

	key = 0;
	for (i = 0; i < USBGEM_NAME_LEN; i++) {
		if (dp->name[i] == 0) {
			break;
		}
		key ^= dp->name[i];
	}
	key ^= ddi_get_instance(dp->dip);
	val ^= key << 32;

	/* generate a local address */
	mac[0] = 0x02;
	mac[1] = (uint8_t)(val >> 32);
	mac[2] = (uint8_t)(val >> 24);
	mac[3] = (uint8_t)(val >> 16);
	mac[4] = (uint8_t)(val >> 8);
	mac[5] = (uint8_t)val;
}

boolean_t
usbgem_get_mac_addr_conf(struct usbgem_dev *dp)
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
	    DDI_PROP_DONTPASS, propname, &valstr)) != DDI_PROP_SUCCESS) {
		return (B_FALSE);
	}

	if (strlen(valstr) != ETHERADDRL*3-1) {
		goto syntax_err;
	}

	cp = valstr;
	j = 0;
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
		usbgem_generate_macaddr(dp, mac);
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
	ddi_prop_free(valstr);

	return (B_FALSE);
}

static void
usbgem_read_conf(struct usbgem_dev *dp)
{
	int	val;

	DPRINTF(1, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	/*
	 * Get media mode infomation from .conf file
	 */
	dp->anadv_autoneg = usbgem_prop_get_int(dp, "adv_autoneg_cap", 1) != 0;
	dp->anadv_1000fdx = usbgem_prop_get_int(dp, "adv_1000fdx_cap", 1) != 0;
	dp->anadv_1000hdx = usbgem_prop_get_int(dp, "adv_1000hdx_cap", 1) != 0;
	dp->anadv_100t4 = usbgem_prop_get_int(dp, "adv_100T4_cap", 1) != 0;
	dp->anadv_100fdx = usbgem_prop_get_int(dp, "adv_100fdx_cap", 1) != 0;
	dp->anadv_100hdx = usbgem_prop_get_int(dp, "adv_100hdx_cap", 1) != 0;
	dp->anadv_10fdx = usbgem_prop_get_int(dp, "adv_10fdx_cap", 1) != 0;
	dp->anadv_10hdx = usbgem_prop_get_int(dp, "adv_10hdx_cap", 1) != 0;
	dp->anadv_1000t_ms = usbgem_prop_get_int(dp, "adv_1000t_ms", 0);

	if ((ddi_prop_exists(DDI_DEV_T_ANY, dp->dip,
	    DDI_PROP_DONTPASS, "full-duplex"))) {
		dp->full_duplex =
		    usbgem_prop_get_int(dp, "full-duplex", 1) != 0;
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

	if ((val = usbgem_prop_get_int(dp, "speed", 0)) > 0) {
		dp->anadv_autoneg = B_FALSE;
		switch (val) {
		case 1000:
			dp->speed = USBGEM_SPD_1000;
			dp->anadv_100t4 = B_FALSE;
			dp->anadv_100fdx = B_FALSE;
			dp->anadv_100hdx = B_FALSE;
			dp->anadv_10fdx = B_FALSE;
			dp->anadv_10hdx = B_FALSE;
			break;
		case 100:
			dp->speed = USBGEM_SPD_100;
			dp->anadv_1000fdx = B_FALSE;
			dp->anadv_1000hdx = B_FALSE;
			dp->anadv_10fdx = B_FALSE;
			dp->anadv_10hdx = B_FALSE;
			break;
		case 10:
			dp->speed = USBGEM_SPD_10;
			dp->anadv_1000fdx = B_FALSE;
			dp->anadv_1000hdx = B_FALSE;
			dp->anadv_100t4 = B_FALSE;
			dp->anadv_100fdx = B_FALSE;
			dp->anadv_100hdx = B_FALSE;
			break;
		default:
			cmn_err(CE_WARN,
			    "!%s: property %s: illegal value:%d",
			    dp->name, "speed", val);
			dp->anadv_autoneg = B_TRUE;
			break;
		}
	}
	val = usbgem_prop_get_int(dp,
	    "adv_pause", dp->ugc.usbgc_flow_control & 1);
	val |= usbgem_prop_get_int(dp,
	    "adv_asmpause", BOOLEAN(dp->ugc.usbgc_flow_control & 2)) << 1;
	if (val > FLOW_CONTROL_RX_PAUSE || val < FLOW_CONTROL_NONE) {
		cmn_err(CE_WARN,
		    "!%s: property %s: illegal value:%d",
		    dp->name, "flow-control", val);
	} else {
		val = min(val, dp->ugc.usbgc_flow_control);
	}
	dp->anadv_pause = BOOLEAN(val & 1);
	dp->anadv_asmpause = BOOLEAN(val & 2);

	dp->mtu = usbgem_prop_get_int(dp, "mtu", dp->mtu);
	dp->txthr = usbgem_prop_get_int(dp, "txthr", dp->txthr);
	dp->rxthr = usbgem_prop_get_int(dp, "rxthr", dp->rxthr);
	dp->txmaxdma = usbgem_prop_get_int(dp, "txmaxdma", dp->txmaxdma);
	dp->rxmaxdma = usbgem_prop_get_int(dp, "rxmaxdma", dp->rxmaxdma);
#ifdef GEM_CONFIG_POLLING
	dp->poll_pkt_delay =
	    usbgem_prop_get_int(dp, "pkt_delay", dp->poll_pkt_delay);

	dp->max_poll_interval[GEM_SPD_10] =
	    usbgem_prop_get_int(dp, "max_poll_interval_10",
	    dp->max_poll_interval[GEM_SPD_10]);
	dp->max_poll_interval[GEM_SPD_100] =
	    usbgem_prop_get_int(dp, "max_poll_interval_100",
	    dp->max_poll_interval[GEM_SPD_100]);
	dp->max_poll_interval[GEM_SPD_1000] =
	    usbgem_prop_get_int(dp, "max_poll_interval_1000",
	    dp->max_poll_interval[GEM_SPD_1000]);

	dp->min_poll_interval[GEM_SPD_10] =
	    usbgem_prop_get_int(dp, "min_poll_interval_10",
	    dp->min_poll_interval[GEM_SPD_10]);
	dp->min_poll_interval[GEM_SPD_100] =
	    usbgem_prop_get_int(dp, "min_poll_interval_100",
	    dp->min_poll_interval[GEM_SPD_100]);
	dp->min_poll_interval[GEM_SPD_1000] =
	    usbgem_prop_get_int(dp, "min_poll_interval_1000",
	    dp->min_poll_interval[GEM_SPD_1000]);
#endif
}

/*
 * usbem kstat support
 */
#ifndef GEM_CONFIG_GLDv3
/* kstat items based from dmfe driver */

struct usbgem_kstat_named {
	struct kstat_named	ks_xcvr_addr;
	struct kstat_named	ks_xcvr_id;
	struct kstat_named	ks_xcvr_inuse;
	struct kstat_named	ks_link_up;
	struct kstat_named	ks_link_duplex;	/* 0:unknwon, 1:half, 2:full */
	struct kstat_named	ks_cap_1000fdx;
	struct kstat_named	ks_cap_1000hdx;
	struct kstat_named	ks_cap_100fdx;
	struct kstat_named	ks_cap_100hdx;
	struct kstat_named	ks_cap_10fdx;
	struct kstat_named	ks_cap_10hdx;
#ifdef NEVER
	struct kstat_named	ks_cap_remfault;
#endif
	struct kstat_named	ks_cap_autoneg;

	struct kstat_named	ks_adv_cap_1000fdx;
	struct kstat_named	ks_adv_cap_1000hdx;
	struct kstat_named	ks_adv_cap_100fdx;
	struct kstat_named	ks_adv_cap_100hdx;
	struct kstat_named	ks_adv_cap_10fdx;
	struct kstat_named	ks_adv_cap_10hdx;
#ifdef NEVER
	struct kstat_named	ks_adv_cap_remfault;
#endif
	struct kstat_named	ks_adv_cap_autoneg;
	struct kstat_named	ks_lp_cap_1000fdx;
	struct kstat_named	ks_lp_cap_1000hdx;
	struct kstat_named	ks_lp_cap_100fdx;
	struct kstat_named	ks_lp_cap_100hdx;
	struct kstat_named	ks_lp_cap_10fdx;
	struct kstat_named	ks_lp_cap_10hdx;
	struct kstat_named	ks_lp_cap_remfault;
	struct kstat_named	ks_lp_cap_autoneg;
};

static int
usbgem_kstat_update(kstat_t *ksp, int rw)
{
	struct usbgem_kstat_named *knp;
	struct usbgem_dev *dp = (struct usbgem_dev *)ksp->ks_private;

	if (rw != KSTAT_READ) {
		return (0);
	}

	knp = (struct usbgem_kstat_named *)ksp->ks_data;

	knp->ks_xcvr_addr.value.ul = dp->mii_phy_addr;
	knp->ks_xcvr_id.value.ul = dp->mii_phy_id;
	knp->ks_xcvr_inuse.value.ul = usbgem_mac_xcvr_inuse(dp);
	knp->ks_link_up.value.ul = dp->mii_state == MII_STATE_LINKUP;
	knp->ks_link_duplex.value.ul =
	    (dp->mii_state == MII_STATE_LINKUP) ?
	    (dp->full_duplex ? 2 : 1) : 0;

	knp->ks_cap_1000fdx.value.ul =
	    (dp->mii_xstatus & MII_XSTATUS_1000BASET_FD) ||
	    (dp->mii_xstatus & MII_XSTATUS_1000BASEX_FD);
	knp->ks_cap_1000hdx.value.ul =
	    (dp->mii_xstatus & MII_XSTATUS_1000BASET) ||
	    (dp->mii_xstatus & MII_XSTATUS_1000BASEX);
	knp->ks_cap_100fdx.value.ul =
	    BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX_FD);
	knp->ks_cap_100hdx.value.ul =
	    BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX);
	knp->ks_cap_10fdx.value.ul =
	    BOOLEAN(dp->mii_status & MII_STATUS_10_FD);
	knp->ks_cap_10hdx.value.ul =
	    BOOLEAN(dp->mii_status & MII_STATUS_10);
#ifdef NEVER
	knp->ks_cap_remfault.value.ul = B_TRUE;
#endif
	knp->ks_cap_autoneg.value.ul =
	    BOOLEAN(dp->mii_status & MII_STATUS_CANAUTONEG);

	knp->ks_adv_cap_1000fdx.value.ul = dp->anadv_1000fdx;
	knp->ks_adv_cap_1000hdx.value.ul = dp->anadv_1000hdx;
	knp->ks_adv_cap_100fdx.value.ul	= dp->anadv_100fdx;
	knp->ks_adv_cap_100hdx.value.ul	= dp->anadv_100hdx;
	knp->ks_adv_cap_10fdx.value.ul	= dp->anadv_10fdx;
	knp->ks_adv_cap_10hdx.value.ul	= dp->anadv_10hdx;
#ifdef NEVER
	knp->ks_adv_cap_remfault.value.ul = 0;
#endif
	knp->ks_adv_cap_autoneg.value.ul = dp->anadv_autoneg;

	knp->ks_lp_cap_1000fdx.value.ul =
	    BOOLEAN(dp->mii_stat1000 & MII_1000TS_LP_FULL);
	knp->ks_lp_cap_1000hdx.value.ul =
	    BOOLEAN(dp->mii_stat1000 & MII_1000TS_LP_HALF);
	knp->ks_lp_cap_100fdx.value.ul =
	    BOOLEAN(dp->mii_lpable & MII_ABILITY_100BASE_TX_FD);
	knp->ks_lp_cap_100hdx.value.ul =
	    BOOLEAN(dp->mii_lpable & MII_ABILITY_100BASE_TX);
	knp->ks_lp_cap_10fdx.value.ul =
	    BOOLEAN(dp->mii_lpable & MII_ABILITY_10BASE_T_FD);
	knp->ks_lp_cap_10hdx.value.ul =
	    BOOLEAN(dp->mii_lpable & MII_ABILITY_10BASE_T);
	knp->ks_lp_cap_remfault.value.ul =
	    BOOLEAN(dp->mii_exp & MII_AN_EXP_PARFAULT);
	knp->ks_lp_cap_autoneg.value.ul =
	    BOOLEAN(dp->mii_exp & MII_AN_EXP_LPCANAN);

	return (0);
}


static int
usbgem_kstat_init(struct usbgem_dev *dp)
{
	int			i;
	kstat_t			*ksp;
	struct usbgem_kstat_named	*knp;

	ksp = kstat_create(
	    (char *)ddi_driver_name(dp->dip), ddi_get_instance(dp->dip),
	    "mii", "net", KSTAT_TYPE_NAMED,
	    sizeof (*knp) / sizeof (knp->ks_xcvr_addr), 0);

	if (ksp == NULL) {
		cmn_err(CE_WARN, "%s: %s() for mii failed",
		    dp->name, __func__);
		return (USB_FAILURE);
	}

	knp = (struct usbgem_kstat_named *)ksp->ks_data;

	kstat_named_init(&knp->ks_xcvr_addr, "xcvr_addr",
	    KSTAT_DATA_INT32);
	kstat_named_init(&knp->ks_xcvr_id, "xcvr_id",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_xcvr_inuse, "xcvr_inuse",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_link_up, "link_up",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_link_duplex, "link_duplex",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_cap_1000fdx, "cap_1000fdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_cap_1000hdx, "cap_1000hdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_cap_100fdx, "cap_100fdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_cap_100hdx, "cap_100hdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_cap_10fdx, "cap_10fdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_cap_10hdx, "cap_10hdx",
	    KSTAT_DATA_UINT32);
#ifdef NEVER
	kstat_named_init(&knp->ks_cap_remfault, "cap_rem_fault",
	    KSTAT_DATA_UINT32);
#endif
	kstat_named_init(&knp->ks_cap_autoneg, "cap_autoneg",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_adv_cap_1000fdx, "adv_cap_1000fdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_adv_cap_1000hdx, "adv_cap_1000hdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_adv_cap_100fdx, "adv_cap_100fdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_adv_cap_100hdx, "adv_cap_100hdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_adv_cap_10fdx, "adv_cap_10fdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_adv_cap_10hdx, "adv_cap_10hdx",
	    KSTAT_DATA_UINT32);
#ifdef NEVER
	kstat_named_init(&knp->ks_adv_cap_remfault, "adv_rem_fault",
	    KSTAT_DATA_UINT32);
#endif
	kstat_named_init(&knp->ks_adv_cap_autoneg, "adv_cap_autoneg",
	    KSTAT_DATA_UINT32);

	kstat_named_init(&knp->ks_lp_cap_1000fdx, "lp_cap_1000fdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_lp_cap_1000hdx, "lp_cap_1000hdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_lp_cap_100fdx, "lp_cap_100fdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_lp_cap_100hdx, "lp_cap_100hdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_lp_cap_10fdx, "lp_cap_10fdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_lp_cap_10hdx, "lp_cap_10hdx",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_lp_cap_remfault, "lp_cap_rem_fault",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&knp->ks_lp_cap_autoneg, "lp_cap_autoneg",
	    KSTAT_DATA_UINT32);

	ksp->ks_private = (void *) dp;
	ksp->ks_update = usbgem_kstat_update;
	dp->ksp = ksp;

	kstat_install(ksp);

	return (USB_SUCCESS);
}
#endif /* GEM_CONFIG_GLDv3 */
/* ======================================================================== */
/*
 * attach/detatch/usb support
 */
/* ======================================================================== */
int
usbgem_ctrl_out(struct usbgem_dev *dp,
	uint8_t reqt, uint8_t req, uint16_t val, uint16_t ix, uint16_t len,
	void *bp, int size)
{
	mblk_t			*data;
	usb_ctrl_setup_t	setup;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	usb_flags_t		flags;
	int			i;
	int			ret;

	DPRINTF(4, (CE_CONT, "!%s: %s "
	    "reqt:0x%02x req:0x%02x val:0x%04x ix:0x%04x len:0x%02x "
	    "bp:0x%p nic_state:%d",
	    dp->name, __func__, reqt, req, val, ix, len, bp, dp->nic_state));

	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		return (USB_PIPE_ERROR);
	}

	data = NULL;
	if (size > 0) {
		if ((data = allocb(size, 0)) == NULL) {
			return (USB_FAILURE);
		}

		bcopy(bp, data->b_rptr, size);
		data->b_wptr = data->b_rptr + size;
	}

	setup.bmRequestType = reqt;
	setup.bRequest = req;
	setup.wValue = val;
	setup.wIndex = ix;
	setup.wLength = len;
	setup.attrs = 0;	/* attributes */

	for (i = usbgem_ctrl_retry; i > 0; i--) {
		completion_reason = 0;
		cb_flags = 0;

		ret = usb_pipe_ctrl_xfer_wait(DEFAULT_PIPE(dp),
		    &setup, &data, &completion_reason, &cb_flags, 0);

		if (ret == USB_SUCCESS) {
			break;
		}
		if (i == 1) {
			cmn_err(CE_WARN,
			    "!%s: %s failed: "
			    "reqt:0x%x req:0x%x val:0x%x ix:0x%x len:0x%x "
			    "ret:%d cr:%s(%d), cb_flags:0x%x %s",
			    dp->name, __func__, reqt, req, val, ix, len,
			    ret, usb_str_cr(completion_reason),
			    completion_reason,
			    cb_flags,
			    (i > 1) ? "retrying..." : "fatal");
		}
	}

	if (data != NULL) {
		freemsg(data);
	}

	return (ret);
}

int
usbgem_ctrl_in(struct usbgem_dev *dp,
	uint8_t reqt, uint8_t req, uint16_t val, uint16_t ix, uint16_t len,
	void *bp, int size)
{
	mblk_t			*data;
	usb_ctrl_setup_t	setup;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	int			i;
	int			ret;
	int			reclen;

	DPRINTF(4, (CE_CONT,
	    "!%s: %s:"
	    " reqt:0x%02x req:0x%02x val:0x%04x ix:0x%04x len:0x%02x"
	    " bp:x%p mac_state:%d",
	    dp->name, __func__, reqt, req, val, ix, len, bp, dp->mac_state));

	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		return (USB_PIPE_ERROR);
	}

	data = NULL;

	setup.bmRequestType = reqt;
	setup.bRequest = req;
	setup.wValue = val;
	setup.wIndex = ix;
	setup.wLength = len;
	setup.attrs = USB_ATTRS_AUTOCLEARING;	/* XXX */

	for (i = usbgem_ctrl_retry; i > 0; i--) {
		completion_reason = 0;
		cb_flags = 0;
		ret = usb_pipe_ctrl_xfer_wait(DEFAULT_PIPE(dp), &setup, &data,
		    &completion_reason, &cb_flags, 0);

		if (ret == USB_SUCCESS) {
			reclen = msgdsize(data);
			bcopy(data->b_rptr, bp, min(reclen, size));
			break;
		}
		if (i == 1) {
			cmn_err(CE_WARN,
			    "!%s: %s failed: "
			    "reqt:0x%x req:0x%x val:0x%x ix:0x%x len:0x%x "
			    "ret:%d cr:%s(%d) cb_flags:0x%x %s",
			    dp->name, __func__,
			    reqt, req, val, ix, len,
			    ret, usb_str_cr(completion_reason),
			    completion_reason,
			    cb_flags,
			    (i > 1) ? "retrying..." : "fatal");
		}
	}

	if (data) {
		freemsg(data);
	}

	return (ret);
}

int
usbgem_ctrl_out_val(struct usbgem_dev *dp,
    uint8_t reqt, uint8_t req, uint16_t val, uint16_t ix, uint16_t len,
    uint32_t v)
{
	uint8_t	buf[4];

	/* convert to little endian from native byte order */
	switch (len) {
	case 4:
		buf[3] = v >> 24;
		buf[2] = v >> 16;
		/* FALLTHROUGH */
	case 2:
		buf[1] = v >> 8;
		/* FALLTHROUGH */
	case 1:
		buf[0] = v;
	}

	return (usbgem_ctrl_out(dp, reqt, req, val, ix, len, buf, len));
}

int
usbgem_ctrl_in_val(struct usbgem_dev *dp,
    uint8_t reqt, uint8_t req, uint16_t val, uint16_t ix, uint16_t len,
    void *valp)
{
	uint8_t		buf[4];
	uint_t		v;
	int		err;

#ifdef SANITY
	bzero(buf, sizeof (buf));
#endif
	err = usbgem_ctrl_in(dp, reqt, req, val, ix, len, buf, len);
	if (err == USB_SUCCESS) {
		v = 0;
		switch (len) {
		case 4:
			v |= buf[3] << 24;
			v |= buf[2] << 16;
			/* FALLTHROUGH */
		case 2:
			v |= buf[1] << 8;
			/* FALLTHROUGH */
		case 1:
			v |= buf[0];
		}

		switch (len) {
		case 4:
			*(uint32_t *)valp = v;
			break;
		case 2:
			*(uint16_t *)valp = v;
			break;
		case 1:
			*(uint8_t *)valp = v;
			break;
		}
	}
	return (err);
}

/*
 * Attach / detach / disconnect / reconnect management
 */
static int
usbgem_open_pipes(struct usbgem_dev *dp)
{
	int			i;
	int			ret;
	int			ifnum;
	int			alt;
	usb_client_dev_data_t	*reg_data;
	usb_ep_data_t		*ep_tree_node;

	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	ifnum = dp->ugc.usbgc_ifnum;
	alt = dp->ugc.usbgc_alt;

	ep_tree_node = usb_lookup_ep_data(dp->dip, dp->reg_data, ifnum, alt,
	    0, USB_EP_ATTR_BULK, USB_EP_DIR_IN);
	if (ep_tree_node == NULL) {
		cmn_err(CE_WARN, "!%s: %s: ep_bulkin is NULL",
		    dp->name, __func__);
		goto err;
	}
	dp->ep_bulkin = &ep_tree_node->ep_descr;

	ep_tree_node = usb_lookup_ep_data(dp->dip, dp->reg_data, ifnum, alt,
	    0, USB_EP_ATTR_BULK, USB_EP_DIR_OUT);
	if (ep_tree_node == NULL) {
		cmn_err(CE_WARN, "!%s: %s: ep_bulkout is NULL",
		    dp->name, __func__);
		goto err;
	}
	dp->ep_bulkout = &ep_tree_node->ep_descr;

	ep_tree_node = usb_lookup_ep_data(dp->dip, dp->reg_data, ifnum, alt,
	    0, USB_EP_ATTR_INTR, USB_EP_DIR_IN);
	if (ep_tree_node) {
		dp->ep_intr = &ep_tree_node->ep_descr;
	} else {
		/* don't care */
		DPRINTF(1, (CE_CONT, "!%s: %s: ep_intr is NULL",
		    dp->name, __func__));
		dp->ep_intr = NULL;
	}

	/* XXX -- no need to open default pipe */

	/* open bulk out pipe */
	bzero(&dp->policy_bulkout, sizeof (usb_pipe_policy_t));
	dp->policy_bulkout.pp_max_async_reqs = 1;

	if ((ret = usb_pipe_open(dp->dip,
	    dp->ep_bulkout, &dp->policy_bulkout, USB_FLAGS_SLEEP,
	    &dp->bulkout_pipe)) != USB_SUCCESS) {
		cmn_err(CE_WARN,
		    "!%s: %s: err:%x: failed to open bulk-out pipe",
		    dp->name, __func__, ret);
		dp->bulkout_pipe = NULL;
		goto err;
	}
	DPRINTF(1, (CE_CONT, "!%s: %s: bulkout_pipe opened successfully",
	    dp->name, __func__));

	/* open bulk in pipe */
	bzero(&dp->policy_bulkin, sizeof (usb_pipe_policy_t));
	dp->policy_bulkin.pp_max_async_reqs = 1;
	if ((ret = usb_pipe_open(dp->dip,
	    dp->ep_bulkin, &dp->policy_bulkin, USB_FLAGS_SLEEP,
	    &dp->bulkin_pipe)) != USB_SUCCESS) {
		cmn_err(CE_WARN,
		    "!%s: %s: ret:%x failed to open bulk-in pipe",
		    dp->name, __func__, ret);
		dp->bulkin_pipe = NULL;
		goto err;
	}
	DPRINTF(1, (CE_CONT, "!%s: %s: bulkin_pipe opened successfully",
	    dp->name, __func__));

	if (dp->ep_intr) {
		/* open interrupt pipe */
		bzero(&dp->policy_interrupt, sizeof (usb_pipe_policy_t));
		dp->policy_interrupt.pp_max_async_reqs = 1;
		if ((ret = usb_pipe_open(dp->dip, dp->ep_intr,
		    &dp->policy_interrupt, USB_FLAGS_SLEEP,
		    &dp->intr_pipe)) != USB_SUCCESS) {
			cmn_err(CE_WARN,
			    "!%s: %s: ret:%x failed to open interrupt pipe",
			    dp->name, __func__, ret);
			dp->intr_pipe = NULL;
			goto err;
		}
	}
	DPRINTF(1, (CE_CONT, "!%s: %s: intr_pipe opened successfully",
	    dp->name, __func__));

	return (USB_SUCCESS);

err:
	if (dp->bulkin_pipe) {
		usb_pipe_close(dp->dip,
		    dp->bulkin_pipe, USB_FLAGS_SLEEP, NULL, 0);
		dp->bulkin_pipe = NULL;
	}
	if (dp->bulkout_pipe) {
		usb_pipe_close(dp->dip,
		    dp->bulkout_pipe, USB_FLAGS_SLEEP, NULL, 0);
		dp->bulkout_pipe = NULL;
	}
	if (dp->intr_pipe) {
		usb_pipe_close(dp->dip,
		    dp->intr_pipe, USB_FLAGS_SLEEP, NULL, 0);
		dp->intr_pipe = NULL;
	}

	return (USB_FAILURE);
}

static int
usbgem_close_pipes(struct usbgem_dev *dp)
{
	DPRINTF(0, (CE_CONT, "!%s: %s: called", dp->name, __func__));

	if (dp->intr_pipe) {
		usb_pipe_close(dp->dip,
		    dp->intr_pipe, USB_FLAGS_SLEEP, NULL, 0);
		dp->intr_pipe = NULL;
	}
	DPRINTF(1, (CE_CONT, "!%s: %s: 1", dp->name, __func__));

	ASSERT(dp->bulkin_pipe);
	usb_pipe_close(dp->dip, dp->bulkin_pipe, USB_FLAGS_SLEEP, NULL, 0);
	dp->bulkin_pipe = NULL;
	DPRINTF(1, (CE_CONT, "!%s: %s: 2", dp->name, __func__));

	ASSERT(dp->bulkout_pipe);
	usb_pipe_close(dp->dip, dp->bulkout_pipe, USB_FLAGS_SLEEP, NULL, 0);
	dp->bulkout_pipe = NULL;
	DPRINTF(1, (CE_CONT, "!%s: %s: 3", dp->name, __func__));

	return (USB_SUCCESS);
}

#define	FREEZE_GRACEFUL		(B_TRUE)
#define	FREEZE_NO_GRACEFUL	(B_FALSE)
static int
usbgem_freeze_device(struct usbgem_dev *dp, boolean_t graceful)
{
	DPRINTF(0, (CE_NOTE, "!%s: %s: called", dp->name, __func__));

	/* stop nic activity */
	(void) usbgem_mac_stop(dp, MAC_STATE_DISCONNECTED, graceful);

	/*
	 * Here we free all memory resource allocated, because it will
	 * cause to panic the system that we free usb_bulk_req objects
	 * during the usb device is disconnected.
	 */
	(void) usbgem_free_memory(dp);

	return (USB_SUCCESS);
}

static int
usbgem_disconnect_cb(dev_info_t *dip)
{
	int	ret;
	struct usbgem_dev	*dp;

	dp = USBGEM_GET_DEV(dip);

	cmn_err(CE_NOTE, "!%s: the usb device was disconnected (dp=%p)",
	    dp->name, (void *)dp);

	/* start serialize */
	rw_enter(&dp->dev_state_lock, RW_WRITER);

	ret = usbgem_freeze_device(dp, 0);

	/* end of serialize */
	rw_exit(&dp->dev_state_lock);

	return (ret);
}

static int
usbgem_recover_device(struct usbgem_dev	*dp)
{
	int	err;

	DPRINTF(0, (CE_NOTE, "!%s: %s: called", dp->name, __func__));

	err = USB_SUCCESS;

	/* reinitialize the usb connection */
	usbgem_close_pipes(dp);
	if ((err = usbgem_open_pipes(dp)) != USB_SUCCESS) {
		goto x;
	}

	/* initialize nic state */
	dp->mac_state = MAC_STATE_STOPPED;
	dp->mii_state = MII_STATE_UNKNOWN;

	/* allocate memory resources again */
	if ((err = usbgem_alloc_memory(dp)) != USB_SUCCESS) {
		goto x;
	}

	/* restart nic and recover state */
	(void) usbgem_restart_nic(dp);

	usbgem_mii_init(dp);

	/* kick potentially stopped house keeping thread */
	cv_signal(&dp->link_watcher_wait_cv);
x:
	return (err);
}

static int
usbgem_reconnect_cb(dev_info_t *dip)
{
	int	err = USB_SUCCESS;
	struct usbgem_dev	*dp;

	dp = USBGEM_GET_DEV(dip);
	DPRINTF(0, (CE_CONT, "!%s: dp=%p", ddi_get_name(dip), dp));
#ifdef notdef
	/* check device changes after disconnect */
	if (usb_check_same_device(dp->dip, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC | USB_CHK_CFG, NULL) != USB_SUCCESS) {
		cmn_err(CE_CONT,
		    "!%s: no or different device installed", dp->name);
		return (DDI_SUCCESS);
	}
#endif
	cmn_err(CE_NOTE, "%s: the usb device was reconnected", dp->name);

	/* start serialize */
	rw_enter(&dp->dev_state_lock, RW_WRITER);

	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		err = usbgem_recover_device(dp);
	}

	/* end of serialize */
	rw_exit(&dp->dev_state_lock);

	return (err == USB_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
}

int
usbgem_suspend(dev_info_t *dip)
{
	int	err = USB_SUCCESS;
	struct usbgem_dev	*dp;

	dp = USBGEM_GET_DEV(dip);

	DPRINTF(0, (CE_CONT, "!%s: %s: callded", dp->name, __func__));

	/* start serialize */
	rw_enter(&dp->dev_state_lock, RW_WRITER);

	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		err = usbgem_freeze_device(dp, STOP_GRACEFUL);
	}

	/* end of serialize */
	rw_exit(&dp->dev_state_lock);

	return (err == USB_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
}

int
usbgem_resume(dev_info_t *dip)
{
	int	err = USB_SUCCESS;
	struct usbgem_dev	*dp;

	dp = USBGEM_GET_DEV(dip);

	DPRINTF(0, (CE_CONT, "!%s: %s: callded", dp->name, __func__));
#ifdef notdef
	/* check device changes after disconnect */
	if (usb_check_same_device(dp->dip, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC | USB_CHK_CFG, NULL) != USB_SUCCESS) {
		cmn_err(CE_CONT,
		    "!%s: no or different device installed", dp->name);
		return (DDI_SUCCESS);
	}
#endif
	/* start serialize */
	rw_enter(&dp->dev_state_lock, RW_WRITER);

	if (dp->mac_state == MAC_STATE_DISCONNECTED) {
		err = usbgem_recover_device(dp);
	}

	/* end of serialize */
	rw_exit(&dp->dev_state_lock);

	return (err == USB_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
}

#define	USBGEM_LOCAL_DATA_SIZE(gc)	\
	(sizeof (struct usbgem_dev) + USBGEM_MCALLOC)

struct usbgem_dev *
usbgem_do_attach(dev_info_t *dip,
	struct usbgem_conf *gc, void *lp, int lmsize)
{
	struct usbgem_dev	*dp;
	int			i;
#ifdef USBGEM_CONFIG_GLDv3
	mac_register_t		*macp = NULL;
#else
	gld_mac_info_t		*macinfo;
	void			*tmp;
#endif
	int			ret;
	int			unit;
	int			err;

	unit = ddi_get_instance(dip);

	DPRINTF(2, (CE_CONT, "!usbgem%d: %s: called", unit, __func__));

	/*
	 * Allocate soft data structure
	 */
	dp = kmem_zalloc(USBGEM_LOCAL_DATA_SIZE(gc), KM_SLEEP);
	if (dp == NULL) {
#ifndef USBGEM_CONFIG_GLDv3
		gld_mac_free(macinfo);
#endif
		return (NULL);
	}
#ifdef USBGEM_CONFIG_GLDv3
	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		cmn_err(CE_WARN, "!gem%d: %s: mac_alloc failed",
		    unit, __func__);
		return (NULL);
	}
#else
	macinfo = gld_mac_alloc(dip);
	dp->macinfo = macinfo;
#endif

	/* link to private area */
	dp->private = lp;
	dp->priv_size = lmsize;
	dp->mc_list = (struct mcast_addr *)&dp[1];

	dp->dip = dip;
	bcopy(gc->usbgc_name, dp->name, USBGEM_NAME_LEN);

	/*
	 * register with usb service
	 */
	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s: %s: usb_client_attach failed",
		    dp->name, __func__);
		goto err_free_private;
	}

	if (usb_get_dev_data(dip, &dp->reg_data,
	    USB_PARSE_LVL_ALL, 0) != USB_SUCCESS) {
		dp->reg_data = NULL;
		goto err_unregister_client;
	}
#ifdef USBGEM_DEBUG_LEVEL
	usb_print_descr_tree(dp->dip, dp->reg_data);
#endif

	if (usbgem_open_pipes(dp) != USB_SUCCESS) {
		/* failed to open pipes */
		cmn_err(CE_WARN, "!%s: %s: failed to open pipes",
		    dp->name, __func__);
		goto err_unregister_client;
	}

	/*
	 * Initialize mutexs and condition variables
	 */
	mutex_init(&dp->rxlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&dp->txlock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dp->rx_drain_cv, NULL, CV_DRIVER, NULL);
	cv_init(&dp->tx_drain_cv, NULL, CV_DRIVER, NULL);
	rw_init(&dp->dev_state_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&dp->link_watcher_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dp->link_watcher_wait_cv, NULL, CV_DRIVER, NULL);
	sema_init(&dp->hal_op_lock, 1, NULL, SEMA_DRIVER, NULL);
	sema_init(&dp->rxfilter_lock, 1, NULL, SEMA_DRIVER, NULL);

	/*
	 * Initialize configuration
	 */
	dp->ugc = *gc;

	dp->mtu = ETHERMTU;
	dp->rxmode = 0;
	dp->speed = USBGEM_SPD_10;	/* default is 10Mbps */
	dp->full_duplex = B_FALSE;	/* default is half */
	dp->flow_control = FLOW_CONTROL_NONE;

	dp->nic_state = NIC_STATE_STOPPED;
	dp->mac_state = MAC_STATE_STOPPED;
	dp->mii_state = MII_STATE_UNKNOWN;

	/* performance tuning parameters */
	dp->txthr = ETHERMAX;		/* tx fifo threshoold */
	dp->txmaxdma = 16*4;		/* tx max dma burst size */
	dp->rxthr = 128;		/* rx fifo threshoold */
	dp->rxmaxdma = 16*4;		/* rx max dma burst size */

	/*
	 * Get media mode infomation from .conf file
	 */
	usbgem_read_conf(dp);

	/* rx_buf_len depend on MTU */
	dp->rx_buf_len = MAXPKTBUF(dp) + dp->ugc.usbgc_rx_header_len;

	/*
	 * Reset the chip
	 */
	if (usbgem_hal_reset_chip(dp) != USB_SUCCESS) {
		cmn_err(CE_WARN,
		    "!%s: %s: failed to reset the usb device",
		    dp->name, __func__);
		goto err_destroy_locks;
	}

	/*
	 * HW dependant paremeter initialization
	 */
	if (usbgem_hal_attach_chip(dp) != USB_SUCCESS) {
		cmn_err(CE_WARN,
		    "!%s: %s: failed to attach the usb device",
		    dp->name, __func__);
		goto err_destroy_locks;
	}

	/* allocate resources */
	if (usbgem_alloc_memory(dp) != USB_SUCCESS) {
		goto err_destroy_locks;
	}

	DPRINTF(0, (CE_CONT,
	    "!%s: %02x:%02x:%02x:%02x:%02x:%02x",
	    dp->name,
	    dp->dev_addr.ether_addr_octet[0],
	    dp->dev_addr.ether_addr_octet[1],
	    dp->dev_addr.ether_addr_octet[2],
	    dp->dev_addr.ether_addr_octet[3],
	    dp->dev_addr.ether_addr_octet[4],
	    dp->dev_addr.ether_addr_octet[5]));

	/* copy mac address */
	dp->cur_addr = dp->dev_addr;

	/* pre-calculated tx timeout in second for performance */
	dp->bulkout_timeout =
	    dp->ugc.usbgc_tx_timeout / drv_usectohz(1000*1000);

#ifdef USBGEM_CONFIG_GLDv3
	usbgem_gld3_init(dp, macp);
#else
	usbgem_gld_init(dp, macinfo, ident);
#endif

	/* Probe MII phy (scan phy) */
	dp->mii_lpable = 0;
	dp->mii_advert = 0;
	dp->mii_exp = 0;
	dp->mii_ctl1000 = 0;
	dp->mii_stat1000 = 0;

	dp->mii_status_ro = 0;
	dp->mii_xstatus_ro = 0;

	if (usbgem_mii_probe(dp) != USB_SUCCESS) {
		cmn_err(CE_WARN, "!%s: %s: mii_probe failed",
		    dp->name, __func__);
		goto err_free_memory;
	}

	/* mask unsupported abilities */
	dp->anadv_autoneg &= BOOLEAN(dp->mii_status & MII_STATUS_CANAUTONEG);
	dp->anadv_1000fdx &=
	    BOOLEAN(dp->mii_xstatus &
	    (MII_XSTATUS_1000BASEX_FD | MII_XSTATUS_1000BASET_FD));
	dp->anadv_1000hdx &=
	    BOOLEAN(dp->mii_xstatus &
	    (MII_XSTATUS_1000BASEX | MII_XSTATUS_1000BASET));
	dp->anadv_100t4 &= BOOLEAN(dp->mii_status & MII_STATUS_100_BASE_T4);
	dp->anadv_100fdx &= BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX_FD);
	dp->anadv_100hdx &= BOOLEAN(dp->mii_status & MII_STATUS_100_BASEX);
	dp->anadv_10fdx &= BOOLEAN(dp->mii_status & MII_STATUS_10_FD);
	dp->anadv_10hdx &= BOOLEAN(dp->mii_status & MII_STATUS_10);

	if (usbgem_mii_init(dp) != USB_SUCCESS) {
		cmn_err(CE_WARN, "!%s: %s: mii_init failed",
		    dp->name, __func__);
		goto err_free_memory;
	}

	/*
	 * initialize kstats including mii statistics
	 */
#ifdef USBGEM_CONFIG_GLDv3
#ifdef USBGEM_CONFIG_ND
	usbgem_nd_setup(dp);
#endif
#else
	if (usbgem_kstat_init(dp) != USB_SUCCESS) {
		goto err_free_memory;
	}
#endif

	/*
	 * Add interrupt to system.
	 */
#ifdef USBGEM_CONFIG_GLDv3
	if (ret = mac_register(macp, &dp->mh)) {
		cmn_err(CE_WARN, "!%s: mac_register failed, error:%d",
		    dp->name, ret);
		goto err_release_stats;
	}
	mac_free(macp);
	macp = NULL;
#else
	/* gld_register will corrupts driver_private */
	tmp = ddi_get_driver_private(dip);
	if (gld_register(dip,
	    (char *)ddi_driver_name(dip), macinfo) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: %s: gld_register failed",
		    dp->name, __func__);
		ddi_set_driver_private(dip, tmp);
		goto err_release_stats;
	}
	/* restore driver private */
	ddi_set_driver_private(dip, tmp);
#endif /* USBGEM_CONFIG_GLDv3 */
	if (usb_register_hotplug_cbs(dip,
	    usbgem_suspend, usbgem_resume) != USB_SUCCESS) {
		cmn_err(CE_WARN,
		    "!%s: %s: failed to register hotplug cbs",
		    dp->name, __func__);
		goto err_unregister_gld;
	}

	/* reset mii and start mii link watcher */
	if (usbgem_mii_start(dp) != USB_SUCCESS) {
		goto err_unregister_hotplug;
	}

	/* start tx watchdow watcher */
	if (usbgem_tx_watcher_start(dp)) {
		goto err_usbgem_mii_stop;
	}

	ddi_set_driver_private(dip, (caddr_t)dp);

	DPRINTF(2, (CE_CONT, "!%s: %s: return: success", dp->name, __func__));

	return (dp);

err_usbgem_mii_stop:
	usbgem_mii_stop(dp);

err_unregister_hotplug:
	usb_unregister_hotplug_cbs(dip);

err_unregister_gld:
#ifdef USBGEM_CONFIG_GLDv3
	mac_unregister(dp->mh);
#else
	gld_unregister(macinfo);
#endif

err_release_stats:
#ifdef USBGEM_CONFIG_GLDv3
#ifdef USBGEM_CONFIG_ND
	/* release NDD resources */
	usbgem_nd_cleanup(dp);
#endif
#else
	kstat_delete(dp->ksp);
#endif

err_free_memory:
	usbgem_free_memory(dp);

err_destroy_locks:
	cv_destroy(&dp->tx_drain_cv);
	cv_destroy(&dp->rx_drain_cv);
	mutex_destroy(&dp->txlock);
	mutex_destroy(&dp->rxlock);
	rw_destroy(&dp->dev_state_lock);
	mutex_destroy(&dp->link_watcher_lock);
	cv_destroy(&dp->link_watcher_wait_cv);
	sema_destroy(&dp->hal_op_lock);
	sema_destroy(&dp->rxfilter_lock);

err_close_pipes:
	(void) usbgem_close_pipes(dp);

err_unregister_client:
	usb_client_detach(dp->dip, dp->reg_data);

err_free_private:
#ifdef USBGEM_CONFIG_GLDv3
	if (macp) {
		mac_free(macp);
	}
#else
	gld_mac_free(macinfo);
#endif
	kmem_free((caddr_t)dp, USBGEM_LOCAL_DATA_SIZE(gc));

	return (NULL);
}

int
usbgem_do_detach(dev_info_t *dip)
{
	struct usbgem_dev	*dp;

	dp = USBGEM_GET_DEV(dip);

#ifdef USBGEM_CONFIG_GLDv3
	/* unregister with gld v3 */
	if (mac_unregister(dp->mh) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
#else
	/* unregister with gld v2 */
	if (gld_unregister(dp->macinfo) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
#endif
	/* unregister with hotplug service */
	usb_unregister_hotplug_cbs(dip);

	/* stop tx watchdog watcher */
	usbgem_tx_watcher_stop(dp);

	/* stop the link manager */
	usbgem_mii_stop(dp);

	/* unregister with usb service */
	(void) usbgem_free_memory(dp);
	(void) usbgem_close_pipes(dp);
	usb_client_detach(dp->dip, dp->reg_data);
	dp->reg_data = NULL;

	/* unregister with kernel statistics */
#ifdef USBGEM_CONFIG_GLDv3
#ifdef USBGEM_CONFIG_ND
	/* release ndd resources */
	usbgem_nd_cleanup(dp);
#endif
#else
	/* destroy kstat objects */
	kstat_delete(dp->ksp);
#endif

	/* release locks and condition variables */
	mutex_destroy(&dp->txlock);
	mutex_destroy(&dp->rxlock);
	cv_destroy(&dp->tx_drain_cv);
	cv_destroy(&dp->rx_drain_cv);
	rw_destroy(&dp->dev_state_lock);
	mutex_destroy(&dp->link_watcher_lock);
	cv_destroy(&dp->link_watcher_wait_cv);
	sema_destroy(&dp->hal_op_lock);
	sema_destroy(&dp->rxfilter_lock);

	/* release basic memory resources */
#ifndef USBGEM_CONFIG_GLDv3
	gld_mac_free(dp->macinfo);
#endif
	kmem_free((caddr_t)(dp->private), dp->priv_size);
	kmem_free((caddr_t)dp, USBGEM_LOCAL_DATA_SIZE(&dp->ugc));

	DPRINTF(2, (CE_CONT, "!%s: %s: return: success",
	    ddi_driver_name(dip), __func__));

	return (DDI_SUCCESS);
}

int
usbgem_mod_init(struct dev_ops *dop, char *name)
{
#ifdef USBGEM_CONFIG_GLDv3
	major_t	major;
	major = ddi_name_to_major(name);
	if (major == DDI_MAJOR_T_NONE) {
		return (DDI_FAILURE);
	}
	mac_init_ops(dop, name);
#endif
	return (DDI_SUCCESS);
}

void
usbgem_mod_fini(struct dev_ops *dop)
{
#ifdef USBGEM_CONFIG_GLDv3
	mac_fini_ops(dop);
#endif
}

int
usbgem_quiesce(dev_info_t *dip)
{
	struct usbgem_dev	*dp;

	dp = USBGEM_GET_DEV(dip);

	ASSERT(dp != NULL);

	if (dp->mac_state != MAC_STATE_DISCONNECTED &&
	    dp->mac_state != MAC_STATE_STOPPED) {
		if (usbgem_hal_stop_chip(dp) != USB_SUCCESS) {
			(void) usbgem_hal_reset_chip(dp);
		}
	}

	/* devo_quiesce() must return DDI_SUCCESS always */
	return (DDI_SUCCESS);
}
