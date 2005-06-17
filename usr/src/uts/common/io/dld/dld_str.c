/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Driver
 */

#include	<sys/types.h>
#include	<sys/stream.h>
#include	<sys/stropts.h>
#include	<sys/strsun.h>
#include	<sys/strsubr.h>
#include	<sys/atomic.h>
#include	<sys/sdt.h>
#include	<sys/mac.h>
#include	<sys/dls.h>
#include	<sys/dld.h>
#include	<sys/dld_impl.h>
#include	<sys/taskq.h>
#include	<sys/vlan.h>

static int	str_constructor(void *, void *, int);
static void	str_destructor(void *, void *);
static void	str_m_put(dld_str_t *, mblk_t *);
static void	str_m_srv(dld_str_t *, mblk_t *);
static void	str_mdata_fastpath_put(dld_str_t *, mblk_t *);
static void	str_mdata_raw_put(dld_str_t *, mblk_t *);
static void	str_mdata_srv(dld_str_t *, mblk_t *);
static void	str_mproto_put(dld_str_t *, mblk_t *);
static void	str_mpcproto_put(dld_str_t *, mblk_t *);
static void	str_mioctl_put(dld_str_t *, mblk_t *);
static void	str_mflush_put(dld_str_t *, mblk_t *);
static mblk_t	*str_unitdata_ind(dld_str_t *, mblk_t *);
static void	str_notify_promisc_on_phys(dld_str_t *);
static void	str_notify_promisc_off_phys(dld_str_t *);
static void	str_notify_phys_addr(dld_str_t *, const uint8_t *);
static void	str_notify_link_up(dld_str_t *);
static void	str_notify_link_down(dld_str_t *);
static void	str_notify_capab_reneg(dld_str_t *);
static void	str_notify_speed(dld_str_t *, uint32_t);
static void	str_notify(void *, mac_notify_type_t);
static void	str_putbq(queue_t *q, mblk_t *mp);

static uint32_t		str_count;
static kmem_cache_t	*str_cachep;

typedef struct str_msg_info {
	uint8_t		smi_type;
	const char	*smi_txt;
	void		(*smi_put)(dld_str_t *, mblk_t *);
	void		(*smi_srv)(dld_str_t *, mblk_t *);
} str_msg_info_t;

/*
 * Normal priority message jump table.
 */
str_msg_info_t	str_mi[] = {
	{ M_DATA, "M_DATA", str_m_put, str_m_srv },
	{ M_PROTO, "M_PROTO", str_mproto_put, str_m_srv },
	{ 0x02, "undefined", str_m_put, str_m_srv },
	{ 0x03, "undefined", str_m_put, str_m_srv },
	{ 0x04, "undefined", str_m_put, str_m_srv },
	{ 0x05, "undefined", str_m_put, str_m_srv },
	{ 0x06, "undefined", str_m_put, str_m_srv },
	{ 0x07, "undefined", str_m_put, str_m_srv },
	{ M_BREAK, "M_BREAK", str_m_put, str_m_srv },
	{ M_PASSFP, "M_PASSFP", str_m_put, str_m_srv },
	{ M_EVENT, "M_EVENT", str_m_put, str_m_srv },
	{ M_SIG, "M_SIG", str_m_put, str_m_srv },
	{ M_DELAY, "M_DELAY", str_m_put, str_m_srv },
	{ M_CTL, "M_CTL", str_m_put, str_m_srv },
	{ M_IOCTL, "M_IOCTL", str_mioctl_put, str_m_srv },
	{ M_SETOPTS, "M_SETOPTS", str_m_put, str_m_srv },
	{ M_RSE, "M_RSE", str_m_put, str_m_srv }
};

#define	STR_MI_COUNT	(sizeof (str_mi) / sizeof (str_mi[0]))

/*
 * High priority message jump table.
 */
str_msg_info_t	str_pmi[] = {
	{ 0x80,	 "undefined", str_m_put, str_m_srv },
	{ M_IOCACK, "M_IOCACK", str_m_put, str_m_srv },
	{ M_IOCNAK, "M_IOCNAK", str_m_put, str_m_srv },
	{ M_PCPROTO, "M_PCPROTO", str_mpcproto_put, str_m_srv },
	{ M_PCSIG, "M_PCSIG", str_m_put, str_m_srv },
	{ M_READ, "M_READ", str_m_put, str_m_srv },
	{ M_FLUSH, "M_FLUSH", str_mflush_put, str_m_srv },
	{ M_STOP, "M_STOP", str_m_put, str_m_srv },
	{ M_START, "M_START", str_m_put, str_m_srv },
	{ M_HANGUP, "M_HANGUP", str_m_put, str_m_srv },
	{ M_ERROR, "M_ERROR", str_m_put, str_m_srv },
	{ M_COPYIN, "M_COPYIN", str_m_put, str_m_srv },
	{ M_COPYOUT, "M_COPYOUT", str_m_put, str_m_srv },
	{ M_IOCDATA, "M_IOCDATA", str_m_put, str_m_srv },
	{ M_PCRSE, "M_PCRSE", str_m_put, str_m_srv },
	{ M_STOPI, "M_STOPI", str_m_put, str_m_srv },
	{ M_STARTI, "M_STARTI", str_m_put, str_m_srv },
	{ M_PCEVENT, "M_PCEVENT", str_m_put, str_m_srv },
	{ M_UNHANGUP, "M_UNHANGUP", str_m_put, str_m_srv }
};

#define	STR_PMI_COUNT	(sizeof (str_pmi) / sizeof (str_pmi[0]))

/*
 * Initialize this module's data structures.
 */
void
dld_str_init(void)
{
	/*
	 * Create dld_str_t object cache.
	 */
	str_cachep = kmem_cache_create("dld_str_cache", sizeof (dld_str_t),
	    0, str_constructor, str_destructor, NULL, NULL, NULL, 0);
	ASSERT(str_cachep != NULL);
}

/*
 * Tear down this module's data structures.
 */
int
dld_str_fini(void)
{
	/*
	 * Make sure that there are no objects in use.
	 */
	if (str_count != 0)
		return (EBUSY);

	/*
	 * Destroy object cache.
	 */
	kmem_cache_destroy(str_cachep);

	return (0);
}

/*
 * Create a new dld_str_t object.
 */
dld_str_t *
dld_str_create(queue_t *rq)
{
	dld_str_t	*dsp;

	/*
	 * Allocate an object from the cache.
	 */
	dsp = kmem_cache_alloc(str_cachep, KM_SLEEP);
	atomic_add_32(&str_count, 1);

	/*
	 * Initialize the queue pointers.
	 */
	ASSERT(RD(rq) == rq);
	dsp->ds_rq = rq;
	dsp->ds_wq = WR(rq);
	rq->q_ptr = WR(rq)->q_ptr = (void *)dsp;

	return (dsp);
}

/*
 * Destroy a dld_str_t object.
 */
void
dld_str_destroy(dld_str_t *dsp)
{
	queue_t		*rq;
	queue_t		*wq;

	/*
	 * Clear the queue pointers.
	 */
	rq = dsp->ds_rq;
	wq = dsp->ds_wq;
	ASSERT(wq == WR(rq));

	rq->q_ptr = wq->q_ptr = NULL;
	dsp->ds_rq = dsp->ds_wq = NULL;

	/*
	 * Reinitialize all the flags.
	 */
	dsp->ds_notifications = 0;
	dsp->ds_passivestate = DLD_UNINITIALIZED;
	dsp->ds_mode = DLD_UNITDATA;

	/*
	 * Free the object back to the cache.
	 */
	kmem_cache_free(str_cachep, dsp);
	atomic_add_32(&str_count, -1);
}

/*
 * kmem_cache contructor function: see kmem_cache_create(9f).
 */
/*ARGSUSED*/
static int
str_constructor(void *buf, void *cdrarg, int kmflags)
{
	dld_str_t	*dsp = buf;

	bzero(buf, sizeof (dld_str_t));

	/*
	 * Take a copy of the global message handler jump tables.
	 */
	ASSERT(dsp->ds_mi == NULL);
	if ((dsp->ds_mi = kmem_zalloc(sizeof (str_mi), kmflags)) == NULL)
		return (-1);

	bcopy(str_mi, dsp->ds_mi, sizeof (str_mi));

	ASSERT(dsp->ds_pmi == NULL);
	if ((dsp->ds_pmi = kmem_zalloc(sizeof (str_pmi), kmflags)) == NULL) {
		kmem_free(dsp->ds_mi, sizeof (str_mi));
		dsp->ds_mi = NULL;
		return (-1);
	}

	bcopy(str_pmi, dsp->ds_pmi, sizeof (str_pmi));

	/*
	 * Allocate a new minor number.
	 */
	if ((dsp->ds_minor = dld_minor_hold(kmflags == KM_SLEEP)) == 0) {
		kmem_free(dsp->ds_mi, sizeof (str_mi));
		dsp->ds_mi = NULL;
		kmem_free(dsp->ds_pmi, sizeof (str_pmi));
		dsp->ds_pmi = NULL;
		return (-1);
	}

	/*
	 * Initialize the DLPI state machine.
	 */
	dsp->ds_dlstate = DL_UNATTACHED;

	return (0);
}

/*
 * kmem_cache destructor function.
 */
/*ARGSUSED*/
static void
str_destructor(void *buf, void *cdrarg)
{
	dld_str_t	*dsp = buf;

	/*
	 * Make sure the DLPI state machine was reset.
	 */
	ASSERT(dsp->ds_dlstate == DL_UNATTACHED);

	/*
	 * Make sure the data-link interface was closed.
	 */
	ASSERT(dsp->ds_mh == NULL);
	ASSERT(dsp->ds_dc == NULL);

	/*
	 * Make sure enabled notifications are cleared.
	 */
	ASSERT(dsp->ds_notifications == 0);

	/*
	 * Make sure polling is disabled.
	 */
	ASSERT(!dsp->ds_polling);

	/*
	 * Make sure M_DATA message handling is disabled.
	 */
	ASSERT(dsp->ds_mi[M_DATA].smi_put == str_m_put);
	ASSERT(dsp->ds_mi[M_DATA].smi_srv == str_m_srv);

	/*
	 * Release the minor number.
	 */
	dld_minor_rele(dsp->ds_minor);

	/*
	 * Clear down the jump tables.
	 */
	kmem_free(dsp->ds_mi, sizeof (str_mi));
	dsp->ds_mi = NULL;

	kmem_free(dsp->ds_pmi, sizeof (str_pmi));
	dsp->ds_pmi = NULL;
}

/*
 * Called from put(9e) to process a streams message.
 */
void
dld_str_put(dld_str_t *dsp, mblk_t *mp)
{
	uint8_t		type;
	str_msg_info_t	*smip;

	/*
	 * Look up the message handler from the appropriate jump table.
	 */
	if ((type = DB_TYPE(mp)) & QPCTL) {
		/*
		 * Clear the priority bit to index into the jump table.
		 */
		type &= ~QPCTL;

		/*
		 * Check the message is not out of range for the jump table.
		 */
		if (type >= STR_PMI_COUNT)
			goto unknown;

		/*
		 * Get the handler from the jump table.
		 */
		smip = &(dsp->ds_pmi[type]);

		/*
		 * OR the priorty bit back in to restore the original message
		 * type.
		 */
		type |= QPCTL;
	} else {
		/*
		 * Check the message is not out of range for the jump table.
		 */
		if (type >= STR_MI_COUNT)
			goto unknown;

		/*
		 * Get the handler from the jump table.
		 */
		smip = &(dsp->ds_mi[type]);
	}

	ASSERT(smip->smi_type == type);
	smip->smi_put(dsp, mp);
	return;

unknown:
	str_m_put(dsp, mp);
}

/*
 * Called from srv(9e) to process a streams message.
 */
void
dld_str_srv(dld_str_t *dsp, mblk_t *mp)
{
	uint8_t		type;
	str_msg_info_t	*smip;

	/*
	 * Look up the message handler from the appropriate jump table.
	 */
	if ((type = DB_TYPE(mp)) & QPCTL) {
		/*
		 * Clear the priority bit to index into the jump table.
		 */
		type &= ~QPCTL;

		/*
		 * Check the message is not out of range for the jump table.
		 */
		if (type >= STR_PMI_COUNT)
			goto unknown;

		/*
		 * Get the handler from the jump table.
		 */
		smip = &(dsp->ds_pmi[type]);

		/*
		 * OR the priorty bit back in to restore the original message
		 * type.
		 */
		type |= QPCTL;
	} else {
		/*
		 * Check the message is not out of range for the jump table.
		 */
		if (type >= STR_MI_COUNT)
			goto unknown;

		/*
		 * Get the handler from the jump table.
		 */
		ASSERT(type < STR_MI_COUNT);
		smip = &(dsp->ds_mi[type]);
	}

	ASSERT(smip->smi_type == type);
	smip->smi_srv(dsp, mp);
	return;

unknown:
	str_m_srv(dsp, mp);
}

/*
 * M_DATA put (IP fast-path mode)
 */
static void
str_mdata_fastpath_put(dld_str_t *dsp, mblk_t *mp)
{
	queue_t		*q = dsp->ds_wq;

	/*
	 * If something is already queued then we must queue to avoid
	 * re-ordering.
	 */
	if (q->q_first != NULL) {
		(void) putq(q, mp);
		return;
	}

	/*
	 * Attempt to transmit the packet.
	 */
	if ((mp = dls_tx(dsp->ds_dc, mp)) != NULL) {
		(void) putbq(q, mp);
		qenable(q);
	}
}

/*
 * M_DATA put (raw mode)
 */
static void
str_mdata_raw_put(dld_str_t *dsp, mblk_t *mp)
{
	queue_t			*q = dsp->ds_wq;
	struct ether_header	*ehp;
	mblk_t			*bp;
	size_t			size;
	size_t			hdrlen;

	size = MBLKL(mp);
	if (size < sizeof (struct ether_header))
		goto discard;

	hdrlen = sizeof (struct ether_header);

	ehp = (struct ether_header *)mp->b_rptr;
	if (ntohs(ehp->ether_type) == VLAN_TPID) {
		struct ether_vlan_header	*evhp;

		if (size < sizeof (struct ether_vlan_header))
			goto discard;

		/*
		 * Replace vtag with our own
		 */
		evhp = (struct ether_vlan_header *)ehp;
		evhp->ether_tci = htons(VLAN_TCI(dsp->ds_pri,
		    ETHER_CFI, dsp->ds_vid));
		hdrlen = sizeof (struct ether_vlan_header);
	}

	/*
	 * Check the packet is not too big and that any remaining
	 * fragment list is composed entirely of M_DATA messages. (We
	 * know the first fragment was M_DATA otherwise we could not
	 * have got here).
	 */
	for (bp = mp->b_next; bp != NULL; bp = bp->b_cont) {
		if (DB_TYPE(bp) != M_DATA)
			goto discard;
		size += MBLKL(bp);
	}

	if (size > dsp->ds_mip->mi_sdu_max + hdrlen)
		goto discard;

	/*
	 * If something is already queued then we must queue to avoid
	 * re-ordering.
	 */
	if (q->q_first != NULL) {
		(void) putq(q, bp);
		return;
	}

	/*
	 * Attempt to transmit the packet.
	 */
	if ((mp = dls_tx(dsp->ds_dc, mp)) != NULL) {
		(void) putbq(q, mp);
		qenable(q);
	}
	return;

discard:
	freemsg(mp);
}

/*
 * M_DATA srv
 */
static void
str_mdata_srv(dld_str_t *dsp, mblk_t *mp)
{
	queue_t		*q = dsp->ds_wq;

	/*
	 * Attempt to transmit the packet.
	 */
	if ((mp = dls_tx(dsp->ds_dc, mp)) == NULL)
		return;

	(void) str_putbq(q, mp);
	qenable(q);
}

/*
 * M_PROTO put
 */
static void
str_mproto_put(dld_str_t *dsp, mblk_t *mp)
{
	dld_proto(dsp, mp);
}

/*
 * M_PCPROTO put
 */
static void
str_mpcproto_put(dld_str_t *dsp, mblk_t *mp)
{
	dld_proto(dsp, mp);
}

/*
 * M_IOCTL put
 */
static void
str_mioctl_put(dld_str_t *dsp, mblk_t *mp)
{
	dld_ioc(dsp, mp);
}

/*
 * M_FLUSH put
 */
/*ARGSUSED*/
static void
str_mflush_put(dld_str_t *dsp, mblk_t *mp)
{
	queue_t		*q = dsp->ds_wq;

	if (*mp->b_rptr & FLUSHW) {
		flushq(q, FLUSHALL);
		*mp->b_rptr &= ~FLUSHW;
	}

	if (*mp->b_rptr & FLUSHR)
		qreply(q, mp);
	else
		freemsg(mp);
}

/*
 * M_* put.
 */
/*ARGSUSED*/
static void
str_m_put(dld_str_t *dsp, mblk_t *mp)
{
	freemsg(mp);
}

/*
 * M_* put.
 */
/*ARGSUSED*/
static void
str_m_srv(dld_str_t *dsp, mblk_t *mp)
{
	freemsgchain(mp);
}

/*
 * Process DL_ATTACH_REQ (style 2) or open(2) (style 1).
 */
int
dld_str_attach(dld_str_t *dsp, dld_ppa_t *dpp)
{
	int			err;
	dls_channel_t		dc;
	uint_t			addr_length;

	ASSERT(dsp->ds_dc == NULL);

	/*
	 * Open a channel.
	 */
	if ((err = dls_open(dpp->dp_name, &dc)) != 0)
		return (err);

	/*
	 * Cache the MAC interface handle, a pointer to the immutable MAC
	 * information and the current and 'factory' MAC address.
	 */
	dsp->ds_mh = dls_mac(dc);
	dsp->ds_mip = mac_info(dsp->ds_mh);

	mac_unicst_get(dsp->ds_mh, dsp->ds_curr_addr);

	addr_length = dsp->ds_mip->mi_addr_length;
	bcopy(dsp->ds_mip->mi_unicst_addr, dsp->ds_fact_addr, addr_length);

	/*
	 * Cache the interface VLAN identifier. (This will be VLAN_ID_NONE for
	 * a non-VLAN interface).
	 */
	dsp->ds_vid = dls_vid(dc);

	/*
	 * Set the default packet priority.
	 */
	dsp->ds_pri = 0;

	/*
	 * Add a notify function so that the we get updates from the MAC.
	 */
	dsp->ds_mnh = mac_notify_add(dsp->ds_mh, str_notify, (void *)dsp);

	dsp->ds_dc = dc;
	return (0);
}

/*
 * Process DL_DETACH_REQ (style 2) or close(2) (style 1). Can also be called
 * from close(2) for style 2.
 */
void
dld_str_detach(dld_str_t *dsp)
{
	/*
	 * Remove the notify function.
	 */
	mac_notify_remove(dsp->ds_mh, dsp->ds_mnh);

	/*
	 * Make sure the M_DATA handler is reset.
	 */
	dld_str_tx_drop(dsp);

	/*
	 * Clear the polling and promisc flags.
	 */
	dsp->ds_polling = B_FALSE;
	dsp->ds_promisc = 0;

	/*
	 * Close the channel.
	 */
	dls_close(dsp->ds_dc);
	dsp->ds_dc = NULL;
	dsp->ds_mh = NULL;
}

/*
 * Enable raw mode for this stream. This mode is mutually exclusive with
 * fast-path and/or polling.
 */
void
dld_str_tx_raw(dld_str_t *dsp)
{
	/*
	 * Enable M_DATA message handling.
	 */
	dsp->ds_mi[M_DATA].smi_put = str_mdata_raw_put;
	dsp->ds_mi[M_DATA].smi_srv = str_mdata_srv;
}

/*
 * Enable fast-path for this stream.
 */
void
dld_str_tx_fastpath(dld_str_t *dsp)
{
	/*
	 * Enable M_DATA message handling.
	 */
	dsp->ds_mi[M_DATA].smi_put = str_mdata_fastpath_put;
	dsp->ds_mi[M_DATA].smi_srv = str_mdata_srv;
}

/*
 * Disable fast-path or raw mode.
 */
void
dld_str_tx_drop(dld_str_t *dsp)
{
	/*
	 * Disable M_DATA message handling.
	 */
	dsp->ds_mi[M_DATA].smi_put = str_m_put;
	dsp->ds_mi[M_DATA].smi_srv = str_m_srv;
}

/*
 * Raw mode receive function.
 */
/*ARGSUSED*/
void
dld_str_rx_raw(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    size_t header_length)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	mblk_t			*next;

	ASSERT(mp != NULL);
	do {
		/*
		 * Get the pointer to the next packet in the chain and then
		 * clear b_next before the packet gets passed on.
		 */
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Wind back b_rptr to point at the MAC header.
		 */
		ASSERT(mp->b_rptr >= DB_BASE(mp) + header_length);
		mp->b_rptr -= header_length;
		if (header_length == sizeof (struct ether_vlan_header)) {
			/*
			 * Strip off the vtag
			 */
			ovbcopy(mp->b_rptr, mp->b_rptr + VLAN_TAGSZ,
			    2 * ETHERADDRL);
			mp->b_rptr += VLAN_TAGSZ;
		}

		/*
		 * Pass the packet on.
		 */
		putnext(dsp->ds_rq, mp);

		/*
		 * Move on to the next packet in the chain.
		 */
		mp = next;
	} while (mp != NULL);
}

/*
 * Fast-path receive function.
 */
/*ARGSUSED*/
void
dld_str_rx_fastpath(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    size_t header_length)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	mblk_t			*next;

	ASSERT(mp != NULL);
	do {
		/*
		 * Get the pointer to the next packet in the chain and then
		 * clear b_next before the packet gets passed on.
		 */
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Pass the packet on.
		 */
		putnext(dsp->ds_rq, mp);

		/*
		 * Move on to the next packet in the chain.
		 */
		mp = next;
	} while (mp != NULL);
}

/*
 * Default receive function (send DL_UNITDATA_IND messages).
 */
/*ARGSUSED*/
void
dld_str_rx_unitdata(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    size_t header_length)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	mblk_t			*ud_mp;
	mblk_t			*next;

	ASSERT(mp != NULL);
	do {
		/*
		 * Get the pointer to the next packet in the chain and then
		 * clear b_next before the packet gets passed on.
		 */
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Wind back b_rptr to point at the MAC header.
		 */
		ASSERT(mp->b_rptr >= DB_BASE(mp) + header_length);
		mp->b_rptr -= header_length;

		/*
		 * Create the DL_UNITDATA_IND M_PROTO.
		 */
		if ((ud_mp = str_unitdata_ind(dsp, mp)) == NULL) {
			freemsgchain(mp);
			return;
		}

		/*
		 * Advance b_rptr to point at the payload again.
		 */
		mp->b_rptr += header_length;

		/*
		 * Prepend the DL_UNITDATA_IND.
		 */
		ud_mp->b_cont = mp;

		/*
		 * Send the message.
		 */
		putnext(dsp->ds_rq, ud_mp);

		/*
		 * Move on to the next packet in the chain.
		 */
		mp = next;
	} while (mp != NULL);
}

/*
 * Generate DL_NOTIFY_IND messages to notify the DLPI consumer of the
 * current state of the interface.
 */
void
dld_str_notify_ind(dld_str_t *dsp)
{
	mac_notify_type_t	type;

	for (type = 0; type < MAC_NNOTE; type++)
		str_notify(dsp, type);
}

typedef struct dl_unitdata_ind_wrapper {
	dl_unitdata_ind_t	dl_unitdata;
	uint8_t			dl_dest_addr[MAXADDRLEN + sizeof (uint16_t)];
	uint8_t			dl_src_addr[MAXADDRLEN + sizeof (uint16_t)];
} dl_unitdata_ind_wrapper_t;

/*
 * Create a DL_UNITDATA_IND M_PROTO message.
 */
static mblk_t *
str_unitdata_ind(dld_str_t *dsp, mblk_t *mp)
{
	mblk_t				*nmp;
	dl_unitdata_ind_wrapper_t	*dlwp;
	dl_unitdata_ind_t		*dlp;
	dls_header_info_t		dhi;
	uint_t				addr_length;
	uint8_t				*daddr;
	uint8_t				*saddr;

	/*
	 * Get the packet header information.
	 */
	dls_header_info(dsp->ds_dc, mp, &dhi);

	/*
	 * Allocate a message large enough to contain the wrapper structure
	 * defined above.
	 */
	if ((nmp = mexchange(dsp->ds_wq, NULL,
	    sizeof (dl_unitdata_ind_wrapper_t), M_PROTO,
	    DL_UNITDATA_IND)) == NULL)
		return (NULL);

	dlwp = (dl_unitdata_ind_wrapper_t *)nmp->b_rptr;

	dlp = &(dlwp->dl_unitdata);
	ASSERT(dlp == (dl_unitdata_ind_t *)nmp->b_rptr);
	ASSERT(dlp->dl_primitive == DL_UNITDATA_IND);

	/*
	 * Copy in the destination address.
	 */
	addr_length = dsp->ds_mip->mi_addr_length;
	daddr = dlwp->dl_dest_addr;
	dlp->dl_dest_addr_offset = (uintptr_t)daddr - (uintptr_t)dlp;
	bcopy(dhi.dhi_daddr, daddr, addr_length);

	/*
	 * Set the destination DLSAP to our bound DLSAP value.
	 */
	*(uint16_t *)(daddr + addr_length) = dsp->ds_sap;
	dlp->dl_dest_addr_length = addr_length + sizeof (uint16_t);

	/*
	 * If the destination address was a group address then
	 * dl_group_address field should be non-zero.
	 */
	dlp->dl_group_address = dhi.dhi_isgroup;

	/*
	 * Copy in the source address.
	 */
	saddr = dlwp->dl_src_addr;
	dlp->dl_src_addr_offset = (uintptr_t)saddr - (uintptr_t)dlp;
	bcopy(dhi.dhi_saddr, saddr, addr_length);

	/*
	 * Set the source DLSAP to the packet ethertype.
	 */
	*(uint16_t *)(saddr + addr_length) = dhi.dhi_ethertype;
	dlp->dl_src_addr_length = addr_length + sizeof (uint16_t);

	return (nmp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_PROMISC_ON_PHYS
 */
static void
str_notify_promisc_on_phys(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_PROMISC_ON_PHYS))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_PROMISC_ON_PHYS;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_PROMISC_OFF_PHYS
 */
static void
str_notify_promisc_off_phys(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_PROMISC_OFF_PHYS))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_PROMISC_OFF_PHYS;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_PHYS_ADDR
 */
static void
str_notify_phys_addr(dld_str_t *dsp, const uint8_t *addr)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;
	uint_t		addr_length;
	uint16_t	ethertype;

	if (!(dsp->ds_notifications & DL_NOTE_PHYS_ADDR))
		return;

	addr_length = dsp->ds_mip->mi_addr_length;
	if ((mp = mexchange(dsp->ds_wq, NULL,
	    sizeof (dl_notify_ind_t) + addr_length + sizeof (uint16_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_PHYS_ADDR;
	dlip->dl_data = DL_CURR_PHYS_ADDR;
	dlip->dl_addr_offset = sizeof (dl_notify_ind_t);
	dlip->dl_addr_length = addr_length + sizeof (uint16_t);

	bcopy(addr, &dlip[1], addr_length);

	ethertype = (dsp->ds_sap < ETHERTYPE_802_MIN) ? 0 : dsp->ds_sap;
	*(uint16_t *)((uchar_t *)(dlip + 1) + addr_length) =
		ethertype;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_LINK_UP
 */
static void
str_notify_link_up(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_LINK_UP))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_LINK_UP;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_LINK_DOWN
 */
static void
str_notify_link_down(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_LINK_DOWN))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_LINK_DOWN;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_SPEED
 */
static void
str_notify_speed(dld_str_t *dsp, uint32_t speed)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_SPEED))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_SPEED;
	dlip->dl_data = speed;

	qreply(dsp->ds_wq, mp);
}

/*
 * DL_NOTIFY_IND: DL_NOTE_CAPAB_RENEG
 */
static void
str_notify_capab_reneg(dld_str_t *dsp)
{
	mblk_t		*mp;
	dl_notify_ind_t	*dlip;

	if (!(dsp->ds_notifications & DL_NOTE_CAPAB_RENEG))
		return;

	if ((mp = mexchange(dsp->ds_wq, NULL, sizeof (dl_notify_ind_t),
	    M_PROTO, 0)) == NULL)
		return;

	bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
	dlip = (dl_notify_ind_t *)mp->b_rptr;
	dlip->dl_primitive = DL_NOTIFY_IND;
	dlip->dl_notification = DL_NOTE_CAPAB_RENEG;

	qreply(dsp->ds_wq, mp);
}

/*
 * MAC notification callback.
 */
static void
str_notify(void *arg, mac_notify_type_t type)
{
	dld_str_t		*dsp = (dld_str_t *)arg;
	queue_t			*q = dsp->ds_wq;

	switch (type) {
	case MAC_NOTE_TX:
		enableok(q);
		qenable(q);
		break;

	case MAC_NOTE_DEVPROMISC:
		/*
		 * Send the appropriate DL_NOTIFY_IND.
		 */
		if (mac_promisc_get(dsp->ds_mh, MAC_DEVPROMISC))
			str_notify_promisc_on_phys(dsp);
		else
			str_notify_promisc_off_phys(dsp);
		break;

	case MAC_NOTE_PROMISC:
		break;

	case MAC_NOTE_UNICST:
		/*
		 * This notification is sent whenever the MAC unicast address
		 * changes. We need to re-cache the address.
		 */
		mac_unicst_get(dsp->ds_mh, dsp->ds_curr_addr);

		/*
		 * Send the appropriate DL_NOTIFY_IND.
		 */
		str_notify_phys_addr(dsp, dsp->ds_curr_addr);
		break;

	case MAC_NOTE_LINK:
		/*
		 * This notification is sent every time the MAC driver
		 * updates the link state.
		 */
		switch (mac_link_get(dsp->ds_mh)) {
		case LINK_STATE_UP:
			/*
			 * The link is up so send the appropriate
			 * DL_NOTIFY_IND.
			 */
			str_notify_link_up(dsp);

			/*
			 * If we can find the link speed then send a
			 * DL_NOTIFY_IND for that too.
			 */
			if (dsp->ds_mip->mi_stat[MAC_STAT_IFSPEED]) {
				uint64_t	val;

				val = mac_stat_get(dsp->ds_mh,
				    MAC_STAT_IFSPEED);
				str_notify_speed(dsp,
				    (uint32_t)(val / 1000ull));
			}
			break;

		case LINK_STATE_DOWN:
			/*
			 * The link is down so send the appropriate
			 * DL_NOTIFY_IND.
			 */
			str_notify_link_down(dsp);
			break;

		default:
			break;
		}
		break;

	case MAC_NOTE_RESOURCE:
		/*
		 * This notification is sent whenever the MAC resources
		 * change. We need to renegotiate the capabilities.
		 * Send the appropriate DL_NOTIFY_IND.
		 */
		str_notify_capab_reneg(dsp);
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}
}

/*
 * Put a chain of packets back on the queue.
 */
static void
str_putbq(queue_t *q, mblk_t *mp)
{
	mblk_t	*bp = NULL;
	mblk_t	*nextp;

	/*
	 * Reverse the order of the chain.
	 */
	while (mp != NULL) {
		nextp = mp->b_next;

		mp->b_next = bp;
		bp = mp;

		mp = nextp;
	}

	/*
	 * Walk the reversed chain and put each message back on the
	 * queue.
	 */
	while (bp != NULL) {
		nextp = bp->b_next;
		bp->b_next = NULL;

		(void) putbq(q, bp);

		bp = nextp;
	}
}
