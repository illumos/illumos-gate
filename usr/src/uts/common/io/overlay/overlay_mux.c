/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Overlay device ksocket multiplexer.
 *
 * For more information, see the big theory statement in
 * uts/common/io/overlay/overlay.c
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ksynch.h>
#include <sys/ksocket.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/pattr.h>
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/tihdr.h>

#include <sys/overlay_impl.h>

#include <sys/sdt.h>

#define	OVERLAY_FREEMSG(mp, reason) \
    DTRACE_PROBE2(overlay__fremsg, mblk_t *, mp, char *, reason)

static list_t overlay_mux_list;
static kmutex_t overlay_mux_lock;

void
overlay_mux_init(void)
{
	list_create(&overlay_mux_list, sizeof (overlay_mux_t),
	    offsetof(overlay_mux_t, omux_lnode));
	mutex_init(&overlay_mux_lock, NULL, MUTEX_DRIVER, NULL);
}

void
overlay_mux_fini(void)
{
	mutex_destroy(&overlay_mux_lock);
	list_destroy(&overlay_mux_list);
}

static int
overlay_mux_comparator(const void *a, const void *b)
{
	const overlay_dev_t *odl, *odr;
	odl = a;
	odr = b;
	if (odl->odd_vid > odr->odd_vid)
		return (1);
	else if (odl->odd_vid < odr->odd_vid)
		return (-1);
	else
		return (0);
}

/*
 * This is the central receive data path. We need to decode the packet, if we
 * can, and then deliver it to the appropriate overlay.
 */
/* ARGSUSED */
static boolean_t
overlay_mux_recv(ksocket_t ks, mblk_t *mpchain, size_t msgsize, int oob,
    void *arg)
{
	mblk_t *mp, *nmp, *fmp;
	overlay_mux_t *mux = arg;

	/*
	 * We may have a received a chain of messages. Each messsage in the
	 * chain will likely have a T_unitdata_ind attached to it as an M_PROTO.
	 * If we aren't getting that, we should probably drop that for the
	 * moment.
	 */
	for (mp = mpchain; mp != NULL; mp = nmp) {
		struct T_unitdata_ind *tudi;
		ovep_encap_info_t infop;
		overlay_dev_t od, *odd;
		int ret;

		nmp = mp->b_next;
		mp->b_next = NULL;

		if (DB_TYPE(mp) != M_PROTO) {
			OVERLAY_FREEMSG(mp, "first one isn't M_PROTO");
			freemsg(mp);
			continue;
		}

		if (mp->b_cont == NULL) {
			OVERLAY_FREEMSG(mp, "missing a b_cont");
			freemsg(mp);
			continue;
		}

		tudi = (struct T_unitdata_ind *)mp->b_rptr;
		if (tudi->PRIM_type != T_UNITDATA_IND) {
			OVERLAY_FREEMSG(mp, "Not a T_unitdata_ind *");
			freemsg(mp);
			continue;
		}

		/*
		 * In the future, we'll care about the source information
		 * for purposes of telling varpd for oob invalidation. But for
		 * now, just drop that block.
		 */
		fmp = mp;
		mp = fmp->b_cont;
		freeb(fmp);

		/*
		 * Until we have VXLAN-or-other-decap HW acceleration support
		 * (e.g.  we support NICs that reach into VXLAN-encapsulated
		 * packets and check the inside-VXLAN IP packets' checksums,
		 * or do LSO with VXLAN), we should clear any HW-accelerated-
		 * performed bits.
		 *
		 * We do this, even in cases of HW_LOCAL_MAC, because we
		 * absolutely have NO context about the inner packet.
		 * It could've arrived off an external NIC and been forwarded
		 * to the overlay network, which means no context.
		 */
		DB_CKSUMFLAGS(mp) = 0;

		/*
		 * Decap and deliver.
		 */
		bzero(&infop, sizeof (ovep_encap_info_t));
		ret = mux->omux_plugin->ovp_ops->ovpo_decap(NULL, mp, &infop);
		if (ret != 0) {
			OVERLAY_FREEMSG(mp, "decap failed");
			freemsg(mp);
			continue;
		}
		if (MBLKL(mp) > infop.ovdi_hdr_size) {
			mp->b_rptr += infop.ovdi_hdr_size;
		} else {
			while (infop.ovdi_hdr_size != 0) {
				size_t rem, blkl;

				if (mp == NULL)
					break;

				blkl = MBLKL(mp);
				rem = MIN(infop.ovdi_hdr_size, blkl);
				infop.ovdi_hdr_size -= rem;
				mp->b_rptr += rem;
				if (rem == blkl) {
					fmp = mp;
					mp = fmp->b_cont;
					fmp->b_cont = NULL;
					OVERLAY_FREEMSG(mp,
					    "freed a fmp block");
					freemsg(fmp);
				}
			}
			if (mp == NULL) {
				OVERLAY_FREEMSG(mp, "freed it all...");
				continue;
			}
		}


		od.odd_vid = infop.ovdi_id;
		mutex_enter(&mux->omux_lock);
		odd = avl_find(&mux->omux_devices, &od, NULL);
		if (odd == NULL) {
			mutex_exit(&mux->omux_lock);
			OVERLAY_FREEMSG(mp, "no matching vid");
			freemsg(mp);
			continue;
		}
		mutex_enter(&odd->odd_lock);
		if ((odd->odd_flags & OVERLAY_F_MDDROP) ||
		    !(odd->odd_flags & OVERLAY_F_IN_MUX)) {
			mutex_exit(&odd->odd_lock);
			mutex_exit(&mux->omux_lock);
			OVERLAY_FREEMSG(mp, "dev dropped");
			freemsg(mp);
			continue;
		}
		overlay_io_start(odd, OVERLAY_F_IN_RX);
		mutex_exit(&odd->odd_lock);
		mutex_exit(&mux->omux_lock);

		mac_rx(odd->odd_mh, NULL, mp);

		mutex_enter(&odd->odd_lock);
		overlay_io_done(odd, OVERLAY_F_IN_RX);
		mutex_exit(&odd->odd_lock);
	}

	return (B_TRUE);
}

/*
 * Register a given device with a socket backend. If no such device socket
 * exists, create a new one.
 */
overlay_mux_t *
overlay_mux_open(overlay_plugin_t *opp, int domain, int family, int protocol,
    struct sockaddr *addr, socklen_t len, int *errp)
{
	int err;
	overlay_mux_t *mux;
	ksocket_t ksock;

	if (errp == NULL)
		errp = &err;

	mutex_enter(&overlay_mux_lock);
	for (mux = list_head(&overlay_mux_list); mux != NULL;
	    mux = list_next(&overlay_mux_list, mux)) {
		if (domain == mux->omux_domain &&
		    family == mux->omux_family &&
		    protocol == mux->omux_protocol &&
		    len == mux->omux_alen &&
		    bcmp(addr, mux->omux_addr, len) == 0) {

			if (opp != mux->omux_plugin) {
				*errp = EEXIST;
				return (NULL);
			}

			mutex_enter(&mux->omux_lock);
			mux->omux_count++;
			mutex_exit(&mux->omux_lock);
			mutex_exit(&overlay_mux_lock);
			*errp = 0;
			return (mux);
		}
	}

	/*
	 * Today we aren't zone-aware and only exist in the global zone. When we
	 * allow for things to exist in the non-global zone, we'll want to use a
	 * credential that's actually specific to the zone.
	 */
	*errp = ksocket_socket(&ksock, domain, family, protocol, KSOCKET_SLEEP,
	    kcred);
	if (*errp != 0) {
		mutex_exit(&overlay_mux_lock);
		return (NULL);
	}

	*errp = ksocket_bind(ksock, addr, len, kcred);
	if (*errp != 0) {
		mutex_exit(&overlay_mux_lock);
		ksocket_close(ksock, kcred);
		return (NULL);
	}

	/*
	 * Ask our lower layer to optionally toggle anything they need on this
	 * socket. Because a socket is owned by a single type of plugin, we can
	 * then ask it to perform any additional socket set up it'd like to do.
	 */
	if (opp->ovp_ops->ovpo_sockopt != NULL &&
	    (*errp = opp->ovp_ops->ovpo_sockopt(ksock)) != 0) {
		mutex_exit(&overlay_mux_lock);
		ksocket_close(ksock, kcred);
		return (NULL);
	}

	mux = kmem_alloc(sizeof (overlay_mux_t), KM_SLEEP);
	list_link_init(&mux->omux_lnode);
	mux->omux_ksock = ksock;
	mux->omux_plugin = opp;
	mux->omux_domain = domain;
	mux->omux_family = family;
	mux->omux_protocol = protocol;
	mux->omux_addr = kmem_alloc(len, KM_SLEEP);
	bcopy(addr, mux->omux_addr, len);
	mux->omux_alen = len;
	mux->omux_count = 1;
	avl_create(&mux->omux_devices, overlay_mux_comparator,
	    sizeof (overlay_dev_t), offsetof(overlay_dev_t, odd_muxnode));
	mutex_init(&mux->omux_lock, NULL, MUTEX_DRIVER, NULL);


	/* Once this is called, we need to expect to rx data */
	*errp = ksocket_krecv_set(ksock, overlay_mux_recv, mux);
	if (*errp != 0) {
		ksocket_close(ksock, kcred);
		mutex_destroy(&mux->omux_lock);
		avl_destroy(&mux->omux_devices);
		kmem_free(mux->omux_addr, len);
		kmem_free(mux, sizeof (overlay_mux_t));
		return (NULL);
	}

	list_insert_tail(&overlay_mux_list, mux);
	mutex_exit(&overlay_mux_lock);

	*errp = 0;
	return (mux);
}

void
overlay_mux_close(overlay_mux_t *mux)
{
	mutex_enter(&overlay_mux_lock);
	mutex_enter(&mux->omux_lock);
	mux->omux_count--;
	if (mux->omux_count != 0) {
		mutex_exit(&mux->omux_lock);
		mutex_exit(&overlay_mux_lock);
		return;
	}
	list_remove(&overlay_mux_list, mux);
	mutex_exit(&mux->omux_lock);
	mutex_exit(&overlay_mux_lock);

	ksocket_close(mux->omux_ksock, kcred);
	avl_destroy(&mux->omux_devices);
	kmem_free(mux->omux_addr, mux->omux_alen);
	kmem_free(mux, sizeof (overlay_mux_t));
}

void
overlay_mux_add_dev(overlay_mux_t *mux, overlay_dev_t *odd)
{
	mutex_enter(&mux->omux_lock);
	avl_add(&mux->omux_devices, odd);
	mutex_exit(&mux->omux_lock);
}

void
overlay_mux_remove_dev(overlay_mux_t *mux, overlay_dev_t *odd)
{
	mutex_enter(&mux->omux_lock);
	avl_remove(&mux->omux_devices, odd);
	mutex_exit(&mux->omux_lock);
}

int
overlay_mux_tx(overlay_mux_t *mux, struct msghdr *hdr, mblk_t *mp)
{
	int ret;

	/*
	 * It'd be nice to be able to use MSG_MBLK_QUICKRELE, unfortunately,
	 * that isn't actually supported by UDP at this time.
	 */
	ret = ksocket_sendmblk(mux->omux_ksock, hdr, 0, &mp, kcred);
	if (ret != 0)
		freemsg(mp);

	return (ret);
}
