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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019, Joyent, Inc.
 * Copyright 2022 Garrett D'Amore
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Softmac data-path switching:
 *
 * - Fast-path model
 *
 * When the softmac fast-path is used, a dedicated lower-stream
 * will be opened over the legacy device for each IP/ARP (upper-)stream
 * over the softMAC, and all DLPI messages (including control messages
 * and data messages) will be exchanged between the upper-stream and
 * the corresponding lower-stream directly. Therefore, the data
 * demultiplexing, filtering and classification processing will be done
 * by the lower-stream, and the GLDv3 DLS/MAC layer processing will be
 * no longer needed.
 *
 * - Slow-path model
 *
 * Some GLDv3 features requires the GLDv3 DLS/MAC layer processing to
 * not be bypassed to assure its function correctness. For example,
 * softmac fast-path must be disabled to support GLDv3 VNIC functionality.
 * In this case, a shared lower-stream will be opened over the legacy
 * device, which is responsible for implementing the GLDv3 callbacks
 * and passing RAW data messages between the legacy devices and the GLDv3
 * framework.
 *
 * By default, the softmac fast-path mode will be used to assure the
 * performance; MAC clients will be able to request to disable the softmac
 * fast-path mode to support certain features, and if that succeeds,
 * the system will fallback to the slow-path softmac data-path model.
 *
 *
 * The details of the softmac data fast-path model is stated as below
 *
 * 1. When a stream is opened on a softMAC, the softmac module will takes
 *    over the DLPI processing on this stream;
 *
 * 2. For IP/ARP streams over a softMAC, softmac data fast-path will be
 *    used by default, unless fast-path is disabled by any MAC client
 *    explicitly. The softmac module first identifies an IP/ARP stream
 *    by seeing whether there is a SIOCSLIFNAME ioctl sent from upstream,
 *    if there is one, this stream is either an IP or an ARP stream
 *    and will use fast-path potentially;
 *
 * 3. When the softmac fast-path is used, an dedicated lower-stream will
 *    be setup for each IP/ARP stream (1-1 mapping). From that point on,
 *    all control and data messages will be exchanged between the IP/ARP
 *    upper-stream and the legacy device through this dedicated
 *    lower-stream. As a result, the DLS/MAC layer processing in GLDv3
 *    will be skipped, and this greatly improves the performance;
 *
 * 4. When the softmac data fast-path is disabled by a MAC client (e.g.,
 *    by a VNIC), all the IP/ARP upper streams will try to switch from
 *    the fast-path to the slow-path. The dedicated lower-stream will be
 *    destroyed, and all the control and data-messages will go through the
 *    existing GLDv3 code path and (in the end) the shared lower-stream;
 *
 * 5. On the other hand, when the last MAC client cancels its fast-path
 *    disable request, all the IP/ARP streams will try to switch back to
 *    the fast-path mode;
 *
 * Step 5 and 6 both rely on the data-path mode switching process
 * described below:
 *
 * 1) To switch the softmac data-path mode (between fast-path and slow-path),
 *    softmac will first send a DL_NOTE_REPLUMB DL_NOTIFY_IND message
 *    upstream over each IP/ARP streams that needs data-path mode switching;
 *
 * 2) When IP receives this DL_NOTE_REPLUMB message, it will bring down
 *    all the IP interfaces on the corresponding ill (IP Lower level
 *    structure), and bring up those interfaces over again; this will in
 *    turn cause the ARP to "replumb" the interface.
 *
 *    During the replumb process, both IP and ARP will send downstream the
 *    necessary DL_DISABMULTI_REQ and DL_UNBIND_REQ messages and cleanup
 *    the old state of the underlying softMAC, following with the necessary
 *    DL_BIND_REQ and DL_ENABMULTI_REQ messages to setup the new state.
 *    Between the cleanup and re-setup process, IP/ARP will also send down
 *    a DL_NOTE_REPLUMB_DONE DL_NOTIFY_CONF messages to the softMAC to
 *    indicate the *switching point*;
 *
 * 3) When softmac receives the DL_NOTE_REPLUMB_DONE message, it either
 *    creates or destroys the dedicated lower-stream (depending on which
 *    data-path mode the softMAC switches to), and change the softmac
 *    data-path mode. From then on, softmac will process all the succeeding
 *    control messages (including the DL_BIND_REQ and DL_ENABMULTI_REQ
 *    messages) and data messages based on new data-path mode.
 */

#include <sys/types.h>
#include <sys/disp.h>
#include <sys/callb.h>
#include <sys/sysmacros.h>
#include <sys/file.h>
#include <sys/vlan.h>
#include <sys/dld.h>
#include <sys/sockio.h>
#include <sys/softmac_impl.h>
#include <net/if.h>

static kmutex_t		softmac_taskq_lock;
static kthread_t	*softmac_taskq_thread;
static kcondvar_t	softmac_taskq_cv;
static list_t		softmac_taskq_list;	/* List of softmac_upper_t */
boolean_t		softmac_taskq_quit;
boolean_t		softmac_taskq_done;

static void		softmac_taskq_dispatch();
static int		softmac_fastpath_setup(softmac_upper_t *);
static mac_tx_cookie_t	softmac_fastpath_wput_data(softmac_upper_t *, mblk_t *,
			    uintptr_t, uint16_t);
static void		softmac_datapath_switch_done(softmac_upper_t *);

void
softmac_fp_init()
{
	mutex_init(&softmac_taskq_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&softmac_taskq_cv, NULL, CV_DRIVER, NULL);

	softmac_taskq_quit = B_FALSE;
	softmac_taskq_done = B_FALSE;
	list_create(&softmac_taskq_list, sizeof (softmac_upper_t),
	    offsetof(softmac_upper_t, su_taskq_list_node));
	softmac_taskq_thread = thread_create(NULL, 0, softmac_taskq_dispatch,
	    NULL, 0, &p0, TS_RUN, minclsyspri);
}

void
softmac_fp_fini()
{
	/*
	 * Request the softmac_taskq thread to quit and wait for it to be done.
	 */
	mutex_enter(&softmac_taskq_lock);
	softmac_taskq_quit = B_TRUE;
	cv_signal(&softmac_taskq_cv);
	while (!softmac_taskq_done)
		cv_wait(&softmac_taskq_cv, &softmac_taskq_lock);
	mutex_exit(&softmac_taskq_lock);
	thread_join(softmac_taskq_thread->t_did);
	list_destroy(&softmac_taskq_list);

	mutex_destroy(&softmac_taskq_lock);
	cv_destroy(&softmac_taskq_cv);
}

static boolean_t
check_ip_above(queue_t *q)
{
	queue_t		*next_q;
	boolean_t	ret = B_TRUE;

	claimstr(q);
	next_q = q->q_next;
	if (strcmp(next_q->q_qinfo->qi_minfo->mi_idname, "ip") != 0)
		ret = B_FALSE;
	releasestr(q);
	return (ret);
}

/* ARGSUSED */
static int
softmac_capab_perim(softmac_upper_t *sup, void *data, uint_t flags)
{
	switch (flags) {
	case DLD_ENABLE:
		mutex_enter(&sup->su_mutex);
		break;
	case DLD_DISABLE:
		mutex_exit(&sup->su_mutex);
		break;
	case DLD_QUERY:
		return (MUTEX_HELD(&sup->su_mutex));
	}
	return (0);
}

static mac_tx_notify_handle_t
softmac_client_tx_notify(softmac_upper_t *sup, mac_tx_notify_t func, void *arg)
{
	ASSERT(MUTEX_HELD(&sup->su_mutex));

	if (func != NULL) {
		sup->su_tx_notify_func = func;
		sup->su_tx_notify_arg = arg;
	} else {
		/*
		 * Wait for all tx_notify_func call to be done.
		 */
		while (sup->su_tx_inprocess != 0)
			cv_wait(&sup->su_cv, &sup->su_mutex);

		sup->su_tx_notify_func = NULL;
		sup->su_tx_notify_arg = NULL;
	}
	return ((mac_tx_notify_handle_t)sup);
}

static boolean_t
softmac_tx_is_flow_blocked(softmac_upper_t *sup, mac_tx_cookie_t cookie)
{
	ASSERT(cookie == (mac_tx_cookie_t)sup);
	return (sup->su_tx_busy);
}

static int
softmac_capab_direct(softmac_upper_t *sup, void *data, uint_t flags)
{
	dld_capab_direct_t	*direct = data;
	softmac_lower_t		*slp = sup->su_slp;

	ASSERT(MUTEX_HELD(&sup->su_mutex));

	ASSERT(sup->su_mode == SOFTMAC_FASTPATH);

	switch (flags) {
	case DLD_ENABLE:
		if (sup->su_direct)
			return (0);

		sup->su_direct_rxinfo.slr_rx = (softmac_rx_t)direct->di_rx_cf;
		sup->su_direct_rxinfo.slr_arg = direct->di_rx_ch;
		slp->sl_rxinfo = &sup->su_direct_rxinfo;
		direct->di_tx_df = (uintptr_t)softmac_fastpath_wput_data;
		direct->di_tx_dh = sup;
		direct->di_tx_fctl_df = (uintptr_t)softmac_tx_is_flow_blocked;
		direct->di_tx_fctl_dh = sup;
		direct->di_tx_cb_df = (uintptr_t)softmac_client_tx_notify;
		direct->di_tx_cb_dh = sup;
		sup->su_direct = B_TRUE;
		return (0);

	case DLD_DISABLE:
		if (!sup->su_direct)
			return (0);

		slp->sl_rxinfo = &sup->su_rxinfo;
		sup->su_direct = B_FALSE;
		return (0);
	}
	return (ENOTSUP);
}

static int
softmac_dld_capab(softmac_upper_t *sup, uint_t type, void *data, uint_t flags)
{
	int	err;

	/*
	 * Don't enable direct callback capabilities unless the caller is
	 * the IP client. When a module is inserted in a stream (_I_INSERT)
	 * the stack initiates capability disable, but due to races, the
	 * module insertion may complete before the capability disable
	 * completes. So we limit the check to DLD_ENABLE case.
	 */
	if ((flags == DLD_ENABLE && type != DLD_CAPAB_PERIM) &&
	    !check_ip_above(sup->su_rq)) {
		return (ENOTSUP);
	}

	switch (type) {
	case DLD_CAPAB_DIRECT:
		err = softmac_capab_direct(sup, data, flags);
		break;

	case DLD_CAPAB_PERIM:
		err = softmac_capab_perim(sup, data, flags);
		break;

	default:
		err = ENOTSUP;
		break;
	}
	return (err);
}

static void
softmac_capability_advertise(softmac_upper_t *sup, mblk_t *mp)
{
	dl_capability_ack_t	*dlap;
	dl_capability_sub_t	*dlsp;
	t_uscalar_t		subsize;
	uint8_t			*ptr;
	queue_t			*q = sup->su_wq;
	mblk_t			*mp1;
	softmac_t		*softmac = sup->su_softmac;
	boolean_t		dld_capable = B_FALSE;
	boolean_t		hcksum_capable = B_FALSE;
	boolean_t		zcopy_capable = B_FALSE;

	ASSERT(sup->su_mode == SOFTMAC_FASTPATH);

	/*
	 * Initially assume no capabilities.
	 */
	subsize = 0;

	/*
	 * Direct capability negotiation interface between IP and softmac
	 */
	if (check_ip_above(sup->su_rq)) {
		dld_capable = B_TRUE;
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_dld_t);
	}

	/*
	 * Check if checksum offload is supported on this MAC.
	 */
	if (softmac->smac_capab_flags & MAC_CAPAB_HCKSUM) {
		hcksum_capable = B_TRUE;
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_hcksum_t);
	}

	/*
	 * Check if zerocopy is supported on this interface.
	 */
	if (!(softmac->smac_capab_flags & MAC_CAPAB_NO_ZCOPY)) {
		zcopy_capable = B_TRUE;
		subsize += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_zerocopy_t);
	}

	/*
	 * If there are no capabilities to advertise or if we
	 * can't allocate a response, send a DL_ERROR_ACK.
	 */
	if ((subsize == 0) || (mp1 = reallocb(mp,
	    sizeof (dl_capability_ack_t) + subsize, 0)) == NULL) {
		dlerrorack(q, mp, DL_CAPABILITY_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	mp = mp1;
	DB_TYPE(mp) = M_PROTO;
	mp->b_wptr = mp->b_rptr + sizeof (dl_capability_ack_t) + subsize;
	bzero(mp->b_rptr, MBLKL(mp));
	dlap = (dl_capability_ack_t *)mp->b_rptr;
	dlap->dl_primitive = DL_CAPABILITY_ACK;
	dlap->dl_sub_offset = sizeof (dl_capability_ack_t);
	dlap->dl_sub_length = subsize;
	ptr = (uint8_t *)&dlap[1];

	/*
	 * IP polling interface.
	 */
	if (dld_capable) {
		dl_capab_dld_t		dld;

		dlsp = (dl_capability_sub_t *)ptr;
		dlsp->dl_cap = DL_CAPAB_DLD;
		dlsp->dl_length = sizeof (dl_capab_dld_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&dld, sizeof (dl_capab_dld_t));
		dld.dld_version = DLD_CURRENT_VERSION;
		dld.dld_capab = (uintptr_t)softmac_dld_capab;
		dld.dld_capab_handle = (uintptr_t)sup;

		dlcapabsetqid(&(dld.dld_mid), sup->su_rq);
		bcopy(&dld, ptr, sizeof (dl_capab_dld_t));
		ptr += sizeof (dl_capab_dld_t);
	}

	/*
	 * TCP/IP checksum offload.
	 */
	if (hcksum_capable) {
		dl_capab_hcksum_t	hcksum;

		dlsp = (dl_capability_sub_t *)ptr;

		dlsp->dl_cap = DL_CAPAB_HCKSUM;
		dlsp->dl_length = sizeof (dl_capab_hcksum_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&hcksum, sizeof (dl_capab_hcksum_t));
		hcksum.hcksum_version = HCKSUM_VERSION_1;
		hcksum.hcksum_txflags = softmac->smac_hcksum_txflags;
		dlcapabsetqid(&(hcksum.hcksum_mid), sup->su_rq);
		bcopy(&hcksum, ptr, sizeof (dl_capab_hcksum_t));
		ptr += sizeof (dl_capab_hcksum_t);
	}

	/*
	 * Zero copy
	 */
	if (zcopy_capable) {
		dl_capab_zerocopy_t	zcopy;

		dlsp = (dl_capability_sub_t *)ptr;

		dlsp->dl_cap = DL_CAPAB_ZEROCOPY;
		dlsp->dl_length = sizeof (dl_capab_zerocopy_t);
		ptr += sizeof (dl_capability_sub_t);

		bzero(&zcopy, sizeof (dl_capab_zerocopy_t));
		zcopy.zerocopy_version = ZEROCOPY_VERSION_1;
		zcopy.zerocopy_flags = DL_CAPAB_VMSAFE_MEM;
		dlcapabsetqid(&(zcopy.zerocopy_mid), sup->su_rq);
		bcopy(&zcopy, ptr, sizeof (dl_capab_zerocopy_t));
		ptr += sizeof (dl_capab_zerocopy_t);
	}

	ASSERT(ptr == mp->b_rptr + sizeof (dl_capability_ack_t) + subsize);
	qreply(q, mp);
}

static void
softmac_capability_req(softmac_upper_t *sup, mblk_t *mp)
{
	dl_capability_req_t	*dlp = (dl_capability_req_t *)mp->b_rptr;
	dl_capability_sub_t	*sp;
	size_t			size, len;
	offset_t		off, end;
	t_uscalar_t		dl_err;
	queue_t			*q = sup->su_wq;

	ASSERT(sup->su_mode == SOFTMAC_FASTPATH);
	if (MBLKL(mp) < sizeof (dl_capability_req_t)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	if (!sup->su_bound) {
		dl_err = DL_OUTSTATE;
		goto failed;
	}

	/*
	 * This request is overloaded. If there are no requested capabilities
	 * then we just want to acknowledge with all the capabilities we
	 * support. Otherwise we enable the set of capabilities requested.
	 */
	if (dlp->dl_sub_length == 0) {
		softmac_capability_advertise(sup, mp);
		return;
	}

	if (!MBLKIN(mp, dlp->dl_sub_offset, dlp->dl_sub_length)) {
		dl_err = DL_BADPRIM;
		goto failed;
	}

	dlp->dl_primitive = DL_CAPABILITY_ACK;

	off = dlp->dl_sub_offset;
	len = dlp->dl_sub_length;

	/*
	 * Walk the list of capabilities to be enabled.
	 */
	for (end = off + len; off < end; ) {
		sp = (dl_capability_sub_t *)(mp->b_rptr + off);
		size = sizeof (dl_capability_sub_t) + sp->dl_length;

		if (off + size > end ||
		    !IS_P2ALIGNED(off, sizeof (uint32_t))) {
			dl_err = DL_BADPRIM;
			goto failed;
		}

		switch (sp->dl_cap) {
		/*
		 * TCP/IP checksum offload to hardware.
		 */
		case DL_CAPAB_HCKSUM: {
			dl_capab_hcksum_t *hcksump;
			dl_capab_hcksum_t hcksum;

			hcksump = (dl_capab_hcksum_t *)&sp[1];
			/*
			 * Copy for alignment.
			 */
			bcopy(hcksump, &hcksum, sizeof (dl_capab_hcksum_t));
			dlcapabsetqid(&(hcksum.hcksum_mid), sup->su_rq);
			bcopy(&hcksum, hcksump, sizeof (dl_capab_hcksum_t));
			break;
		}

		default:
			break;
		}

		off += size;
	}
	qreply(q, mp);
	return;
failed:
	dlerrorack(q, mp, DL_CAPABILITY_REQ, dl_err, 0);
}

static void
softmac_bind_req(softmac_upper_t *sup, mblk_t *mp)
{
	softmac_lower_t	*slp = sup->su_slp;
	softmac_t	*softmac = sup->su_softmac;
	mblk_t		*ackmp, *mp1;
	int		err;

	if (MBLKL(mp) < DL_BIND_REQ_SIZE) {
		freemsg(mp);
		return;
	}

	/*
	 * Allocate ackmp incase the underlying driver does not ack timely.
	 */
	if ((mp1 = allocb(sizeof (dl_error_ack_t), BPRI_HI)) == NULL) {
		dlerrorack(sup->su_wq, mp, DL_BIND_REQ, DL_SYSERR, ENOMEM);
		return;
	}

	err = softmac_output(slp, mp, DL_BIND_REQ, DL_BIND_ACK, &ackmp);
	if (ackmp != NULL) {
		freemsg(mp1);
	} else {
		/*
		 * The driver does not ack timely.
		 */
		ASSERT(err == ENOMSG);
		ackmp = mp1;
	}
	if (err != 0)
		goto failed;

	/*
	 * Enable capabilities the underlying driver claims to support.
	 */
	if ((err = softmac_capab_enable(slp)) != 0)
		goto failed;

	/*
	 * Check whether this softmac is already marked as exclusively used,
	 * e.g., an aggregation is created over it. Fail the BIND_REQ if so.
	 */
	mutex_enter(&softmac->smac_active_mutex);
	if (softmac->smac_active) {
		mutex_exit(&softmac->smac_active_mutex);
		err = EBUSY;
		goto failed;
	}
	softmac->smac_nactive++;
	sup->su_active = B_TRUE;
	mutex_exit(&softmac->smac_active_mutex);
	sup->su_bound = B_TRUE;

	qreply(sup->su_wq, ackmp);
	return;
failed:
	if (err != 0) {
		dlerrorack(sup->su_wq, ackmp, DL_BIND_REQ, DL_SYSERR, err);
		return;
	}
}

static void
softmac_unbind_req(softmac_upper_t *sup, mblk_t *mp)
{
	softmac_lower_t	*slp = sup->su_slp;
	softmac_t	*softmac = sup->su_softmac;
	mblk_t		*ackmp, *mp1;
	int		err;

	if (MBLKL(mp) < DL_UNBIND_REQ_SIZE) {
		freemsg(mp);
		return;
	}

	if (!sup->su_bound) {
		dlerrorack(sup->su_wq, mp, DL_UNBIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	/*
	 * Allocate ackmp incase the underlying driver does not ack timely.
	 */
	if ((mp1 = allocb(sizeof (dl_error_ack_t), BPRI_HI)) == NULL) {
		dlerrorack(sup->su_wq, mp, DL_UNBIND_REQ, DL_SYSERR, ENOMEM);
		return;
	}

	err = softmac_output(slp, mp, DL_UNBIND_REQ, DL_OK_ACK, &ackmp);
	if (ackmp != NULL) {
		freemsg(mp1);
	} else {
		/*
		 * The driver does not ack timely.
		 */
		ASSERT(err == ENOMSG);
		ackmp = mp1;
	}
	if (err != 0) {
		dlerrorack(sup->su_wq, ackmp, DL_UNBIND_REQ, DL_SYSERR, err);
		return;
	}

	sup->su_bound = B_FALSE;

	mutex_enter(&softmac->smac_active_mutex);
	if (sup->su_active) {
		ASSERT(!softmac->smac_active);
		softmac->smac_nactive--;
		sup->su_active = B_FALSE;
	}
	mutex_exit(&softmac->smac_active_mutex);

done:
	qreply(sup->su_wq, ackmp);
}

/*
 * Process the non-data mblk.
 */
static void
softmac_wput_single_nondata(softmac_upper_t *sup, mblk_t *mp)
{
	softmac_t *softmac = sup->su_softmac;
	softmac_lower_t	*slp = sup->su_slp;
	unsigned char	dbtype;
	t_uscalar_t	prim;

	dbtype = DB_TYPE(mp);
	sup->su_is_arp = 0;
	switch (dbtype) {
	case M_CTL:
		sup->su_is_arp = 1;
		/* FALLTHROUGH */
	case M_IOCTL: {
		uint32_t	expected_mode;

		if (((struct iocblk *)(mp->b_rptr))->ioc_cmd != SIOCSLIFNAME)
			break;

		/*
		 * Nak the M_IOCTL based on the STREAMS specification.
		 */
		if (dbtype == M_IOCTL)
			miocnak(sup->su_wq, mp, 0, EINVAL);
		else
			freemsg(mp);

		/*
		 * This stream is either IP or ARP. See whether
		 * we need to setup a dedicated-lower-stream for it.
		 */
		mutex_enter(&softmac->smac_fp_mutex);

		expected_mode = DATAPATH_MODE(softmac);
		if (expected_mode == SOFTMAC_SLOWPATH)
			sup->su_mode = SOFTMAC_SLOWPATH;
		list_insert_head(&softmac->smac_sup_list, sup);
		mutex_exit(&softmac->smac_fp_mutex);

		/*
		 * Setup the fast-path dedicated lower stream if fast-path
		 * is expected. Note that no lock is held here, and if
		 * smac_expected_mode is changed from SOFTMAC_FASTPATH to
		 * SOFTMAC_SLOWPATH, the DL_NOTE_REPLUMB message used for
		 * data-path switching would already be queued and will
		 * be processed by softmac_wput_single_nondata() later.
		 */
		if (expected_mode == SOFTMAC_FASTPATH)
			(void) softmac_fastpath_setup(sup);
		return;
	}
	case M_PROTO:
	case M_PCPROTO:
		if (MBLKL(mp) < sizeof (t_uscalar_t)) {
			freemsg(mp);
			return;
		}
		prim = ((union DL_primitives *)mp->b_rptr)->dl_primitive;
		switch (prim) {
		case DL_NOTIFY_IND:
			if (MBLKL(mp) < sizeof (dl_notify_ind_t) ||
			    ((dl_notify_ind_t *)mp->b_rptr)->dl_notification !=
			    DL_NOTE_REPLUMB) {
				freemsg(mp);
				return;
			}
			/*
			 * This DL_NOTE_REPLUMB message is initiated
			 * and queued by the softmac itself, when the
			 * sup is trying to switching its datapath mode
			 * between SOFTMAC_SLOWPATH and SOFTMAC_FASTPATH.
			 * Send this message upstream.
			 */
			qreply(sup->su_wq, mp);
			return;
		case DL_NOTIFY_CONF:
			if (MBLKL(mp) < sizeof (dl_notify_conf_t) ||
			    ((dl_notify_conf_t *)mp->b_rptr)->dl_notification !=
			    DL_NOTE_REPLUMB_DONE) {
				freemsg(mp);
				return;
			}
			/*
			 * This is an indication from IP/ARP that the
			 * fastpath->slowpath switch is done.
			 */
			freemsg(mp);
			softmac_datapath_switch_done(sup);
			return;
		}
		break;
	}

	/*
	 * No need to hold lock to check su_mode, since su_mode updating only
	 * operation is is serialized by softmac_wput_nondata_task().
	 */
	if (sup->su_mode != SOFTMAC_FASTPATH) {
		(void) dld_wput(sup->su_wq, mp);
		return;
	}

	/*
	 * Fastpath non-data message processing. Most of non-data messages
	 * can be directly passed down to the dedicated-lower-stream, aside
	 * from the following M_PROTO/M_PCPROTO messages.
	 */
	switch (dbtype) {
	case M_PROTO:
	case M_PCPROTO:
		switch (prim) {
		case DL_BIND_REQ:
			softmac_bind_req(sup, mp);
			break;
		case DL_UNBIND_REQ:
			softmac_unbind_req(sup, mp);
			break;
		case DL_CAPABILITY_REQ:
			softmac_capability_req(sup, mp);
			break;
		default:
			putnext(slp->sl_wq, mp);
			break;
		}
		break;
	default:
		putnext(slp->sl_wq, mp);
		break;
	}
}

/*
 * The worker thread which processes non-data messages. Note we only process
 * one message at one time in order to be able to "flush" the queued message
 * and serialize the processing.
 */
static void
softmac_wput_nondata_task(void *arg)
{
	softmac_upper_t	*sup = arg;
	mblk_t		*mp;

	mutex_enter(&sup->su_disp_mutex);

	while (sup->su_pending_head != NULL) {
		if (sup->su_closing)
			break;

		SOFTMAC_DQ_PENDING(sup, &mp);
		mutex_exit(&sup->su_disp_mutex);
		softmac_wput_single_nondata(sup, mp);
		mutex_enter(&sup->su_disp_mutex);
	}

	/*
	 * If the stream is closing, flush all queued messages and inform
	 * the stream to be closed.
	 */
	freemsgchain(sup->su_pending_head);
	sup->su_pending_head = sup->su_pending_tail = NULL;
	sup->su_dlpi_pending = B_FALSE;
	cv_signal(&sup->su_disp_cv);
	mutex_exit(&sup->su_disp_mutex);
}

/*
 * Kernel thread to handle taskq dispatch failures in softmac_wput_nondata().
 * This thread is started when the softmac module is first loaded.
 */
static void
softmac_taskq_dispatch(void)
{
	callb_cpr_t	cprinfo;
	softmac_upper_t	*sup;

	CALLB_CPR_INIT(&cprinfo, &softmac_taskq_lock, callb_generic_cpr,
	    "softmac_taskq_dispatch");
	mutex_enter(&softmac_taskq_lock);

	while (!softmac_taskq_quit) {
		sup = list_head(&softmac_taskq_list);
		while (sup != NULL) {
			list_remove(&softmac_taskq_list, sup);
			sup->su_taskq_scheduled = B_FALSE;
			mutex_exit(&softmac_taskq_lock);
			VERIFY(taskq_dispatch(system_taskq,
			    softmac_wput_nondata_task, sup, TQ_SLEEP) !=
			    TASKQID_INVALID);
			mutex_enter(&softmac_taskq_lock);
			sup = list_head(&softmac_taskq_list);
		}

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&softmac_taskq_cv, &softmac_taskq_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &softmac_taskq_lock);
	}

	softmac_taskq_done = B_TRUE;
	cv_signal(&softmac_taskq_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

void
softmac_wput_nondata(softmac_upper_t *sup, mblk_t *mp)
{
	/*
	 * The processing of the message might block. Enqueue the
	 * message for later processing.
	 */
	mutex_enter(&sup->su_disp_mutex);

	if (sup->su_closing) {
		mutex_exit(&sup->su_disp_mutex);
		freemsg(mp);
		return;
	}

	SOFTMAC_EQ_PENDING(sup, mp);

	if (sup->su_dlpi_pending) {
		mutex_exit(&sup->su_disp_mutex);
		return;
	}
	sup->su_dlpi_pending = B_TRUE;
	mutex_exit(&sup->su_disp_mutex);

	if (taskq_dispatch(system_taskq, softmac_wput_nondata_task,
	    sup, TQ_NOSLEEP) != TASKQID_INVALID) {
		return;
	}

	mutex_enter(&softmac_taskq_lock);
	if (!sup->su_taskq_scheduled) {
		list_insert_tail(&softmac_taskq_list, sup);
		cv_signal(&softmac_taskq_cv);
	}
	sup->su_taskq_scheduled = B_TRUE;
	mutex_exit(&softmac_taskq_lock);
}

/*
 * Setup the dedicated-lower-stream (fast-path) for the IP/ARP upperstream.
 */
static int
softmac_fastpath_setup(softmac_upper_t *sup)
{
	softmac_t	*softmac = sup->su_softmac;
	softmac_lower_t	*slp;
	int		err;

	err = softmac_lower_setup(softmac, sup, &slp);

	mutex_enter(&sup->su_mutex);
	/*
	 * Wait for all data messages to be processed so that we can change
	 * the su_mode.
	 */
	while (sup->su_tx_inprocess != 0)
		cv_wait(&sup->su_cv, &sup->su_mutex);

	ASSERT(sup->su_mode != SOFTMAC_FASTPATH);
	ASSERT(sup->su_slp == NULL);
	if (err != 0) {
		sup->su_mode = SOFTMAC_SLOWPATH;
	} else {
		sup->su_slp = slp;
		sup->su_mode = SOFTMAC_FASTPATH;
	}
	mutex_exit(&sup->su_mutex);
	return (err);
}

/*
 * Tear down the dedicated-lower-stream (fast-path) for the IP/ARP upperstream.
 */
static void
softmac_fastpath_tear(softmac_upper_t *sup)
{
	mutex_enter(&sup->su_mutex);
	/*
	 * Wait for all data messages in the dedicated-lower-stream
	 * to be processed.
	 */
	while (sup->su_tx_inprocess != 0)
		cv_wait(&sup->su_cv, &sup->su_mutex);

	/*
	 * Note that this function is called either when the stream is closed,
	 * or the stream is unbound (fastpath-slowpath-switch). Therefore,
	 * No need to call the tx_notify callback.
	 */
	sup->su_tx_notify_func = NULL;
	sup->su_tx_notify_arg = NULL;
	if (sup->su_tx_busy) {
		ASSERT(sup->su_tx_flow_mp == NULL);
		VERIFY((sup->su_tx_flow_mp = getq(sup->su_wq)) != NULL);
		sup->su_tx_busy = B_FALSE;
	}

	sup->su_mode = SOFTMAC_SLOWPATH;

	/*
	 * Destroy the dedicated-lower-stream. Note that slp is destroyed
	 * when lh is closed.
	 */
	(void) ldi_close(sup->su_slp->sl_lh, FREAD|FWRITE, kcred);
	sup->su_slp = NULL;
	mutex_exit(&sup->su_mutex);
}

void
softmac_wput_data(softmac_upper_t *sup, mblk_t *mp)
{
	/*
	 * No lock is required to access the su_mode field since the data
	 * traffic is quiesce by IP when the data-path mode is in the
	 * process of switching.
	 */
	if (sup->su_mode != SOFTMAC_FASTPATH)
		(void) dld_wput(sup->su_wq, mp);
	else
		(void) softmac_fastpath_wput_data(sup, mp, (uintptr_t)NULL, 0);
}

/*ARGSUSED*/
static mac_tx_cookie_t
softmac_fastpath_wput_data(softmac_upper_t *sup, mblk_t *mp, uintptr_t f_hint,
    uint16_t flag)
{
	queue_t		*wq = sup->su_slp->sl_wq;

	/*
	 * This function is called from IP, only the MAC_DROP_ON_NO_DESC
	 * flag can be specified.
	 */
	ASSERT((flag & ~MAC_DROP_ON_NO_DESC) == 0);
	ASSERT(mp->b_next == NULL);

	/*
	 * Check wether the dedicated-lower-stream is able to handle more
	 * messages, and enable the flow-control if it is not.
	 *
	 * Note that in order not to introduce any packet reordering, we
	 * always send the message down to the dedicated-lower-stream:
	 *
	 * If the flow-control is already enabled, but we still get
	 * the messages from the upper-stream, it means that the upper
	 * stream does not respect STREAMS flow-control (e.g., TCP). Simply
	 * pass the message down to the lower-stream in that case.
	 */
	if (SOFTMAC_CANPUTNEXT(wq)) {
		putnext(wq, mp);
		return ((mac_tx_cookie_t)NULL);
	}

	if (sup->su_tx_busy) {
		if ((flag & MAC_DROP_ON_NO_DESC) != 0)
			freemsg(mp);
		else
			putnext(wq, mp);
		return ((mac_tx_cookie_t)sup);
	}

	mutex_enter(&sup->su_mutex);
	if (!sup->su_tx_busy) {
		/*
		 * If DLD_CAPAB_DIRECT is enabled, the notify callback will be
		 * called when the flow control can be disabled. Otherwise,
		 * put the tx_flow_mp into the wq to make use of the old
		 * streams flow control.
		 */
		ASSERT(sup->su_tx_flow_mp != NULL);
		(void) putq(sup->su_wq, sup->su_tx_flow_mp);
		sup->su_tx_flow_mp = NULL;
		sup->su_tx_busy = B_TRUE;
		qenable(wq);
	}
	mutex_exit(&sup->su_mutex);

	if ((flag & MAC_DROP_ON_NO_DESC) != 0)
		freemsg(mp);
	else
		putnext(wq, mp);
	return ((mac_tx_cookie_t)sup);
}

boolean_t
softmac_active_set(void *arg)
{
	softmac_t	*softmac = arg;

	mutex_enter(&softmac->smac_active_mutex);
	if (softmac->smac_nactive != 0) {
		mutex_exit(&softmac->smac_active_mutex);
		return (B_FALSE);
	}
	softmac->smac_active = B_TRUE;
	mutex_exit(&softmac->smac_active_mutex);
	return (B_TRUE);
}

void
softmac_active_clear(void *arg)
{
	softmac_t	*softmac = arg;

	mutex_enter(&softmac->smac_active_mutex);
	ASSERT(softmac->smac_active && (softmac->smac_nactive == 0));
	softmac->smac_active = B_FALSE;
	mutex_exit(&softmac->smac_active_mutex);
}

/*
 * Disable/reenable fastpath on given softmac. This request could come from a
 * MAC client or directly from administrators.
 */
int
softmac_datapath_switch(softmac_t *softmac, boolean_t disable, boolean_t admin)
{
	softmac_upper_t		*sup;
	mblk_t			*head = NULL, *tail = NULL, *mp;
	list_t			reqlist;
	softmac_switch_req_t	*req;
	uint32_t		current_mode, expected_mode;
	int			err = 0;

	mutex_enter(&softmac->smac_fp_mutex);

	current_mode = DATAPATH_MODE(softmac);
	if (admin) {
		if (softmac->smac_fastpath_admin_disabled == disable) {
			mutex_exit(&softmac->smac_fp_mutex);
			return (0);
		}
		softmac->smac_fastpath_admin_disabled = disable;
	} else if (disable) {
		softmac->smac_fp_disable_clients++;
	} else {
		ASSERT(softmac->smac_fp_disable_clients != 0);
		softmac->smac_fp_disable_clients--;
	}

	expected_mode = DATAPATH_MODE(softmac);
	if (current_mode == expected_mode) {
		mutex_exit(&softmac->smac_fp_mutex);
		return (0);
	}

	/*
	 * The expected mode is different from whatever datapath mode
	 * this softmac is expected from last request, enqueue the data-path
	 * switch request.
	 */
	list_create(&reqlist, sizeof (softmac_switch_req_t),
	    offsetof(softmac_switch_req_t, ssq_req_list_node));

	/*
	 * Allocate all DL_NOTIFY_IND messages and request structures that
	 * are required to switch each IP/ARP stream to the expected mode.
	 */
	for (sup = list_head(&softmac->smac_sup_list); sup != NULL;
	    sup = list_next(&softmac->smac_sup_list, sup)) {
		dl_notify_ind_t	*dlip;

		req = kmem_alloc(sizeof (softmac_switch_req_t), KM_NOSLEEP);
		if (req == NULL)
			break;

		req->ssq_expected_mode = expected_mode;
		if (sup->su_is_arp) {
			list_insert_tail(&reqlist, req);
			continue;
		}
		/*
		 * Allocate the DL_NOTE_REPLUMB message.
		 */
		if ((mp = allocb(sizeof (dl_notify_ind_t), BPRI_LO)) == NULL) {
			kmem_free(req, sizeof (softmac_switch_req_t));
			break;
		}

		list_insert_tail(&reqlist, req);

		mp->b_wptr = mp->b_rptr + sizeof (dl_notify_ind_t);
		mp->b_datap->db_type = M_PROTO;
		bzero(mp->b_rptr, sizeof (dl_notify_ind_t));
		dlip = (dl_notify_ind_t *)mp->b_rptr;
		dlip->dl_primitive = DL_NOTIFY_IND;
		dlip->dl_notification = DL_NOTE_REPLUMB;
		if (head == NULL) {
			head = tail = mp;
		} else {
			tail->b_next = mp;
			tail = mp;
		}
	}

	/*
	 * Note that it is fine if the expected data-path mode is fast-path
	 * and some of streams fails to switch. Only return failure if we
	 * are expected to switch to the slow-path.
	 */
	if (sup != NULL && expected_mode == SOFTMAC_SLOWPATH) {
		err = ENOMEM;
		goto fail;
	}

	/*
	 * Start switching for each IP/ARP stream. The switching operation
	 * will eventually succeed and there is no need to wait for it
	 * to finish.
	 */
	for (sup = list_head(&softmac->smac_sup_list); sup != NULL;
	    sup = list_next(&softmac->smac_sup_list, sup)) {
		if (!sup->su_is_arp) {
			mp = head->b_next;
			head->b_next = NULL;
			softmac_wput_nondata(sup, head);
			head = mp;
		}
		/*
		 * Add the switch request to the requests list of the stream.
		 */
		req = list_head(&reqlist);
		ASSERT(req != NULL);
		list_remove(&reqlist, req);
		list_insert_tail(&sup->su_req_list, req);
	}

	mutex_exit(&softmac->smac_fp_mutex);
	ASSERT(list_is_empty(&reqlist));
	list_destroy(&reqlist);
	return (0);
fail:
	if (admin) {
		softmac->smac_fastpath_admin_disabled = !disable;
	} else if (disable) {
		softmac->smac_fp_disable_clients--;
	} else {
		softmac->smac_fp_disable_clients++;
	}

	mutex_exit(&softmac->smac_fp_mutex);
	while ((req = list_head(&reqlist)) != NULL) {
		list_remove(&reqlist, req);
		kmem_free(req, sizeof (softmac_switch_req_t));
	}
	freemsgchain(head);
	list_destroy(&reqlist);
	return (err);
}

int
softmac_fastpath_disable(void *arg)
{
	return (softmac_datapath_switch((softmac_t *)arg, B_TRUE, B_FALSE));
}

void
softmac_fastpath_enable(void *arg)
{
	VERIFY(softmac_datapath_switch((softmac_t *)arg, B_FALSE,
	    B_FALSE) == 0);
}

void
softmac_upperstream_close(softmac_upper_t *sup)
{
	softmac_t		*softmac = sup->su_softmac;
	softmac_switch_req_t	*req;

	mutex_enter(&softmac->smac_fp_mutex);

	if (sup->su_mode == SOFTMAC_FASTPATH)
		softmac_fastpath_tear(sup);

	if (sup->su_mode != SOFTMAC_UNKNOWN) {
		list_remove(&softmac->smac_sup_list, sup);
		sup->su_mode = SOFTMAC_UNKNOWN;
	}

	/*
	 * Cleanup all the switch requests queueed on this stream.
	 */
	while ((req = list_head(&sup->su_req_list)) != NULL) {
		list_remove(&sup->su_req_list, req);
		kmem_free(req, sizeof (softmac_switch_req_t));
	}
	mutex_exit(&softmac->smac_fp_mutex);
}

/*
 * Handle the DL_NOTE_REPLUMB_DONE indication from IP/ARP. Change the upper
 * stream from the fastpath mode to the slowpath mode.
 */
static void
softmac_datapath_switch_done(softmac_upper_t *sup)
{
	softmac_t		*softmac = sup->su_softmac;
	softmac_switch_req_t	*req;
	uint32_t		expected_mode;

	mutex_enter(&softmac->smac_fp_mutex);
	req = list_head(&sup->su_req_list);
	list_remove(&sup->su_req_list, req);
	expected_mode = req->ssq_expected_mode;
	kmem_free(req, sizeof (softmac_switch_req_t));

	if (expected_mode == sup->su_mode) {
		mutex_exit(&softmac->smac_fp_mutex);
		return;
	}

	ASSERT(!sup->su_bound);
	mutex_exit(&softmac->smac_fp_mutex);

	/*
	 * It is fine if the expected mode is fast-path and we fail
	 * to enable fastpath on this stream.
	 */
	if (expected_mode == SOFTMAC_SLOWPATH)
		softmac_fastpath_tear(sup);
	else
		(void) softmac_fastpath_setup(sup);
}
