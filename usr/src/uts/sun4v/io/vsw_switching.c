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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/cpu.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/strsun.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <net/if.h>
#include <sys/varargs.h>
#include <sys/machsystm.h>
#include <sys/modctl.h>
#include <sys/modhash.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/taskq.h>
#include <sys/note.h>
#include <sys/mach_descrip.h>
#include <sys/mac.h>
#include <sys/mdeg.h>
#include <sys/ldc.h>
#include <sys/vsw_fdb.h>
#include <sys/vsw.h>
#include <sys/vio_mailbox.h>
#include <sys/vnet_mailbox.h>
#include <sys/vnet_common.h>
#include <sys/vio_util.h>
#include <sys/sdt.h>
#include <sys/atomic.h>

/* Switching setup routines */
void vsw_setup_switching_timeout(void *arg);
void vsw_stop_switching_timeout(vsw_t *vswp);
int vsw_setup_switching(vsw_t *);
static	int vsw_setup_layer2(vsw_t *);
static	int vsw_setup_layer3(vsw_t *);

/* Switching/data transmit routines */
static	void vsw_switch_l2_frame(vsw_t *vswp, mblk_t *mp, int caller,
    vsw_port_t *port, mac_resource_handle_t);
static	void vsw_switch_l3_frame(vsw_t *vswp, mblk_t *mp, int caller,
    vsw_port_t *port, mac_resource_handle_t);
static	int vsw_forward_all(vsw_t *vswp, mblk_t *mp, mblk_t *mpt,
    int caller, vsw_port_t *port);
static	int vsw_forward_grp(vsw_t *vswp, mblk_t *mp, mblk_t *mpt,
    int caller, vsw_port_t *port);

/* Forwarding database (FDB) routines */
static	vsw_port_t *vsw_lookup_fdb(vsw_t *vswp, struct ether_header *);
int vsw_add_rem_mcst(vnet_mcast_msg_t *, vsw_port_t *);
void vsw_del_mcst_port(vsw_port_t *);
int vsw_add_mcst(vsw_t *, uint8_t, uint64_t, void *);
int vsw_del_mcst(vsw_t *, uint8_t, uint64_t, void *);
void vsw_del_mcst_vsw(vsw_t *);
int vsw_add_fdb(vsw_t *vswp, vsw_port_t *port);
int vsw_del_fdb(vsw_t *vswp, vsw_port_t *port);

/* Support functions */
static mblk_t *vsw_dupmsgchain(mblk_t *mp);
static int vsw_get_same_dest_list(struct ether_header *ehp,
    mblk_t **rhead, mblk_t **rtail, mblk_t **mpp);


/*
 * Functions imported from other files.
 */
extern mblk_t *vsw_tx_msg(vsw_t *, mblk_t *);
extern mcst_addr_t *vsw_del_addr(uint8_t, void *, uint64_t);
extern int vsw_mac_open(vsw_t *vswp);
extern void vsw_mac_close(vsw_t *vswp);
extern void vsw_mac_rx(vsw_t *vswp, int caller, mac_resource_handle_t mrh,
    mblk_t *mp, mblk_t *mpt, vsw_macrx_flags_t flags);
extern void vsw_mac_rx(vsw_t *vswp, int caller, mac_resource_handle_t mrh,
    mblk_t *mp, mblk_t *mpt, vsw_macrx_flags_t flags);
extern void vsw_set_addrs(vsw_t *vswp);
extern int vsw_get_hw_maddr(vsw_t *);
extern int vsw_mac_attach(vsw_t *vswp);
extern int vsw_portsend(vsw_port_t *port, mblk_t *mp, mblk_t *mpt);

/*
 * Tunables used in this file.
 */
extern int vsw_setup_switching_delay;


/*
 * Timeout routine to setup switching mode:
 * vsw_setup_switching() is invoked from vsw_attach() or vsw_update_md_prop()
 * initially. If it fails and the error is EAGAIN, then this timeout handler
 * is started to retry vsw_setup_switching(). vsw_setup_switching() is retried
 * until we successfully finish it; or the returned error is not EAGAIN.
 */
void
vsw_setup_switching_timeout(void *arg)
{
	vsw_t		*vswp = (vsw_t *)arg;
	int		rv;

	if (vswp->swtmout_enabled == B_FALSE)
		return;

	rv = vsw_setup_switching(vswp);

	if (rv == 0) {
		/*
		 * Successfully setup switching mode.
		 * Program unicst, mcst addrs of vsw
		 * interface and ports in the physdev.
		 */
		vsw_set_addrs(vswp);
	}

	mutex_enter(&vswp->swtmout_lock);

	if (rv == EAGAIN && vswp->swtmout_enabled == B_TRUE) {
		/*
		 * Reschedule timeout() if the error is EAGAIN and the
		 * timeout is still enabled. For errors other than EAGAIN,
		 * we simply return without rescheduling timeout().
		 */
		vswp->swtmout_id =
		    timeout(vsw_setup_switching_timeout, vswp,
		    (vsw_setup_switching_delay * drv_usectohz(MICROSEC)));
		goto exit;
	}

	/* timeout handler completed */
	vswp->swtmout_enabled = B_FALSE;
	vswp->swtmout_id = 0;

exit:
	mutex_exit(&vswp->swtmout_lock);
}

/*
 * Cancel the timeout handler to setup switching mode.
 */
void
vsw_stop_switching_timeout(vsw_t *vswp)
{
	timeout_id_t tid;

	mutex_enter(&vswp->swtmout_lock);

	tid = vswp->swtmout_id;

	if (tid != 0) {
		/* signal timeout handler to stop */
		vswp->swtmout_enabled = B_FALSE;
		vswp->swtmout_id = 0;
		mutex_exit(&vswp->swtmout_lock);

		(void) untimeout(tid);
	} else {
		mutex_exit(&vswp->swtmout_lock);
	}

	(void) atomic_swap_32(&vswp->switching_setup_done, B_FALSE);

	mutex_enter(&vswp->mac_lock);
	vswp->mac_open_retries = 0;
	mutex_exit(&vswp->mac_lock);
}

/*
 * Setup the required switching mode.
 * This routine is invoked from vsw_attach() or vsw_update_md_prop()
 * initially. If it fails and the error is EAGAIN, then a timeout handler
 * is started to retry vsw_setup_switching(), until it successfully finishes;
 * or the returned error is not EAGAIN.
 *
 * Returns:
 *  0 on success.
 *  EAGAIN if retry is needed.
 *  1 on all other failures.
 */
int
vsw_setup_switching(vsw_t *vswp)
{
	int	i, rv = 1;

	D1(vswp, "%s: enter", __func__);

	/*
	 * Select best switching mode.
	 * Note that we start from the saved smode_idx. This is done as
	 * this routine can be called from the timeout handler to retry
	 * setting up a specific mode. Currently only the function which
	 * sets up layer2/promisc mode returns EAGAIN if the underlying
	 * physical device is not available yet, causing retries.
	 */
	for (i = vswp->smode_idx; i < vswp->smode_num; i++) {
		vswp->smode_idx = i;
		switch (vswp->smode[i]) {
		case VSW_LAYER2:
		case VSW_LAYER2_PROMISC:
			rv = vsw_setup_layer2(vswp);
			break;

		case VSW_LAYER3:
			rv = vsw_setup_layer3(vswp);
			break;

		default:
			DERR(vswp, "unknown switch mode");
			break;
		}

		if ((rv == 0) || (rv == EAGAIN))
			break;

		/* all other errors(rv != 0): continue & select the next mode */
		rv = 1;
	}

	if (rv && (rv != EAGAIN)) {
		cmn_err(CE_WARN, "!vsw%d: Unable to setup specified "
		    "switching mode", vswp->instance);
	} else if (rv == 0) {
		(void) atomic_swap_32(&vswp->switching_setup_done, B_TRUE);
	}

	D2(vswp, "%s: Operating in mode %d", __func__,
	    vswp->smode[vswp->smode_idx]);

	D1(vswp, "%s: exit", __func__);

	return (rv);
}

/*
 * Setup for layer 2 switching.
 *
 * Returns:
 *  0 on success.
 *  EAGAIN if retry is needed.
 *  EIO on all other failures.
 */
static int
vsw_setup_layer2(vsw_t *vswp)
{
	int	rv;

	D1(vswp, "%s: enter", __func__);

	vswp->vsw_switch_frame = vsw_switch_l2_frame;

	rv = strlen(vswp->physname);
	if (rv == 0) {
		/*
		 * Physical device name is NULL, which is
		 * required for layer 2.
		 */
		cmn_err(CE_WARN, "!vsw%d: no physical device name specified",
		    vswp->instance);
		return (EIO);
	}

	mutex_enter(&vswp->mac_lock);

	rv = vsw_mac_open(vswp);
	if (rv != 0) {
		if (rv != EAGAIN) {
			cmn_err(CE_WARN, "!vsw%d: Unable to open physical "
			    "device: %s\n", vswp->instance, vswp->physname);
		}
		mutex_exit(&vswp->mac_lock);
		return (rv);
	}

	if (vswp->smode[vswp->smode_idx] == VSW_LAYER2) {
		/*
		 * Verify that underlying device can support multiple
		 * unicast mac addresses.
		 */
		rv = vsw_get_hw_maddr(vswp);
		if (rv != 0) {
			cmn_err(CE_WARN, "!vsw%d: Unable to setup "
			    "layer2 switching", vswp->instance);
			goto exit_error;
		}
	}

	/*
	 * Attempt to link into the MAC layer so we can get
	 * and send packets out over the physical adapter.
	 */
	rv = vsw_mac_attach(vswp);
	if (rv != 0) {
		/*
		 * Registration with the MAC layer has failed,
		 * so return error so that can fall back to next
		 * prefered switching method.
		 */
		cmn_err(CE_WARN, "!vsw%d: Unable to setup physical device: "
		    "%s\n", vswp->instance, vswp->physname);
		goto exit_error;
	}

	D1(vswp, "%s: exit", __func__);

	mutex_exit(&vswp->mac_lock);
	return (0);

exit_error:
	vsw_mac_close(vswp);
	mutex_exit(&vswp->mac_lock);
	return (EIO);
}

static int
vsw_setup_layer3(vsw_t *vswp)
{
	D1(vswp, "%s: enter", __func__);

	D2(vswp, "%s: operating in layer 3 mode", __func__);
	vswp->vsw_switch_frame = vsw_switch_l3_frame;

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Switch the given ethernet frame when operating in layer 2 mode.
 *
 * vswp: pointer to the vsw instance
 * mp: pointer to chain of ethernet frame(s) to be switched
 * caller: identifies the source of this frame as:
 * 		1. VSW_VNETPORT - a vsw port (connected to a vnet).
 *		2. VSW_PHYSDEV - the physical ethernet device
 *		3. VSW_LOCALDEV - vsw configured as a virtual interface
 * arg: argument provided by the caller.
 *		1. for VNETPORT - pointer to the corresponding vsw_port_t.
 *		2. for PHYSDEV - NULL
 *		3. for LOCALDEV - pointer to to this vsw_t(self)
 */
void
vsw_switch_l2_frame(vsw_t *vswp, mblk_t *mp, int caller,
			vsw_port_t *arg, mac_resource_handle_t mrh)
{
	struct ether_header	*ehp;
	vsw_port_t		*port = NULL;
	mblk_t			*bp, *ret_m;
	mblk_t			*mpt = NULL;
	int			rv;
	vsw_port_list_t		*plist = &vswp->plist;

	D1(vswp, "%s: enter (caller %d)", __func__, caller);

	/*
	 * PERF: rather than breaking up the chain here, scan it
	 * to find all mblks heading to same destination and then
	 * pass that sub-chain to the lower transmit functions.
	 */

	/* process the chain of packets */
	bp = mp;
	while (bp) {
		ehp = (struct ether_header *)bp->b_rptr;
		rv = vsw_get_same_dest_list(ehp, &mp, &mpt, &bp);
		ASSERT(rv != 0);

		D2(vswp, "%s: mblk data buffer %lld : actual data size %lld",
		    __func__, MBLKSIZE(mp), MBLKL(mp));

		if (ether_cmp(&ehp->ether_dhost, &vswp->if_addr) == 0) {
			/*
			 * If destination is VSW_LOCALDEV (vsw as an eth
			 * interface) and if the device is up & running,
			 * send the packet up the stack on this host.
			 * If the virtual interface is down, drop the packet.
			 */
			if (caller != VSW_LOCALDEV) {
				vsw_mac_rx(vswp, caller, mrh, mp,
				    mpt, VSW_MACRX_FREEMSG);
			} else {
				freemsgchain(mp);
			}
			continue;
		}

		READ_ENTER(&plist->lockrw);
		port = vsw_lookup_fdb(vswp, ehp);
		if (port) {
			/*
			 * Mark the port as in-use before releasing the lockrw.
			 */
			VSW_PORT_REFHOLD(port);
			RW_EXIT(&plist->lockrw);

			/*
			 * If plumbed and in promisc mode then copy msg
			 * and send up the stack.
			 */
			vsw_mac_rx(vswp, caller, mrh, mp,
			    mpt, VSW_MACRX_PROMISC | VSW_MACRX_COPYMSG);

			/*
			 * If the destination is in FDB, the packet
			 * should be forwarded to the correponding
			 * vsw_port (connected to a vnet device -
			 * VSW_VNETPORT)
			 */
			(void) vsw_portsend(port, mp, mpt);

			/*
			 * Decrement use count in port.
			 */
			VSW_PORT_REFRELE(port);
		} else {
			RW_EXIT(&plist->lockrw);
			/*
			 * Destination not in FDB.
			 *
			 * If the destination is broadcast or
			 * multicast forward the packet to all
			 * (VNETPORTs, PHYSDEV, LOCALDEV),
			 * except the caller.
			 */
			if (IS_BROADCAST(ehp)) {
				D3(vswp, "%s: BROADCAST pkt", __func__);
				(void) vsw_forward_all(vswp, mp, mpt,
				    caller, arg);
			} else if (IS_MULTICAST(ehp)) {
				D3(vswp, "%s: MULTICAST pkt", __func__);
				(void) vsw_forward_grp(vswp, mp, mpt,
				    caller, arg);
			} else {
				/*
				 * If the destination is unicast, and came
				 * from either a logical network device or
				 * the switch itself when it is plumbed, then
				 * send it out on the physical device and also
				 * up the stack if the logical interface is
				 * in promiscious mode.
				 *
				 * NOTE:  The assumption here is that if we
				 * cannot find the destination in our fdb, its
				 * a unicast address, and came from either a
				 * vnet or down the stack (when plumbed) it
				 * must be destinded for an ethernet device
				 * outside our ldoms.
				 */
				if (caller == VSW_VNETPORT) {
					/* promisc check copy etc */
					vsw_mac_rx(vswp, caller, mrh, mp, mpt,
					    VSW_MACRX_PROMISC |
					    VSW_MACRX_COPYMSG);

					if ((ret_m = vsw_tx_msg(vswp, mp))
					    != NULL) {
						DERR(vswp, "%s: drop mblks to "
						    "phys dev", __func__);
						freemsgchain(ret_m);
					}

				} else if (caller == VSW_PHYSDEV) {
					/*
					 * Pkt seen because card in promisc
					 * mode. Send up stack if plumbed in
					 * promisc mode, else drop it.
					 */
					vsw_mac_rx(vswp, caller, mrh, mp, mpt,
					    VSW_MACRX_PROMISC |
					    VSW_MACRX_FREEMSG);

				} else if (caller == VSW_LOCALDEV) {
					/*
					 * Pkt came down the stack, send out
					 * over physical device.
					 */
					if ((ret_m = vsw_tx_msg(vswp, mp))
					    != NULL) {
						DERR(vswp, "%s: drop mblks to "
						    "phys dev", __func__);
						freemsgchain(ret_m);
					}
				}
			}
		}
	}
	D1(vswp, "%s: exit\n", __func__);
}

/*
 * Switch ethernet frame when in layer 3 mode (i.e. using IP
 * layer to do the routing).
 *
 * There is a large amount of overlap between this function and
 * vsw_switch_l2_frame. At some stage we need to revisit and refactor
 * both these functions.
 */
void
vsw_switch_l3_frame(vsw_t *vswp, mblk_t *mp, int caller,
			vsw_port_t *arg, mac_resource_handle_t mrh)
{
	struct ether_header	*ehp;
	vsw_port_t		*port = NULL;
	mblk_t			*bp = NULL;
	mblk_t			*mpt;
	int			rv;
	vsw_port_list_t		*plist = &vswp->plist;

	D1(vswp, "%s: enter (caller %d)", __func__, caller);

	/*
	 * In layer 3 mode should only ever be switching packets
	 * between IP layer and vnet devices. So make sure thats
	 * who is invoking us.
	 */
	if ((caller != VSW_LOCALDEV) && (caller != VSW_VNETPORT)) {
		DERR(vswp, "%s: unexpected caller (%d)", __func__, caller);
		freemsgchain(mp);
		return;
	}

	/* process the chain of packets */
	bp = mp;
	while (bp) {
		ehp = (struct ether_header *)bp->b_rptr;
		rv = vsw_get_same_dest_list(ehp, &mp, &mpt, &bp);
		ASSERT(rv != 0);

		D2(vswp, "%s: mblk data buffer %lld : actual data size %lld",
		    __func__, MBLKSIZE(mp), MBLKL(mp));

		READ_ENTER(&plist->lockrw);
		port = vsw_lookup_fdb(vswp, ehp);
		if (port) {
			/*
			 * Mark the port as in-use before releasing the lockrw.
			 */
			VSW_PORT_REFHOLD(port);
			RW_EXIT(&plist->lockrw);

			D2(vswp, "%s: sending to target port", __func__);
			(void) vsw_portsend(port, mp, mpt);

			/*
			 * Decrement ref count.
			 */
			VSW_PORT_REFRELE(port);
		} else {
			RW_EXIT(&plist->lockrw);
			/*
			 * Destination not in FDB
			 *
			 * If the destination is broadcast or
			 * multicast forward the packet to all
			 * (VNETPORTs, PHYSDEV, LOCALDEV),
			 * except the caller.
			 */
			if (IS_BROADCAST(ehp)) {
				D2(vswp, "%s: BROADCAST pkt", __func__);
				(void) vsw_forward_all(vswp, mp, mpt,
				    caller, arg);
			} else if (IS_MULTICAST(ehp)) {
				D2(vswp, "%s: MULTICAST pkt", __func__);
				(void) vsw_forward_grp(vswp, mp, mpt,
				    caller, arg);
			} else {
				/*
				 * Unicast pkt from vnet that we don't have
				 * an FDB entry for, so must be destinded for
				 * the outside world. Attempt to send up to the
				 * IP layer to allow it to deal with it.
				 */
				if (caller == VSW_VNETPORT) {
					vsw_mac_rx(vswp, caller, mrh,
					    mp, mpt, VSW_MACRX_FREEMSG);
				}
			}
		}
	}

	D1(vswp, "%s: exit", __func__);
}

/*
 * Forward the ethernet frame to all ports (VNETPORTs, PHYSDEV, LOCALDEV),
 * except the caller (port on which frame arrived).
 */
static int
vsw_forward_all(vsw_t *vswp, mblk_t *mp, mblk_t *mpt,
    int caller, vsw_port_t *arg)
{
	vsw_port_list_t	*plist = &vswp->plist;
	vsw_port_t	*portp;
	mblk_t		*nmp = NULL;
	mblk_t		*ret_m = NULL;
	int		skip_port = 0;

	D1(vswp, "vsw_forward_all: enter\n");

	/*
	 * Broadcast message from inside ldoms so send to outside
	 * world if in either of layer 2 modes.
	 */
	if (((vswp->smode[vswp->smode_idx] == VSW_LAYER2) ||
	    (vswp->smode[vswp->smode_idx] == VSW_LAYER2_PROMISC)) &&
	    ((caller == VSW_LOCALDEV) || (caller == VSW_VNETPORT))) {

		nmp = vsw_dupmsgchain(mp);
		if (nmp) {
			if ((ret_m = vsw_tx_msg(vswp, nmp)) != NULL) {
				DERR(vswp, "%s: dropping pkt(s) "
				    "consisting of %ld bytes of data for"
				    " physical device", __func__, MBLKL(ret_m));
				freemsgchain(ret_m);
			}
		}
	}

	if (caller == VSW_VNETPORT)
		skip_port = 1;

	/*
	 * Broadcast message from other vnet (layer 2 or 3) or outside
	 * world (layer 2 only), send up stack if plumbed.
	 */
	if ((caller == VSW_PHYSDEV) || (caller == VSW_VNETPORT)) {
		vsw_mac_rx(vswp, caller, NULL, mp, mpt, VSW_MACRX_COPYMSG);
	}

	/* send it to all VNETPORTs */
	READ_ENTER(&plist->lockrw);
	for (portp = plist->head; portp != NULL; portp = portp->p_next) {
		D2(vswp, "vsw_forward_all: port %d", portp->p_instance);
		/*
		 * Caution ! - don't reorder these two checks as arg
		 * will be NULL if the caller is PHYSDEV. skip_port is
		 * only set if caller is VNETPORT.
		 */
		if ((skip_port) && (portp == arg)) {
			continue;
		} else {
			nmp = vsw_dupmsgchain(mp);
			if (nmp) {
				mblk_t *mpt = nmp;

				/* Find tail */
				while (mpt->b_next != NULL) {
					mpt = mpt->b_next;
				}
				/*
				 * The plist->lockrw is protecting the
				 * portp from getting destroyed here.
				 * So, no ref_cnt is incremented here.
				 */
				(void) vsw_portsend(portp, nmp, mpt);
			} else {
				DERR(vswp, "vsw_forward_all: nmp NULL");
			}
		}
	}
	RW_EXIT(&plist->lockrw);

	freemsgchain(mp);

	D1(vswp, "vsw_forward_all: exit\n");
	return (0);
}

/*
 * Forward pkts to any devices or interfaces which have registered
 * an interest in them (i.e. multicast groups).
 */
static int
vsw_forward_grp(vsw_t *vswp, mblk_t *mp, mblk_t *mpt,
    int caller, vsw_port_t *arg)
{
	struct ether_header	*ehp = (struct ether_header *)mp->b_rptr;
	mfdb_ent_t		*entp = NULL;
	mfdb_ent_t		*tpp = NULL;
	vsw_port_t 		*port;
	uint64_t		key = 0;
	mblk_t			*nmp = NULL;
	mblk_t			*ret_m = NULL;
	boolean_t		check_if = B_TRUE;

	/*
	 * Convert address to hash table key
	 */
	KEY_HASH(key, ehp->ether_dhost);

	D1(vswp, "%s: key 0x%llx", __func__, key);

	/*
	 * If pkt came from either a vnet or down the stack (if we are
	 * plumbed) and we are in layer 2 mode, then we send the pkt out
	 * over the physical adapter, and then check to see if any other
	 * vnets are interested in it.
	 */
	if (((vswp->smode[vswp->smode_idx] == VSW_LAYER2) ||
	    (vswp->smode[vswp->smode_idx] == VSW_LAYER2_PROMISC)) &&
	    ((caller == VSW_VNETPORT) || (caller == VSW_LOCALDEV))) {
		nmp = vsw_dupmsgchain(mp);
		if (nmp) {
			if ((ret_m = vsw_tx_msg(vswp, nmp)) != NULL) {
				DERR(vswp, "%s: dropping pkt(s) consisting of "
				    "%ld bytes of data for physical device",
				    __func__, MBLKL(ret_m));
				freemsgchain(ret_m);
			}
		}
	}

	READ_ENTER(&vswp->mfdbrw);
	if (mod_hash_find(vswp->mfdb, (mod_hash_key_t)key,
	    (mod_hash_val_t *)&entp) != 0) {
		D3(vswp, "%s: no table entry found for addr 0x%llx",
		    __func__, key);
	} else {
		/*
		 * Send to list of devices associated with this address...
		 */
		for (tpp = entp; tpp != NULL; tpp = tpp->nextp) {

			/* dont send to ourselves */
			if ((caller == VSW_VNETPORT) &&
			    (tpp->d_addr == (void *)arg)) {
				port = (vsw_port_t *)tpp->d_addr;
				D3(vswp, "%s: not sending to ourselves"
				    " : port %d", __func__, port->p_instance);
				continue;

			} else if ((caller == VSW_LOCALDEV) &&
			    (tpp->d_type == VSW_LOCALDEV)) {
				D3(vswp, "%s: not sending back up stack",
				    __func__);
				continue;
			}

			if (tpp->d_type == VSW_VNETPORT) {
				port = (vsw_port_t *)tpp->d_addr;
				D3(vswp, "%s: sending to port %ld for addr "
				    "0x%llx", __func__, port->p_instance, key);

				nmp = vsw_dupmsgchain(mp);
				if (nmp) {
					mblk_t *mpt = nmp;

					/* Find tail */
					while (mpt->b_next != NULL) {
						mpt = mpt->b_next;
					}
					/*
					 * The vswp->mfdbrw is protecting the
					 * portp from getting destroyed here.
					 * So, no ref_cnt is incremented here.
					 */
					(void) vsw_portsend(port, nmp, mpt);
				}
			} else {
				vsw_mac_rx(vswp, caller, NULL,
				    mp, mpt, VSW_MACRX_COPYMSG);
				D3(vswp, "%s: sending up stack"
				    " for addr 0x%llx", __func__, key);
				check_if = B_FALSE;
			}
		}
	}

	RW_EXIT(&vswp->mfdbrw);

	/*
	 * If the pkt came from either a vnet or from physical device,
	 * and if we havent already sent the pkt up the stack then we
	 * check now if we can/should (i.e. the interface is plumbed
	 * and in promisc mode).
	 */
	if ((check_if) &&
	    ((caller == VSW_VNETPORT) || (caller == VSW_PHYSDEV))) {
		vsw_mac_rx(vswp, caller, NULL, mp, mpt,
		    VSW_MACRX_PROMISC | VSW_MACRX_COPYMSG);
	}

	freemsgchain(mp);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Add an entry into FDB, for the given mac address and port_id.
 * Returns 0 on success, 1 on failure.
 *
 * Lock protecting FDB must be held by calling process.
 */
int
vsw_add_fdb(vsw_t *vswp, vsw_port_t *port)
{
	uint64_t	addr = 0;

	D1(vswp, "%s: enter", __func__);

	KEY_HASH(addr, port->p_macaddr);

	D2(vswp, "%s: key = 0x%llx", __func__, addr);

	/*
	 * Note: duplicate keys will be rejected by mod_hash.
	 */
	if (mod_hash_insert(vswp->fdb, (mod_hash_key_t)addr,
	    (mod_hash_val_t)port) != 0) {
		DERR(vswp, "%s: unable to add entry into fdb.", __func__);
		return (1);
	}

	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Remove an entry from FDB.
 * Returns 0 on success, 1 on failure.
 */
int
vsw_del_fdb(vsw_t *vswp, vsw_port_t *port)
{
	uint64_t	addr = 0;

	D1(vswp, "%s: enter", __func__);

	KEY_HASH(addr, port->p_macaddr);

	D2(vswp, "%s: key = 0x%llx", __func__, addr);

	(void) mod_hash_destroy(vswp->fdb, (mod_hash_val_t)addr);

	D1(vswp, "%s: enter", __func__);

	return (0);
}

/*
 * Search fdb for a given mac address.
 * Returns pointer to the entry if found, else returns NULL.
 */
static vsw_port_t *
vsw_lookup_fdb(vsw_t *vswp, struct ether_header *ehp)
{
	uint64_t	key = 0;
	vsw_port_t	*port = NULL;

	D1(vswp, "%s: enter", __func__);

	KEY_HASH(key, ehp->ether_dhost);

	D2(vswp, "%s: key = 0x%llx", __func__, key);

	if (mod_hash_find(vswp->fdb, (mod_hash_key_t)key,
	    (mod_hash_val_t *)&port) != 0) {
		D2(vswp, "%s: no port found", __func__);
		return (NULL);
	}

	D1(vswp, "%s: exit", __func__);

	return (port);
}

/*
 * Add or remove multicast address(es).
 *
 * Returns 0 on success, 1 on failure.
 */
int
vsw_add_rem_mcst(vnet_mcast_msg_t *mcst_pkt, vsw_port_t *port)
{
	mcst_addr_t		*mcst_p = NULL;
	vsw_t			*vswp = port->p_vswp;
	uint64_t		addr = 0x0;
	int			i;

	D1(vswp, "%s: enter", __func__);

	D2(vswp, "%s: %d addresses", __func__, mcst_pkt->count);

	for (i = 0; i < mcst_pkt->count; i++) {
		/*
		 * Convert address into form that can be used
		 * as hash table key.
		 */
		KEY_HASH(addr, mcst_pkt->mca[i]);

		/*
		 * Add or delete the specified address/port combination.
		 */
		if (mcst_pkt->set == 0x1) {
			D3(vswp, "%s: adding multicast address 0x%llx for "
			    "port %ld", __func__, addr, port->p_instance);
			if (vsw_add_mcst(vswp, VSW_VNETPORT, addr, port) == 0) {
				/*
				 * Update the list of multicast
				 * addresses contained within the
				 * port structure to include this new
				 * one.
				 */
				mcst_p = kmem_zalloc(sizeof (mcst_addr_t),
				    KM_NOSLEEP);
				if (mcst_p == NULL) {
					DERR(vswp, "%s: unable to alloc mem",
					    __func__);
					(void) vsw_del_mcst(vswp,
					    VSW_VNETPORT, addr, port);
					return (1);
				}

				mcst_p->nextp = NULL;
				mcst_p->addr = addr;
				ether_copy(&mcst_pkt->mca[i], &mcst_p->mca);

				/*
				 * Program the address into HW. If the addr
				 * has already been programmed then the MAC
				 * just increments a ref counter (which is
				 * used when the address is being deleted)
				 */
				mutex_enter(&vswp->mac_lock);
				if (vswp->mh != NULL) {
					if (mac_multicst_add(vswp->mh,
					    (uchar_t *)&mcst_pkt->mca[i])) {
						mutex_exit(&vswp->mac_lock);
						cmn_err(CE_WARN, "!vsw%d: "
						    "unable to add multicast "
						    "address: %s\n",
						    vswp->instance,
						    ether_sprintf((void *)
						    &mcst_p->mca));
						(void) vsw_del_mcst(vswp,
						    VSW_VNETPORT, addr, port);
						kmem_free(mcst_p,
						    sizeof (*mcst_p));
						return (1);
					}
					mcst_p->mac_added = B_TRUE;
				}
				mutex_exit(&vswp->mac_lock);

				mutex_enter(&port->mca_lock);
				mcst_p->nextp = port->mcap;
				port->mcap = mcst_p;
				mutex_exit(&port->mca_lock);

			} else {
				DERR(vswp, "%s: error adding multicast "
				    "address 0x%llx for port %ld",
				    __func__, addr, port->p_instance);
				return (1);
			}
		} else {
			/*
			 * Delete an entry from the multicast hash
			 * table and update the address list
			 * appropriately.
			 */
			if (vsw_del_mcst(vswp, VSW_VNETPORT, addr, port) == 0) {
				D3(vswp, "%s: deleting multicast address "
				    "0x%llx for port %ld", __func__, addr,
				    port->p_instance);

				mcst_p = vsw_del_addr(VSW_VNETPORT, port, addr);
				ASSERT(mcst_p != NULL);

				/*
				 * Remove the address from HW. The address
				 * will actually only be removed once the ref
				 * count within the MAC layer has dropped to
				 * zero. I.e. we can safely call this fn even
				 * if other ports are interested in this
				 * address.
				 */
				mutex_enter(&vswp->mac_lock);
				if (vswp->mh != NULL && mcst_p->mac_added) {
					if (mac_multicst_remove(vswp->mh,
					    (uchar_t *)&mcst_pkt->mca[i])) {
						mutex_exit(&vswp->mac_lock);
						cmn_err(CE_WARN, "!vsw%d: "
						    "unable to remove mcast "
						    "address: %s\n",
						    vswp->instance,
						    ether_sprintf((void *)
						    &mcst_p->mca));
						kmem_free(mcst_p,
						    sizeof (*mcst_p));
						return (1);
					}
					mcst_p->mac_added = B_FALSE;
				}
				mutex_exit(&vswp->mac_lock);
				kmem_free(mcst_p, sizeof (*mcst_p));

			} else {
				DERR(vswp, "%s: error deleting multicast "
				    "addr 0x%llx for port %ld",
				    __func__, addr, port->p_instance);
				return (1);
			}
		}
	}
	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Add a new multicast entry.
 *
 * Search hash table based on address. If match found then
 * update associated val (which is chain of ports), otherwise
 * create new key/val (addr/port) pair and insert into table.
 */
int
vsw_add_mcst(vsw_t *vswp, uint8_t devtype, uint64_t addr, void *arg)
{
	int		dup = 0;
	int		rv = 0;
	mfdb_ent_t	*ment = NULL;
	mfdb_ent_t	*tmp_ent = NULL;
	mfdb_ent_t	*new_ent = NULL;
	void		*tgt = NULL;

	if (devtype == VSW_VNETPORT) {
		/*
		 * Being invoked from a vnet.
		 */
		ASSERT(arg != NULL);
		tgt = arg;
		D2(NULL, "%s: port %d : address 0x%llx", __func__,
		    ((vsw_port_t *)arg)->p_instance, addr);
	} else {
		/*
		 * We are being invoked via the m_multicst mac entry
		 * point.
		 */
		D2(NULL, "%s: address 0x%llx", __func__, addr);
		tgt = (void *)vswp;
	}

	WRITE_ENTER(&vswp->mfdbrw);
	if (mod_hash_find(vswp->mfdb, (mod_hash_key_t)addr,
	    (mod_hash_val_t *)&ment) != 0) {

		/* address not currently in table */
		ment = kmem_alloc(sizeof (mfdb_ent_t), KM_SLEEP);
		ment->d_addr = (void *)tgt;
		ment->d_type = devtype;
		ment->nextp = NULL;

		if (mod_hash_insert(vswp->mfdb, (mod_hash_key_t)addr,
		    (mod_hash_val_t)ment) != 0) {
			DERR(vswp, "%s: hash table insertion failed", __func__);
			kmem_free(ment, sizeof (mfdb_ent_t));
			rv = 1;
		} else {
			D2(vswp, "%s: added initial entry for 0x%llx to "
			    "table", __func__, addr);
		}
	} else {
		/*
		 * Address in table. Check to see if specified port
		 * is already associated with the address. If not add
		 * it now.
		 */
		tmp_ent = ment;
		while (tmp_ent != NULL) {
			if (tmp_ent->d_addr == (void *)tgt) {
				if (devtype == VSW_VNETPORT) {
					DERR(vswp, "%s: duplicate port entry "
					    "found for portid %ld and key "
					    "0x%llx", __func__,
					    ((vsw_port_t *)arg)->p_instance,
					    addr);
				} else {
					DERR(vswp, "%s: duplicate entry found"
					    "for key 0x%llx", __func__, addr);
				}
				rv = 1;
				dup = 1;
				break;
			}
			tmp_ent = tmp_ent->nextp;
		}

		/*
		 * Port not on list so add it to end now.
		 */
		if (0 == dup) {
			D2(vswp, "%s: added entry for 0x%llx to table",
			    __func__, addr);
			new_ent = kmem_alloc(sizeof (mfdb_ent_t), KM_SLEEP);
			new_ent->d_addr = (void *)tgt;
			new_ent->d_type = devtype;
			new_ent->nextp = NULL;

			tmp_ent = ment;
			while (tmp_ent->nextp != NULL)
				tmp_ent = tmp_ent->nextp;

			tmp_ent->nextp = new_ent;
		}
	}

	RW_EXIT(&vswp->mfdbrw);
	return (rv);
}

/*
 * Remove a multicast entry from the hashtable.
 *
 * Search hash table based on address. If match found, scan
 * list of ports associated with address. If specified port
 * found remove it from list.
 */
int
vsw_del_mcst(vsw_t *vswp, uint8_t devtype, uint64_t addr, void *arg)
{
	mfdb_ent_t	*ment = NULL;
	mfdb_ent_t	*curr_p, *prev_p;
	void		*tgt = NULL;

	D1(vswp, "%s: enter", __func__);

	if (devtype == VSW_VNETPORT) {
		tgt = (vsw_port_t *)arg;
		D2(vswp, "%s: removing port %d from mFDB for address"
		    " 0x%llx", __func__, ((vsw_port_t *)tgt)->p_instance, addr);
	} else {
		D2(vswp, "%s: removing entry", __func__);
		tgt = (void *)vswp;
	}

	WRITE_ENTER(&vswp->mfdbrw);
	if (mod_hash_find(vswp->mfdb, (mod_hash_key_t)addr,
	    (mod_hash_val_t *)&ment) != 0) {
		D2(vswp, "%s: address 0x%llx not in table", __func__, addr);
		RW_EXIT(&vswp->mfdbrw);
		return (1);
	}

	prev_p = curr_p = ment;

	while (curr_p != NULL) {
		if (curr_p->d_addr == (void *)tgt) {
			if (devtype == VSW_VNETPORT) {
				D2(vswp, "%s: port %d found", __func__,
				    ((vsw_port_t *)tgt)->p_instance);
			} else {
				D2(vswp, "%s: instance found", __func__);
			}

			if (prev_p == curr_p) {
				/*
				 * head of list, if no other element is in
				 * list then destroy this entry, otherwise
				 * just replace it with updated value.
				 */
				ment = curr_p->nextp;
				if (ment == NULL) {
					(void) mod_hash_destroy(vswp->mfdb,
					    (mod_hash_val_t)addr);
				} else {
					(void) mod_hash_replace(vswp->mfdb,
					    (mod_hash_key_t)addr,
					    (mod_hash_val_t)ment);
				}
			} else {
				/*
				 * Not head of list, no need to do
				 * replacement, just adjust list pointers.
				 */
				prev_p->nextp = curr_p->nextp;
			}
			break;
		}

		prev_p = curr_p;
		curr_p = curr_p->nextp;
	}

	RW_EXIT(&vswp->mfdbrw);

	D1(vswp, "%s: exit", __func__);

	if (curr_p == NULL)
		return (1);
	kmem_free(curr_p, sizeof (mfdb_ent_t));
	return (0);
}

/*
 * Port is being deleted, but has registered an interest in one
 * or more multicast groups. Using the list of addresses maintained
 * within the port structure find the appropriate entry in the hash
 * table and remove this port from the list of interested ports.
 */
void
vsw_del_mcst_port(vsw_port_t *port)
{
	mcst_addr_t	*mcap = NULL;
	vsw_t		*vswp = port->p_vswp;

	D1(vswp, "%s: enter", __func__);

	mutex_enter(&port->mca_lock);

	while ((mcap = port->mcap) != NULL) {

		port->mcap = mcap->nextp;

		mutex_exit(&port->mca_lock);

		(void) vsw_del_mcst(vswp, VSW_VNETPORT,
		    mcap->addr, port);

		/*
		 * Remove the address from HW. The address
		 * will actually only be removed once the ref
		 * count within the MAC layer has dropped to
		 * zero. I.e. we can safely call this fn even
		 * if other ports are interested in this
		 * address.
		 */
		mutex_enter(&vswp->mac_lock);
		if (vswp->mh != NULL && mcap->mac_added) {
			(void) mac_multicst_remove(vswp->mh,
			    (uchar_t *)&mcap->mca);
		}
		mutex_exit(&vswp->mac_lock);

		kmem_free(mcap, sizeof (*mcap));

		mutex_enter(&port->mca_lock);

	}

	mutex_exit(&port->mca_lock);

	D1(vswp, "%s: exit", __func__);
}

/*
 * This vsw instance is detaching, but has registered an interest in one
 * or more multicast groups. Using the list of addresses maintained
 * within the vsw structure find the appropriate entry in the hash
 * table and remove this instance from the list of interested ports.
 */
void
vsw_del_mcst_vsw(vsw_t *vswp)
{
	mcst_addr_t	*next_p = NULL;

	D1(vswp, "%s: enter", __func__);

	mutex_enter(&vswp->mca_lock);

	while (vswp->mcap != NULL) {
		DERR(vswp, "%s: deleting addr 0x%llx",
		    __func__, vswp->mcap->addr);
		(void) vsw_del_mcst(vswp, VSW_LOCALDEV, vswp->mcap->addr, NULL);

		next_p = vswp->mcap->nextp;
		kmem_free(vswp->mcap, sizeof (mcst_addr_t));
		vswp->mcap = next_p;
	}

	vswp->mcap = NULL;
	mutex_exit(&vswp->mca_lock);

	D1(vswp, "%s: exit", __func__);
}

static int
vsw_get_same_dest_list(struct ether_header *ehp,
    mblk_t **rhead, mblk_t **rtail, mblk_t **mpp)
{
	int count = 0;
	mblk_t *bp;
	mblk_t *nbp;
	mblk_t *head = NULL;
	mblk_t *tail = NULL;
	mblk_t *prev = NULL;
	struct ether_header *behp;

	/* process the chain of packets */
	bp = *mpp;
	while (bp) {
		nbp = bp->b_next;
		behp = (struct ether_header *)bp->b_rptr;
		bp->b_prev = NULL;
		if (ether_cmp(&ehp->ether_dhost, &behp->ether_dhost) == 0) {
			if (prev == NULL) {
				*mpp = nbp;
			} else {
				prev->b_next = nbp;
			}
			bp->b_next =  NULL;
			if (head == NULL) {
				head = tail = bp;
			} else {
				tail->b_next = bp;
				tail = bp;
			}
			count++;
		} else {
			prev = bp;
		}
		bp = nbp;
	}
	*rhead = head;
	*rtail = tail;
	DTRACE_PROBE1(vsw_same_dest, int, count);
	return (count);
}

static mblk_t *
vsw_dupmsgchain(mblk_t *mp)
{
	mblk_t	*nmp = NULL;
	mblk_t	**nmpp = &nmp;

	for (; mp != NULL; mp = mp->b_next) {
		if ((*nmpp = dupmsg(mp)) == NULL) {
			freemsgchain(nmp);
			return (NULL);
		}

		nmpp = &((*nmpp)->b_next);
	}

	return (nmp);
}
