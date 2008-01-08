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
#include <sys/vsw.h>

/* MAC Ring table functions. */
static void vsw_mac_ring_tbl_init(vsw_t *vswp);
static void vsw_mac_ring_tbl_destroy(vsw_t *vswp);
static void vsw_queue_worker(vsw_mac_ring_t *rrp);
static void vsw_queue_stop(vsw_queue_t *vqp);
static vsw_queue_t *vsw_queue_create();
static void vsw_queue_destroy(vsw_queue_t *vqp);
static void vsw_rx_queue_cb(void *, mac_resource_handle_t, mblk_t *);
static void vsw_rx_cb(void *, mac_resource_handle_t, mblk_t *);

/* MAC layer routines */
static mac_resource_handle_t vsw_mac_ring_add_cb(void *arg,
		mac_resource_t *mrp);
static	int vsw_set_hw_addr(vsw_t *, mac_multi_addr_t *);
static	int vsw_set_hw_promisc(vsw_t *, vsw_port_t *, int);
static	int vsw_unset_hw_addr(vsw_t *, int);
static	int vsw_unset_hw_promisc(vsw_t *, vsw_port_t *, int);
static int vsw_prog_if(vsw_t *);

/* Support functions */
static int vsw_prog_ports(vsw_t *);
int vsw_set_hw(vsw_t *, vsw_port_t *, int);
int vsw_unset_hw(vsw_t *, vsw_port_t *, int);
void vsw_reconfig_hw(vsw_t *);
int vsw_mac_attach(vsw_t *vswp);
void vsw_mac_detach(vsw_t *vswp);
int vsw_mac_open(vsw_t *vswp);
void vsw_mac_close(vsw_t *vswp);
void vsw_unset_addrs(vsw_t *vswp);
void vsw_set_addrs(vsw_t *vswp);
int vsw_get_hw_maddr(vsw_t *);
mblk_t *vsw_tx_msg(vsw_t *, mblk_t *);

/*
 * Tunables used in this file.
 */
extern int vsw_mac_open_retries;
extern boolean_t vsw_multi_ring_enable;
extern int vsw_mac_rx_rings;

/*
 * Check to see if the card supports the setting of multiple unicst
 * addresses.
 *
 * Returns 0 if card supports the programming of multiple unicast addresses,
 * otherwise returns 1.
 */
int
vsw_get_hw_maddr(vsw_t *vswp)
{
	D1(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->mac_lock));

	if (vswp->mh == NULL)
		return (1);

	if (!mac_capab_get(vswp->mh, MAC_CAPAB_MULTIADDRESS, &vswp->maddr)) {
		cmn_err(CE_WARN, "!vsw%d: device (%s) does not support "
		    "setting multiple unicast addresses", vswp->instance,
		    vswp->physname);
		return (1);
	}

	D2(vswp, "%s: %d addrs : %d free", __func__,
	    vswp->maddr.maddr_naddr, vswp->maddr.maddr_naddrfree);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Program unicast and multicast addresses of vsw interface and the ports
 * into the physical device.
 */
void
vsw_set_addrs(vsw_t *vswp)
{
	vsw_port_list_t	*plist = &vswp->plist;
	vsw_port_t	*port;
	mcst_addr_t	*mcap;
	int		rv;

	READ_ENTER(&vswp->if_lockrw);

	if (vswp->if_state & VSW_IF_UP) {

		/* program unicst addr of vsw interface in the physdev */
		if (vswp->addr_set == VSW_ADDR_UNSET) {
			mutex_enter(&vswp->hw_lock);
			rv = vsw_set_hw(vswp, NULL, VSW_LOCALDEV);
			mutex_exit(&vswp->hw_lock);
			if (rv != 0) {
				cmn_err(CE_NOTE,
				    "!vsw%d: failed to program interface "
				    "unicast address\n", vswp->instance);
			}
			/*
			 * Notify the MAC layer of the changed address.
			 */
			mac_unicst_update(vswp->if_mh,
			    (uint8_t *)&vswp->if_addr);
		}

		/* program mcast addrs of vsw interface in the physdev */
		mutex_enter(&vswp->mca_lock);
		mutex_enter(&vswp->mac_lock);
		for (mcap = vswp->mcap; mcap != NULL; mcap = mcap->nextp) {
			if (mcap->mac_added)
				continue;
			rv = mac_multicst_add(vswp->mh, (uchar_t *)&mcap->mca);
			if (rv == 0) {
				mcap->mac_added = B_TRUE;
			} else {
				cmn_err(CE_WARN, "!vsw%d: unable to add "
				    "multicast address: %s\n", vswp->instance,
				    ether_sprintf((void *)&mcap->mca));
			}
		}
		mutex_exit(&vswp->mac_lock);
		mutex_exit(&vswp->mca_lock);

	}

	RW_EXIT(&vswp->if_lockrw);

	WRITE_ENTER(&plist->lockrw);

	/* program unicast address of ports in the physical device */
	mutex_enter(&vswp->hw_lock);
	for (port = plist->head; port != NULL; port = port->p_next) {
		if (port->addr_set != VSW_ADDR_UNSET) /* addr already set */
			continue;
		if (vsw_set_hw(vswp, port, VSW_VNETPORT)) {
			cmn_err(CE_NOTE,
			    "!vsw%d: port:%d failed to set unicast address\n",
			    vswp->instance, port->p_instance);
		}
	}
	mutex_exit(&vswp->hw_lock);

	/* program multicast addresses of ports in the physdev */
	for (port = plist->head; port != NULL; port = port->p_next) {
		mutex_enter(&port->mca_lock);
		mutex_enter(&vswp->mac_lock);
		for (mcap = port->mcap; mcap != NULL; mcap = mcap->nextp) {
			if (mcap->mac_added)
				continue;
			rv = mac_multicst_add(vswp->mh, (uchar_t *)&mcap->mca);
			if (rv == 0) {
				mcap->mac_added = B_TRUE;
			} else {
				cmn_err(CE_WARN, "!vsw%d: unable to add "
				    "multicast address: %s\n", vswp->instance,
				    ether_sprintf((void *)&mcap->mca));
			}
		}
		mutex_exit(&vswp->mac_lock);
		mutex_exit(&port->mca_lock);
	}

	RW_EXIT(&plist->lockrw);
}

/*
 * Remove unicast and multicast addresses of vsw interface and the ports
 * from the physical device.
 */
void
vsw_unset_addrs(vsw_t *vswp)
{
	vsw_port_list_t	*plist = &vswp->plist;
	vsw_port_t	*port;
	mcst_addr_t	*mcap;

	READ_ENTER(&vswp->if_lockrw);

	if (vswp->if_state & VSW_IF_UP) {

		/*
		 * Remove unicast addr of vsw interfce
		 * from current physdev
		 */
		mutex_enter(&vswp->hw_lock);
		(void) vsw_unset_hw(vswp, NULL, VSW_LOCALDEV);
		mutex_exit(&vswp->hw_lock);

		/*
		 * Remove mcast addrs of vsw interface
		 * from current physdev
		 */
		mutex_enter(&vswp->mca_lock);
		mutex_enter(&vswp->mac_lock);
		for (mcap = vswp->mcap; mcap != NULL; mcap = mcap->nextp) {
			if (!mcap->mac_added)
				continue;
			(void) mac_multicst_remove(vswp->mh,
			    (uchar_t *)&mcap->mca);
			mcap->mac_added = B_FALSE;
		}
		mutex_exit(&vswp->mac_lock);
		mutex_exit(&vswp->mca_lock);

	}

	RW_EXIT(&vswp->if_lockrw);

	WRITE_ENTER(&plist->lockrw);

	/*
	 * Remove unicast address of ports from the current physical device
	 */
	mutex_enter(&vswp->hw_lock);
	for (port = plist->head; port != NULL; port = port->p_next) {
		/* Remove address if was programmed into HW. */
		if (port->addr_set == VSW_ADDR_UNSET)
			continue;
		(void) vsw_unset_hw(vswp, port, VSW_VNETPORT);
	}
	mutex_exit(&vswp->hw_lock);

	/* Remove multicast addresses of ports from the current physdev */
	for (port = plist->head; port != NULL; port = port->p_next) {
		mutex_enter(&port->mca_lock);
		mutex_enter(&vswp->mac_lock);
		for (mcap = port->mcap; mcap != NULL; mcap = mcap->nextp) {
			if (!mcap->mac_added)
				continue;
			(void) mac_multicst_remove(vswp->mh,
			    (uchar_t *)&mcap->mca);
			mcap->mac_added = B_FALSE;
		}
		mutex_exit(&vswp->mac_lock);
		mutex_exit(&port->mca_lock);
	}

	RW_EXIT(&plist->lockrw);
}

/*
 * Open the underlying physical device for access in layer2 mode.
 * Returns:
 * 0 on success
 * EAGAIN if mac_open() fails due to the device being not available yet.
 * EIO on any other failures.
 */
int
vsw_mac_open(vsw_t *vswp)
{
	int	rv;

	ASSERT(MUTEX_HELD(&vswp->mac_lock));

	if (vswp->mh != NULL) {
		/* already open */
		return (0);
	}

	if (vswp->mac_open_retries++ >= vsw_mac_open_retries) {
		/* exceeded max retries */
		return (EIO);
	}

	rv = mac_open(vswp->physname, &vswp->mh);
	if (rv != 0) {
		/*
		 * If mac_open() failed and the error indicates that the
		 * device is not available yet, then, we return EAGAIN to
		 * indicate that it needs to be retried.
		 * For example, this may happen during boot up, as the
		 * required link aggregation groups(devices) have not been
		 * created yet.
		 */
		if (rv == ENOENT) {
			return (EAGAIN);
		} else {
			cmn_err(CE_WARN, "vsw%d: mac_open %s failed rv:%x",
			    vswp->instance, vswp->physname, rv);
			return (EIO);
		}
	}

	vswp->mac_open_retries = 0;

	return (0);
}

/*
 * Close the underlying physical device.
 */
void
vsw_mac_close(vsw_t *vswp)
{
	ASSERT(MUTEX_HELD(&vswp->mac_lock));

	if (vswp->mh != NULL) {
		mac_close(vswp->mh);
		vswp->mh = NULL;
	}
}

/*
 * Link into the MAC layer to gain access to the services provided by
 * the underlying physical device driver (which should also have
 * registered with the MAC layer).
 *
 * Only when in layer 2 mode.
 */
int
vsw_mac_attach(vsw_t *vswp)
{
	D1(vswp, "%s: enter", __func__);

	ASSERT(vswp->mrh == NULL);
	ASSERT(vswp->mstarted == B_FALSE);
	ASSERT(vswp->mresources == B_FALSE);

	ASSERT(MUTEX_HELD(&vswp->mac_lock));

	ASSERT(vswp->mh != NULL);

	D2(vswp, "vsw_mac_attach: using device %s", vswp->physname);

	if (vsw_multi_ring_enable) {
		/*
		 * Initialize the ring table.
		 */
		vsw_mac_ring_tbl_init(vswp);

		/*
		 * Register our rx callback function.
		 */
		vswp->mrh = mac_rx_add(vswp->mh,
		    vsw_rx_queue_cb, (void *)vswp);
		ASSERT(vswp->mrh != NULL);

		/*
		 * Register our mac resource callback.
		 */
		mac_resource_set(vswp->mh, vsw_mac_ring_add_cb, (void *)vswp);
		vswp->mresources = B_TRUE;

		/*
		 * Get the ring resources available to us from
		 * the mac below us.
		 */
		mac_resources(vswp->mh);
	} else {
		/*
		 * Just register our rx callback function
		 */
		vswp->mrh = mac_rx_add(vswp->mh, vsw_rx_cb, (void *)vswp);
		ASSERT(vswp->mrh != NULL);
	}

	/* Get the MAC tx fn */
	vswp->txinfo = mac_tx_get(vswp->mh);

	/* start the interface */
	if (mac_start(vswp->mh) != 0) {
		cmn_err(CE_WARN, "!vsw%d: Could not start mac interface",
		    vswp->instance);
		goto mac_fail_exit;
	}

	vswp->mstarted = B_TRUE;

	D1(vswp, "%s: exit", __func__);
	return (0);

mac_fail_exit:
	vsw_mac_detach(vswp);

	D1(vswp, "%s: exit", __func__);
	return (1);
}

void
vsw_mac_detach(vsw_t *vswp)
{
	D1(vswp, "vsw_mac_detach: enter");

	ASSERT(vswp != NULL);
	ASSERT(MUTEX_HELD(&vswp->mac_lock));

	if (vsw_multi_ring_enable) {
		vsw_mac_ring_tbl_destroy(vswp);
	}

	if (vswp->mh != NULL) {
		if (vswp->mstarted)
			mac_stop(vswp->mh);
		if (vswp->mrh != NULL)
			mac_rx_remove(vswp->mh, vswp->mrh, B_TRUE);
		if (vswp->mresources)
			mac_resource_set(vswp->mh, NULL, NULL);
	}

	vswp->mrh = NULL;
	vswp->txinfo = NULL;
	vswp->mstarted = B_FALSE;

	D1(vswp, "vsw_mac_detach: exit");
}

/*
 * Depending on the mode specified, the capabilites and capacity
 * of the underlying device setup the physical device.
 *
 * If in layer 3 mode, then do nothing.
 *
 * If in layer 2 programmed mode attempt to program the unicast address
 * associated with the port into the physical device. If this is not
 * possible due to resource exhaustion or simply because the device does
 * not support multiple unicast addresses then if required fallback onto
 * putting the card into promisc mode.
 *
 * If in promisc mode then simply set the card into promisc mode.
 *
 * Returns 0 success, 1 on failure.
 */
int
vsw_set_hw(vsw_t *vswp, vsw_port_t *port, int type)
{
	mac_multi_addr_t	mac_addr;
	int			err;

	D1(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->hw_lock));
	ASSERT((type == VSW_LOCALDEV) || (type == VSW_VNETPORT));

	if (vswp->smode[vswp->smode_idx] == VSW_LAYER3)
		return (0);

	if (vswp->smode[vswp->smode_idx] == VSW_LAYER2_PROMISC) {
		return (vsw_set_hw_promisc(vswp, port, type));
	}

	/*
	 * Attempt to program the unicast address into the HW.
	 */
	mac_addr.mma_addrlen = ETHERADDRL;
	if (type == VSW_VNETPORT) {
		ASSERT(port != NULL);
		ether_copy(&port->p_macaddr, &mac_addr.mma_addr);
	} else {
		ether_copy(&vswp->if_addr, &mac_addr.mma_addr);
	}

	err = vsw_set_hw_addr(vswp, &mac_addr);
	if (err == ENOSPC) {
		/*
		 * Mark that attempt should be made to re-config sometime
		 * in future if a port is deleted.
		 */
		vswp->recfg_reqd = B_TRUE;

		/*
		 * Only 1 mode specified, nothing more to do.
		 */
		if (vswp->smode_num == 1)
			return (err);

		/*
		 * If promiscuous was next mode specified try to
		 * set the card into that mode.
		 */
		if ((vswp->smode_idx <= (vswp->smode_num - 2)) &&
		    (vswp->smode[vswp->smode_idx + 1] ==
		    VSW_LAYER2_PROMISC)) {
			vswp->smode_idx += 1;
			return (vsw_set_hw_promisc(vswp, port, type));
		}
		return (err);
	}

	if (err != 0)
		return (err);

	if (type == VSW_VNETPORT) {
		port->addr_slot = mac_addr.mma_slot;
		port->addr_set = VSW_ADDR_HW;
	} else {
		vswp->addr_slot = mac_addr.mma_slot;
		vswp->addr_set = VSW_ADDR_HW;
	}

	D2(vswp, "programmed addr %s into slot %d "
	"of device %s", ether_sprintf((void *)mac_addr.mma_addr),
	    mac_addr.mma_slot, vswp->physname);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * If in layer 3 mode do nothing.
 *
 * If in layer 2 switched mode remove the address from the physical
 * device.
 *
 * If in layer 2 promiscuous mode disable promisc mode.
 *
 * Returns 0 on success.
 */
int
vsw_unset_hw(vsw_t *vswp, vsw_port_t *port, int type)
{
	mac_addr_slot_t	slot;
	int		rv;

	D1(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->hw_lock));

	if (vswp->smode[vswp->smode_idx] == VSW_LAYER3)
		return (0);

	switch (type) {
	case VSW_VNETPORT:
		ASSERT(port != NULL);

		if (port->addr_set == VSW_ADDR_PROMISC) {
			return (vsw_unset_hw_promisc(vswp, port, type));

		} else if (port->addr_set == VSW_ADDR_HW) {
			slot = port->addr_slot;
			if ((rv = vsw_unset_hw_addr(vswp, slot)) == 0)
				port->addr_set = VSW_ADDR_UNSET;
		}

		break;

	case VSW_LOCALDEV:
		if (vswp->addr_set == VSW_ADDR_PROMISC) {
			return (vsw_unset_hw_promisc(vswp, NULL, type));

		} else if (vswp->addr_set == VSW_ADDR_HW) {
			slot = vswp->addr_slot;
			if ((rv = vsw_unset_hw_addr(vswp, slot)) == 0)
				vswp->addr_set = VSW_ADDR_UNSET;
		}

		break;

	default:
		/* should never happen */
		DERR(vswp, "%s: unknown type %d", __func__, type);
		ASSERT(0);
		return (1);
	}

	D1(vswp, "%s: exit", __func__);
	return (rv);
}

/*
 * Attempt to program a unicast address into HW.
 *
 * Returns 0 on sucess, 1 on failure.
 */
static int
vsw_set_hw_addr(vsw_t *vswp, mac_multi_addr_t *mac)
{
	void	*mah;
	int	rv = EINVAL;

	D1(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->hw_lock));

	if (vswp->maddr.maddr_handle == NULL)
		return (rv);

	mah = vswp->maddr.maddr_handle;

	rv = vswp->maddr.maddr_add(mah, mac);

	if (rv == 0)
		return (rv);

	/*
	 * Its okay for the add to fail because we have exhausted
	 * all the resouces in the hardware device. Any other error
	 * we want to flag.
	 */
	if (rv != ENOSPC) {
		cmn_err(CE_WARN, "!vsw%d: error programming "
		    "address %s into HW err (%d)",
		    vswp->instance, ether_sprintf((void *)mac->mma_addr), rv);
	}
	D1(vswp, "%s: exit", __func__);
	return (rv);
}

/*
 * Remove a unicast mac address which has previously been programmed
 * into HW.
 *
 * Returns 0 on sucess, 1 on failure.
 */
static int
vsw_unset_hw_addr(vsw_t *vswp, int slot)
{
	void	*mah;
	int	rv;

	D1(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->hw_lock));
	ASSERT(slot >= 0);

	if (vswp->maddr.maddr_handle == NULL)
		return (1);

	mah = vswp->maddr.maddr_handle;

	rv = vswp->maddr.maddr_remove(mah, slot);
	if (rv != 0) {
		cmn_err(CE_WARN, "!vsw%d: unable to remove address "
		    "from slot %d in device %s (err %d)",
		    vswp->instance, slot, vswp->physname, rv);
		return (1);
	}

	D2(vswp, "removed addr from slot %d in device %s",
	    slot, vswp->physname);

	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Set network card into promisc mode.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_set_hw_promisc(vsw_t *vswp, vsw_port_t *port, int type)
{
	D1(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->hw_lock));
	ASSERT((type == VSW_LOCALDEV) || (type == VSW_VNETPORT));

	mutex_enter(&vswp->mac_lock);
	if (vswp->mh == NULL) {
		mutex_exit(&vswp->mac_lock);
		return (1);
	}

	if (vswp->promisc_cnt++ == 0) {
		if (mac_promisc_set(vswp->mh, B_TRUE, MAC_DEVPROMISC) != 0) {
			vswp->promisc_cnt--;
			mutex_exit(&vswp->mac_lock);
			return (1);
		}
		cmn_err(CE_NOTE, "!vsw%d: switching device %s into "
		    "promiscuous mode", vswp->instance, vswp->physname);
	}
	mutex_exit(&vswp->mac_lock);

	if (type == VSW_VNETPORT) {
		ASSERT(port != NULL);
		port->addr_set = VSW_ADDR_PROMISC;
	} else {
		vswp->addr_set = VSW_ADDR_PROMISC;
	}

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Turn off promiscuous mode on network card.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_unset_hw_promisc(vsw_t *vswp, vsw_port_t *port, int type)
{
	vsw_port_list_t 	*plist = &vswp->plist;

	D2(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->hw_lock));
	ASSERT((type == VSW_LOCALDEV) || (type == VSW_VNETPORT));

	mutex_enter(&vswp->mac_lock);
	if (vswp->mh == NULL) {
		mutex_exit(&vswp->mac_lock);
		return (1);
	}

	if (--vswp->promisc_cnt == 0) {
		if (mac_promisc_set(vswp->mh, B_FALSE, MAC_DEVPROMISC) != 0) {
			vswp->promisc_cnt++;
			mutex_exit(&vswp->mac_lock);
			return (1);
		}

		/*
		 * We are exiting promisc mode either because we were
		 * only in promisc mode because we had failed over from
		 * switched mode due to HW resource issues, or the user
		 * wanted the card in promisc mode for all the ports and
		 * the last port is now being deleted. Tweak the message
		 * accordingly.
		 */
		if (plist->num_ports != 0) {
			cmn_err(CE_NOTE, "!vsw%d: switching device %s back to "
			    "programmed mode", vswp->instance, vswp->physname);
		} else {
			cmn_err(CE_NOTE, "!vsw%d: switching device %s out of "
			    "promiscuous mode", vswp->instance, vswp->physname);
		}
	}
	mutex_exit(&vswp->mac_lock);

	if (type == VSW_VNETPORT) {
		ASSERT(port != NULL);
		ASSERT(port->addr_set == VSW_ADDR_PROMISC);
		port->addr_set = VSW_ADDR_UNSET;
	} else {
		ASSERT(vswp->addr_set == VSW_ADDR_PROMISC);
		vswp->addr_set = VSW_ADDR_UNSET;
	}

	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Determine whether or not we are operating in our prefered
 * mode and if not whether the physical resources now allow us
 * to operate in it.
 *
 * If a port is being removed should only be invoked after port has been
 * removed from the port list.
 */
void
vsw_reconfig_hw(vsw_t *vswp)
{
	int			s_idx;

	D1(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->hw_lock));

	if (vswp->maddr.maddr_handle == NULL) {
		return;
	}

	/*
	 * If we are in layer 2 (i.e. switched) or would like to be
	 * in layer 2 then check if any ports or the vswitch itself
	 * need to be programmed into the HW.
	 *
	 * This can happen in two cases - switched was specified as
	 * the prefered mode of operation but we exhausted the HW
	 * resources and so failed over to the next specifed mode,
	 * or switched was the only mode specified so after HW
	 * resources were exhausted there was nothing more we
	 * could do.
	 */
	if (vswp->smode_idx > 0)
		s_idx = vswp->smode_idx - 1;
	else
		s_idx = vswp->smode_idx;

	if (vswp->smode[s_idx] != VSW_LAYER2) {
		return;
	}

	D2(vswp, "%s: attempting reconfig..", __func__);

	/*
	 * First, attempt to set the vswitch mac address into HW,
	 * if required.
	 */
	if (vsw_prog_if(vswp)) {
		return;
	}

	/*
	 * Next, attempt to set any ports which have not yet been
	 * programmed into HW.
	 */
	if (vsw_prog_ports(vswp)) {
		return;
	}

	/*
	 * By now we know that have programmed all desired ports etc
	 * into HW, so safe to mark reconfiguration as complete.
	 */
	vswp->recfg_reqd = B_FALSE;

	vswp->smode_idx = s_idx;

	D1(vswp, "%s: exit", __func__);
}

/*
 * Check to see if vsw itself is plumbed, and if so whether or not
 * its mac address should be written into HW.
 *
 * Returns 0 if could set address, or didn't have to set it.
 * Returns 1 if failed to set address.
 */
static int
vsw_prog_if(vsw_t *vswp)
{
	mac_multi_addr_t	addr;

	D1(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->hw_lock));

	READ_ENTER(&vswp->if_lockrw);
	if ((vswp->if_state & VSW_IF_UP) &&
	    (vswp->addr_set != VSW_ADDR_HW)) {

		addr.mma_addrlen = ETHERADDRL;
		ether_copy(&vswp->if_addr, &addr.mma_addr);

		if (vsw_set_hw_addr(vswp, &addr) != 0) {
			RW_EXIT(&vswp->if_lockrw);
			return (1);
		}

		vswp->addr_slot = addr.mma_slot;

		/*
		 * If previously when plumbed had had to place
		 * interface into promisc mode, now reverse that.
		 *
		 * Note that interface will only actually be set into
		 * non-promisc mode when last port/interface has been
		 * programmed into HW.
		 */
		if (vswp->addr_set == VSW_ADDR_PROMISC)
			(void) vsw_unset_hw_promisc(vswp, NULL, VSW_LOCALDEV);

		vswp->addr_set = VSW_ADDR_HW;
	}
	RW_EXIT(&vswp->if_lockrw);

	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Scan the port list for any ports which have not yet been set
 * into HW. For those found attempt to program their mac addresses
 * into the physical device.
 *
 * Returns 0 if able to program all required ports (can be 0) into HW.
 * Returns 1 if failed to set at least one mac address.
 */
static int
vsw_prog_ports(vsw_t *vswp)
{
	mac_multi_addr_t	addr;
	vsw_port_list_t		*plist = &vswp->plist;
	vsw_port_t		*tp;
	int			rv = 0;

	D1(vswp, "%s: enter", __func__);

	ASSERT(MUTEX_HELD(&vswp->hw_lock));

	READ_ENTER(&plist->lockrw);
	for (tp = plist->head; tp != NULL; tp = tp->p_next) {
		if (tp->addr_set != VSW_ADDR_HW) {
			addr.mma_addrlen = ETHERADDRL;
			ether_copy(&tp->p_macaddr, &addr.mma_addr);

			if (vsw_set_hw_addr(vswp, &addr) != 0) {
				rv = 1;
				break;
			}

			tp->addr_slot = addr.mma_slot;

			/*
			 * If when this port had first attached we had
			 * had to place the interface into promisc mode,
			 * then now reverse that.
			 *
			 * Note that the interface will not actually
			 * change to non-promisc mode until all ports
			 * have been programmed.
			 */
			if (tp->addr_set == VSW_ADDR_PROMISC)
				(void) vsw_unset_hw_promisc(vswp,
				    tp, VSW_VNETPORT);

			tp->addr_set = VSW_ADDR_HW;
		}
	}
	RW_EXIT(&plist->lockrw);

	D1(vswp, "%s: exit", __func__);
	return (rv);
}

static void
vsw_mac_ring_tbl_entry_init(vsw_t *vswp, vsw_mac_ring_t *ringp)
{
	ringp->ring_state = VSW_MAC_RING_FREE;
	ringp->ring_arg = NULL;
	ringp->ring_blank = NULL;
	ringp->ring_vqp = NULL;
	ringp->ring_vswp = vswp;
}

static void
vsw_mac_ring_tbl_init(vsw_t *vswp)
{
	int		i;

	mutex_init(&vswp->mac_ring_lock, NULL, MUTEX_DRIVER, NULL);

	vswp->mac_ring_tbl_sz = vsw_mac_rx_rings;
	vswp->mac_ring_tbl  =
	    kmem_alloc(vsw_mac_rx_rings * sizeof (vsw_mac_ring_t), KM_SLEEP);

	for (i = 0; i < vswp->mac_ring_tbl_sz; i++)
		vsw_mac_ring_tbl_entry_init(vswp, &vswp->mac_ring_tbl[i]);
}

static void
vsw_mac_ring_tbl_destroy(vsw_t *vswp)
{
	int		i;
	vsw_mac_ring_t	*ringp;

	mutex_enter(&vswp->mac_ring_lock);
	for (i = 0; i < vswp->mac_ring_tbl_sz; i++) {
		ringp = &vswp->mac_ring_tbl[i];

		if (ringp->ring_state != VSW_MAC_RING_FREE) {
			/*
			 * Destroy the queue.
			 */
			vsw_queue_stop(ringp->ring_vqp);
			vsw_queue_destroy(ringp->ring_vqp);

			/*
			 * Re-initialize the structure.
			 */
			vsw_mac_ring_tbl_entry_init(vswp, ringp);
		}
	}
	mutex_exit(&vswp->mac_ring_lock);

	mutex_destroy(&vswp->mac_ring_lock);
	kmem_free(vswp->mac_ring_tbl,
	    vswp->mac_ring_tbl_sz * sizeof (vsw_mac_ring_t));
	vswp->mac_ring_tbl_sz = 0;
}

/*
 * Handle resource add callbacks from the driver below.
 */
static mac_resource_handle_t
vsw_mac_ring_add_cb(void *arg, mac_resource_t *mrp)
{
	vsw_t		*vswp = (vsw_t *)arg;
	mac_rx_fifo_t	*mrfp = (mac_rx_fifo_t *)mrp;
	vsw_mac_ring_t	*ringp;
	vsw_queue_t	*vqp;
	int		i;

	ASSERT(vswp != NULL);
	ASSERT(mrp != NULL);
	ASSERT(vswp->mac_ring_tbl != NULL);

	D1(vswp, "%s: enter", __func__);

	/*
	 * Check to make sure we have the correct resource type.
	 */
	if (mrp->mr_type != MAC_RX_FIFO)
		return (NULL);

	/*
	 * Find a open entry in the ring table.
	 */
	mutex_enter(&vswp->mac_ring_lock);
	for (i = 0; i < vswp->mac_ring_tbl_sz; i++) {
		ringp = &vswp->mac_ring_tbl[i];

		/*
		 * Check for an empty slot, if found, then setup queue
		 * and thread.
		 */
		if (ringp->ring_state == VSW_MAC_RING_FREE) {
			/*
			 * Create the queue for this ring.
			 */
			vqp = vsw_queue_create();

			/*
			 * Initialize the ring data structure.
			 */
			ringp->ring_vqp = vqp;
			ringp->ring_arg = mrfp->mrf_arg;
			ringp->ring_blank = mrfp->mrf_blank;
			ringp->ring_state = VSW_MAC_RING_INUSE;

			/*
			 * Create the worker thread.
			 */
			vqp->vq_worker = thread_create(NULL, 0,
			    vsw_queue_worker, ringp, 0, &p0,
			    TS_RUN, minclsyspri);
			if (vqp->vq_worker == NULL) {
				vsw_queue_destroy(vqp);
				vsw_mac_ring_tbl_entry_init(vswp, ringp);
				ringp = NULL;
			}

			if (ringp != NULL) {
				/*
				 * Make sure thread get's running state for
				 * this ring.
				 */
				mutex_enter(&vqp->vq_lock);
				while ((vqp->vq_state != VSW_QUEUE_RUNNING) &&
				    (vqp->vq_state != VSW_QUEUE_DRAINED)) {
					cv_wait(&vqp->vq_cv, &vqp->vq_lock);
				}

				/*
				 * If the thread is not running, cleanup.
				 */
				if (vqp->vq_state == VSW_QUEUE_DRAINED) {
					vsw_queue_destroy(vqp);
					vsw_mac_ring_tbl_entry_init(vswp,
					    ringp);
					ringp = NULL;
				}
				mutex_exit(&vqp->vq_lock);
			}

			mutex_exit(&vswp->mac_ring_lock);
			D1(vswp, "%s: exit", __func__);
			return ((mac_resource_handle_t)ringp);
		}
	}
	mutex_exit(&vswp->mac_ring_lock);

	/*
	 * No slots in the ring table available.
	 */
	D1(vswp, "%s: exit", __func__);
	return (NULL);
}

static void
vsw_queue_stop(vsw_queue_t *vqp)
{
	mutex_enter(&vqp->vq_lock);

	if (vqp->vq_state == VSW_QUEUE_RUNNING) {
		vqp->vq_state = VSW_QUEUE_STOP;
		cv_signal(&vqp->vq_cv);

		while (vqp->vq_state != VSW_QUEUE_DRAINED)
			cv_wait(&vqp->vq_cv, &vqp->vq_lock);
	}

	vqp->vq_state = VSW_QUEUE_STOPPED;

	mutex_exit(&vqp->vq_lock);
}

static vsw_queue_t *
vsw_queue_create()
{
	vsw_queue_t *vqp;

	vqp = kmem_zalloc(sizeof (vsw_queue_t), KM_SLEEP);

	mutex_init(&vqp->vq_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vqp->vq_cv, NULL, CV_DRIVER, NULL);
	vqp->vq_first = NULL;
	vqp->vq_last = NULL;
	vqp->vq_state = VSW_QUEUE_STOPPED;

	return (vqp);
}

static void
vsw_queue_destroy(vsw_queue_t *vqp)
{
	cv_destroy(&vqp->vq_cv);
	mutex_destroy(&vqp->vq_lock);
	kmem_free(vqp, sizeof (vsw_queue_t));
}

static void
vsw_queue_worker(vsw_mac_ring_t *rrp)
{
	mblk_t		*mp;
	vsw_queue_t	*vqp = rrp->ring_vqp;
	vsw_t		*vswp = rrp->ring_vswp;

	mutex_enter(&vqp->vq_lock);

	ASSERT(vqp->vq_state == VSW_QUEUE_STOPPED);

	/*
	 * Set the state to running, since the thread is now active.
	 */
	vqp->vq_state = VSW_QUEUE_RUNNING;
	cv_signal(&vqp->vq_cv);

	while (vqp->vq_state == VSW_QUEUE_RUNNING) {
		/*
		 * Wait for work to do or the state has changed
		 * to not running.
		 */
		while ((vqp->vq_state == VSW_QUEUE_RUNNING) &&
		    (vqp->vq_first == NULL)) {
			cv_wait(&vqp->vq_cv, &vqp->vq_lock);
		}

		/*
		 * Process packets that we received from the interface.
		 */
		if (vqp->vq_first != NULL) {
			mp = vqp->vq_first;

			vqp->vq_first = NULL;
			vqp->vq_last = NULL;

			mutex_exit(&vqp->vq_lock);

			/* switch the chain of packets received */
			vswp->vsw_switch_frame(vswp, mp,
			    VSW_PHYSDEV, NULL, NULL);

			mutex_enter(&vqp->vq_lock);
		}
	}

	/*
	 * We are drained and signal we are done.
	 */
	vqp->vq_state = VSW_QUEUE_DRAINED;
	cv_signal(&vqp->vq_cv);

	/*
	 * Exit lock and drain the remaining packets.
	 */
	mutex_exit(&vqp->vq_lock);

	/*
	 * Exit the thread
	 */
	thread_exit();
}

/*
 * static void
 * vsw_rx_queue_cb() - Receive callback routine when
 *	vsw_multi_ring_enable is non-zero.  Queue the packets
 *	to a packet queue for a worker thread to process.
 */
static void
vsw_rx_queue_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	vsw_mac_ring_t	*ringp = (vsw_mac_ring_t *)mrh;
	vsw_t		*vswp = (vsw_t *)arg;
	vsw_queue_t	*vqp;
	mblk_t		*bp, *last;

	ASSERT(mrh != NULL);
	ASSERT(vswp != NULL);
	ASSERT(mp != NULL);

	D1(vswp, "%s: enter", __func__);

	/*
	 * Find the last element in the mblk chain.
	 */
	bp = mp;
	do {
		last = bp;
		bp = bp->b_next;
	} while (bp != NULL);

	/* Get the queue for the packets */
	vqp = ringp->ring_vqp;

	/*
	 * Grab the lock such we can queue the packets.
	 */
	mutex_enter(&vqp->vq_lock);

	if (vqp->vq_state != VSW_QUEUE_RUNNING) {
		freemsgchain(mp);
		mutex_exit(&vqp->vq_lock);
		goto vsw_rx_queue_cb_exit;
	}

	/*
	 * Add the mblk chain to the queue.  If there
	 * is some mblks in the queue, then add the new
	 * chain to the end.
	 */
	if (vqp->vq_first == NULL)
		vqp->vq_first = mp;
	else
		vqp->vq_last->b_next = mp;

	vqp->vq_last = last;

	/*
	 * Signal the worker thread that there is work to
	 * do.
	 */
	cv_signal(&vqp->vq_cv);

	/*
	 * Let go of the lock and exit.
	 */
	mutex_exit(&vqp->vq_lock);

vsw_rx_queue_cb_exit:
	D1(vswp, "%s: exit", __func__);
}

/*
 * receive callback routine. Invoked by MAC layer when there
 * are pkts being passed up from physical device.
 *
 * PERF: It may be more efficient when the card is in promisc
 * mode to check the dest address of the pkts here (against
 * the FDB) rather than checking later. Needs to be investigated.
 */
static void
vsw_rx_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	_NOTE(ARGUNUSED(mrh))

	vsw_t		*vswp = (vsw_t *)arg;

	ASSERT(vswp != NULL);

	D1(vswp, "vsw_rx_cb: enter");

	/* switch the chain of packets received */
	vswp->vsw_switch_frame(vswp, mp, VSW_PHYSDEV, NULL, NULL);

	D1(vswp, "vsw_rx_cb: exit");
}

/*
 * Send a message out over the physical device via the MAC layer.
 *
 * Returns any mblks that it was unable to transmit.
 */
mblk_t *
vsw_tx_msg(vsw_t *vswp, mblk_t *mp)
{
	const mac_txinfo_t	*mtp;

	mutex_enter(&vswp->mac_lock);
	if ((vswp->mh == NULL) || (vswp->mstarted == B_FALSE)) {

		DERR(vswp, "vsw_tx_msg: dropping pkts: no tx routine avail");
		mutex_exit(&vswp->mac_lock);
		return (mp);
	} else {
		mtp = vswp->txinfo;
		mp = mtp->mt_fn(mtp->mt_arg, mp);
	}
	mutex_exit(&vswp->mac_lock);

	return (mp);
}
