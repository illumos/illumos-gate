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
#include <netinet/arp.h>
#include <inet/arp.h>
#include <sys/varargs.h>
#include <sys/machsystm.h>
#include <sys/modctl.h>
#include <sys/modhash.h>
#include <sys/mac_client.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/taskq.h>
#include <sys/note.h>
#include <sys/mach_descrip.h>
#include <sys/mac.h>
#include <sys/mdeg.h>
#include <sys/vsw.h>
#include <sys/vlan.h>

/* MAC Ring table functions. */
static void vsw_port_rx_cb(void *, mac_resource_handle_t, mblk_t *,
    boolean_t);
static void vsw_if_rx_cb(void *, mac_resource_handle_t, mblk_t *, boolean_t);

/* MAC layer routines */
static int vsw_set_port_hw_addr(vsw_port_t *port);
static int vsw_set_if_hw_addr(vsw_t *vswp);
static	void vsw_unset_hw_addr(vsw_t *, vsw_port_t *, int);
static int vsw_maccl_open(vsw_t *vswp, vsw_port_t *port, int type);
static void vsw_maccl_close(vsw_t *vswp, vsw_port_t *port, int type);
static void vsw_mac_multicast_add_all(vsw_t *vswp, vsw_port_t *portp, int type);
static void vsw_mac_multicast_remove_all(vsw_t *vswp,
    vsw_port_t *portp, int type);
static void vsw_mac_add_vlans(vsw_t *vswp, mac_client_handle_t mch,
    uint8_t *macaddr, uint16_t flags, vsw_vlanid_t *vids, int nvids);
static void vsw_mac_remove_vlans(mac_client_handle_t mch, vsw_vlanid_t *vids,
    int nvids);
static	void vsw_mac_set_mtu(vsw_t *vswp, uint32_t mtu);

/* Support functions */
int vsw_set_hw(vsw_t *, vsw_port_t *, int);
void vsw_unset_hw(vsw_t *, vsw_port_t *, int);
void vsw_reconfig_hw(vsw_t *);
int vsw_mac_open(vsw_t *vswp);
void vsw_mac_close(vsw_t *vswp);
int vsw_mac_multicast_add(vsw_t *vswp, vsw_port_t *port, mcst_addr_t *mcst_p,
    int type);
void vsw_mac_multicast_remove(vsw_t *vswp, vsw_port_t *port,
    mcst_addr_t *mcst_p, int type);
int vsw_mac_client_init(vsw_t *vswp, vsw_port_t *port, int type);
void vsw_mac_client_cleanup(vsw_t *vswp, vsw_port_t *port, int type);
void vsw_mac_cleanup_ports(vsw_t *vswp);
void vsw_unset_addrs(vsw_t *vswp);
void vsw_set_addrs(vsw_t *vswp);
mblk_t *vsw_tx_msg(vsw_t *, mblk_t *, int, vsw_port_t *);
void vsw_publish_macaddr(vsw_t *vswp, vsw_port_t *portp);
void vsw_port_mac_reconfig(vsw_port_t *portp, boolean_t update_vlans,
    uint16_t new_pvid, vsw_vlanid_t *new_vids, int new_nvids);
void vsw_mac_port_reconfig_vlans(vsw_port_t *portp, uint16_t new_pvid,
    vsw_vlanid_t *new_vids, int new_nvids);
void vsw_if_mac_reconfig(vsw_t *vswp, boolean_t update_vlans,
    uint16_t new_pvid, vsw_vlanid_t *new_vids, int new_nvids);

/*
 * Functions imported from other files.
 */
extern int vsw_portsend(vsw_port_t *port, mblk_t *mp);
extern void vsw_hio_stop_port(vsw_port_t *portp);
extern void vsw_hio_port_reset(vsw_port_t *portp, boolean_t immediate);
extern uint32_t vsw_publish_macaddr_count;
extern uint32_t vsw_vlan_frame_untag(void *arg, int type, mblk_t **np,
	mblk_t **npt);
static char mac_mtu_propname[] = "mtu";

/*
 * Tunables used in this file.
 */
extern int vsw_mac_open_retries;


#define	WRITE_MACCL_ENTER(vswp, port, type)	\
	(type == VSW_LOCALDEV) ?  rw_enter(&vswp->maccl_rwlock, RW_WRITER) :\
	rw_enter(&port->maccl_rwlock, RW_WRITER)

#define	READ_MACCL_ENTER(vswp, port, type)	\
	(type == VSW_LOCALDEV) ?  rw_enter(&vswp->maccl_rwlock, RW_READER) :\
	rw_enter(&port->maccl_rwlock, RW_READER)

#define	RW_MACCL_EXIT(vswp, port, type)	\
	(type == VSW_LOCALDEV) ?  rw_exit(&vswp->maccl_rwlock) :	\
	rw_exit(&port->maccl_rwlock)


/*
 * Locking strategy in this file is explained as follows:
 *	 - A global lock(vswp->mac_lock) is used to protect the
 *	   MAC calls that deal with entire device. That is, the
 *	   operations that deal with mac_handle which include
 *	   mac_open()/close() and mac_client_open().
 *
 *	- A per port/interface RW lock(maccl_rwlock) is used protect
 *	  the operations that deal with the MAC client.
 *
 *	When both mac_lock and maccl_rwlock need to be held, the
 *	mac_lock need be acquired first and then maccl_rwlock. That is,
 *		mac_lock---->maccl_rwlock
 *
 *	The 'mca_lock' that protects the mcast list is also acquired
 *	within the context of maccl_rwlock. The hierarchy for this
 *	one is as below:
 *		maccl_rwlock---->mca_lock
 */


/*
 * Program unicast and multicast addresses of vsw interface and the ports
 * into the network device.
 */
void
vsw_set_addrs(vsw_t *vswp)
{
	vsw_port_list_t	*plist = &vswp->plist;
	vsw_port_t	*port;
	int		rv;

	READ_ENTER(&vswp->if_lockrw);

	if (vswp->if_state & VSW_IF_UP) {

		/* Open a mac client and program addresses */
		rv = vsw_mac_client_init(vswp, NULL, VSW_LOCALDEV);
		if (rv != 0) {
			cmn_err(CE_NOTE,
			    "!vsw%d: failed to program interface "
			    "unicast address\n", vswp->instance);
		}

		/*
		 * Notify the MAC layer of the changed address.
		 */
		if (rv == 0) {
			mac_unicst_update(vswp->if_mh,
			    (uint8_t *)&vswp->if_addr);
		}

	}

	RW_EXIT(&vswp->if_lockrw);

	WRITE_ENTER(&plist->lockrw);

	/* program unicast address of ports in the network device */
	for (port = plist->head; port != NULL; port = port->p_next) {
		if (port->addr_set) /* addr already set */
			continue;

		/* Open a mac client and program addresses */
		rv = vsw_mac_client_init(vswp, port, VSW_VNETPORT);
		if (rv != 0) {
			cmn_err(CE_NOTE,
			    "!vsw%d: failed to program port(%d) "
			    "unicast address\n", vswp->instance,
			    port->p_instance);
		}
	}
	/* announce macaddr of vnets to the physical switch */
	if (vsw_publish_macaddr_count != 0) {	/* enabled */
		for (port = plist->head; port != NULL; port = port->p_next) {
			vsw_publish_macaddr(vswp, port);
		}
	}

	RW_EXIT(&plist->lockrw);
}

/*
 * Remove unicast, multicast addresses and close mac clients
 * for the vsw interface and all ports.
 */
void
vsw_unset_addrs(vsw_t *vswp)
{
	READ_ENTER(&vswp->if_lockrw);
	if (vswp->if_state & VSW_IF_UP) {

		/* Cleanup and close the mac client for the interface */
		vsw_mac_client_cleanup(vswp, NULL, VSW_LOCALDEV);
	}
	RW_EXIT(&vswp->if_lockrw);

	/* Cleanup and close the mac clients for all ports */
	vsw_mac_cleanup_ports(vswp);
}

/*
 * Open the underlying network device for access in layer2 mode.
 * Returns:
 *	0 on success
 *	EAGAIN if mac_open() fails due to the device being not available yet.
 *	EIO on any other failures.
 */
int
vsw_mac_open(vsw_t *vswp)
{
	int			rv;

	ASSERT(MUTEX_HELD(&vswp->mac_lock));

	if (vswp->mh != NULL) {
		/* already open */
		return (0);
	}

	if (vswp->mac_open_retries++ >= vsw_mac_open_retries) {
		/* exceeded max retries */
		return (EIO);
	}

	if ((rv = mac_open_by_linkname(vswp->physname, &vswp->mh)) != 0) {
		/*
		 * If mac_open() failed and the error indicates that either
		 * the dlmgmtd door or the device is not available yet, we
		 * return EAGAIN to indicate that mac_open() needs to be
		 * retried. For example, this may happen during boot up, if
		 * the required link aggregation groups(devices) have not
		 * been created yet.
		 */
		if (rv == ENOENT || rv == EBADF) {
			return (EAGAIN);
		} else {
			cmn_err(CE_WARN, "vsw%d: mac_open %s failed rv:%x",
			    vswp->instance, vswp->physname, rv);
			return (EIO);
		}
	}
	vswp->mac_open_retries = 0;

	vsw_mac_set_mtu(vswp, vswp->mtu);

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
		if (vswp->mtu != vswp->mtu_physdev_orig) {
			vsw_mac_set_mtu(vswp, vswp->mtu_physdev_orig);
		}
		mac_close(vswp->mh);
		vswp->mh = NULL;
	}
}

/*
 * Add multicast addr.
 */
int
vsw_mac_multicast_add(vsw_t *vswp, vsw_port_t *port, mcst_addr_t *mcst_p,
    int type)
{
	int			ret = 0;
	mac_client_handle_t	mch;

	WRITE_MACCL_ENTER(vswp, port, type);

	mch = (type == VSW_LOCALDEV) ? vswp->mch : port->p_mch;

	if (mch != NULL) {
		ret = mac_multicast_add(mch, mcst_p->mca.ether_addr_octet);
		if (ret != 0) {
			cmn_err(CE_WARN, "!vsw%d: unable to "
			    "program multicast address(%s) err=%d",
			    vswp->instance,
			    ether_sprintf((void *)&mcst_p->mca), ret);
			RW_MACCL_EXIT(vswp, port, type);
			return (ret);
		}
		mcst_p->mac_added = B_TRUE;
	}

	RW_MACCL_EXIT(vswp, port, type);
	return (ret);
}

/*
 * Remove multicast addr.
 */
void
vsw_mac_multicast_remove(vsw_t *vswp, vsw_port_t *port, mcst_addr_t *mcst_p,
    int type)
{
	mac_client_handle_t	mch;

	WRITE_MACCL_ENTER(vswp, port, type);
	mch = (type == VSW_LOCALDEV) ? vswp->mch : port->p_mch;

	if (mch != NULL && mcst_p->mac_added) {
		mac_multicast_remove(mch, mcst_p->mca.ether_addr_octet);
		mcst_p->mac_added = B_FALSE;
	}
	RW_MACCL_EXIT(vswp, port, type);
}


/*
 * Add all multicast addresses of the port.
 */
static void
vsw_mac_multicast_add_all(vsw_t *vswp, vsw_port_t *portp, int type)
{
	mcst_addr_t		*mcap;
	mac_client_handle_t	mch;
	kmutex_t		*mca_lockp;
	int			rv;

	ASSERT((type == VSW_LOCALDEV) || (type == VSW_VNETPORT));
	if (type == VSW_LOCALDEV) {
		ASSERT(RW_WRITE_HELD(&vswp->maccl_rwlock));
		mch = vswp->mch;
		mcap = vswp->mcap;
		mca_lockp = &vswp->mca_lock;
	} else {
		ASSERT(RW_WRITE_HELD(&portp->maccl_rwlock));
		mch = portp->p_mch;
		mcap = portp->mcap;
		mca_lockp = &portp->mca_lock;
	}

	if (mch == NULL)
		return;

	mutex_enter(mca_lockp);
	for (mcap = mcap; mcap != NULL; mcap = mcap->nextp) {
		if (mcap->mac_added)
			continue;
		rv = mac_multicast_add(mch, (uchar_t *)&mcap->mca);
		if (rv == 0) {
			mcap->mac_added = B_TRUE;
		} else {
			cmn_err(CE_WARN, "!vsw%d: unable to program "
			    "multicast address(%s) err=%d", vswp->instance,
			    ether_sprintf((void *)&mcap->mca), rv);
		}
	}
	mutex_exit(mca_lockp);
}

/*
 * Remove all multicast addresses of the port.
 */
static void
vsw_mac_multicast_remove_all(vsw_t *vswp, vsw_port_t *portp, int type)
{
	mac_client_handle_t	mch;
	mcst_addr_t		*mcap;
	kmutex_t		*mca_lockp;

	ASSERT((type == VSW_LOCALDEV) || (type == VSW_VNETPORT));
	if (type == VSW_LOCALDEV) {
		ASSERT(RW_WRITE_HELD(&vswp->maccl_rwlock));
		mch = vswp->mch;
		mcap = vswp->mcap;
		mca_lockp = &vswp->mca_lock;
	} else {
		ASSERT(RW_WRITE_HELD(&portp->maccl_rwlock));
		mch = portp->p_mch;
		mcap = portp->mcap;
		mca_lockp = &portp->mca_lock;
	}

	if (mch == NULL)
		return;

	mutex_enter(mca_lockp);
	for (; mcap != NULL; mcap = mcap->nextp) {
		if (!mcap->mac_added)
			continue;
		(void) mac_multicast_remove(mch, (uchar_t *)&mcap->mca);
		mcap->mac_added = B_FALSE;
	}
	mutex_exit(mca_lockp);
}

/*
 * Open a mac client and program uncast and multicast addresses
 * for a port or the interface.
 * Returns:
 *	0 on success
 *	non-zero for failure.
 */
int
vsw_mac_client_init(vsw_t *vswp, vsw_port_t *port, int type)
{
	int rv;

	mutex_enter(&vswp->mac_lock);
	WRITE_MACCL_ENTER(vswp, port, type);
	rv = vsw_maccl_open(vswp, port, type);

	/* Release mac_lock now */
	mutex_exit(&vswp->mac_lock);

	if (rv == 0) {
		(void) vsw_set_hw(vswp, port, type);
		vsw_mac_multicast_add_all(vswp, port, type);
	}
	RW_MACCL_EXIT(vswp, port, type);
	return (rv);
}

/*
 * Open a MAC client for a port or an interface.
 * The flags and their purpose as below:
 *
 *	MAC_OPEN_FLAGS_NO_HWRINGS -- This flag is used by default
 *	for all ports/interface so that they are associated with
 *	default group & resources. It will not be used for the
 *	ports that have HybridIO is enabled so that the h/w resources
 *	assigned to it.
 *
 *	MAC_OPEN_FLAGS_SHARES_DESIRED -- This flag is used to indicate
 *	that a port desires a Share. This will be the case with the
 *	the ports that have hybrid mode enabled. This will only cause
 *	MAC layer to allocate a share and corresponding resources
 *	ahead of time.
 *
 *	MAC_OPEN_FLAGS_TAG_DISABLE -- This flag is used for VLAN
 *	support. It will cause MAC to not add any tags, but expect
 *	vsw to tag the packets.
 *
 *	MAC_OPEN_FLAGS_STRIP_DISABLE -- This flag is used for VLAN
 *	support. It will case the MAC layer to not strip the tags.
 *	Vsw may have to strip the tag for pvid case.
 */
static int
vsw_maccl_open(vsw_t *vswp, vsw_port_t *port, int type)
{
	int		rv = 0;
	int		instance;
	char		mac_cl_name[MAXNAMELEN];
	const char	*dev_name;
	mac_client_handle_t *mchp;
	uint64_t flags = (MAC_OPEN_FLAGS_NO_HWRINGS |
	    MAC_OPEN_FLAGS_TAG_DISABLE |
	    MAC_OPEN_FLAGS_STRIP_DISABLE);

	ASSERT(MUTEX_HELD(&vswp->mac_lock));
	if (vswp->mh == NULL) {
		/*
		 * In case net-dev is changed (either set to nothing or
		 * using aggregation device), return success here as the
		 * timeout mechanism will handle it.
		 */
		return (0);
	}

	mchp = (type == VSW_LOCALDEV) ? &vswp->mch : &port->p_mch;
	if (*mchp != NULL) {
		/* already open */
		return (0);
	}
	dev_name = ddi_driver_name(vswp->dip);
	instance = ddi_get_instance(vswp->dip);
	if (type == VSW_VNETPORT) {
		if (port->p_hio_enabled == B_TRUE) {
			flags &= ~MAC_OPEN_FLAGS_NO_HWRINGS;
			flags |= MAC_OPEN_FLAGS_SHARES_DESIRED;
		}
		(void) snprintf(mac_cl_name, MAXNAMELEN, "%s%d%s%d", dev_name,
		    instance, "_port", port->p_instance);
	} else {
		(void) snprintf(mac_cl_name, MAXNAMELEN, "%s%s%d",
		    dev_name, "_if", instance);
	}

	rv = mac_client_open(vswp->mh, mchp, mac_cl_name, flags);
	if (rv != 0) {
		cmn_err(CE_NOTE, "!vsw%d:%s mac_client_open() failed\n",
		    vswp->instance, mac_cl_name);
	}
	return (rv);
}

/*
 * Clean up by removing uncast, multicast addresses and
 * closing the MAC client for a port or the interface.
 */
void
vsw_mac_client_cleanup(vsw_t *vswp, vsw_port_t *port, int type)
{
	WRITE_MACCL_ENTER(vswp, port, type);
	vsw_unset_hw(vswp, port, type);
	vsw_maccl_close(vswp, port, type);
	vsw_mac_multicast_remove_all(vswp, port, type);
	RW_MACCL_EXIT(vswp, port, type);
}

/*
 * Close a MAC client for a port or an interface.
 */
static void
vsw_maccl_close(vsw_t *vswp, vsw_port_t *port, int type)
{
	mac_client_handle_t *mchp;

	ASSERT((type == VSW_LOCALDEV) || (type == VSW_VNETPORT));

	mchp = (type == VSW_LOCALDEV) ? &vswp->mch : &port->p_mch;
	if (*mchp != NULL) {
		mac_client_close(*mchp, 0);
		*mchp = NULL;
	}
}

/*
 * Cleanup MAC client related stuff for all ports.
 */
void
vsw_mac_cleanup_ports(vsw_t *vswp)
{
	vsw_port_list_t		*plist = &vswp->plist;
	vsw_port_t		*port;

	READ_ENTER(&plist->lockrw);
	for (port = plist->head; port != NULL; port = port->p_next) {
		vsw_mac_client_cleanup(vswp, port, VSW_VNETPORT);
	}
	RW_EXIT(&plist->lockrw);
}

/*
 * Depending on the mode specified, the capabilites and capacity
 * of the underlying device setup the physical device.
 *
 * If in layer 3 mode, then do nothing.
 *
 * If in layer 2 mode, open a mac client and program the mac-address
 * and vlan-ids. The MAC layer will take care of programming
 * the address into h/w or set the h/w into promiscuous mode.
 *
 * Returns 0 success, 1 on failure.
 */
int
vsw_set_hw(vsw_t *vswp, vsw_port_t *port, int type)
{
	int			err = 1;

	D1(vswp, "%s: enter", __func__);

	ASSERT((type == VSW_LOCALDEV) || (type == VSW_VNETPORT));

	if (vswp->smode == VSW_LAYER3)
		return (0);

	if (type == VSW_VNETPORT) {
		ASSERT(port != NULL);
		err = vsw_set_port_hw_addr(port);
	} else {
		err = vsw_set_if_hw_addr(vswp);
	}

	D1(vswp, "%s: exit", __func__);
	return (err);
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
void
vsw_unset_hw(vsw_t *vswp, vsw_port_t *port, int type)
{
	D1(vswp, "%s: enter", __func__);

	ASSERT((type == VSW_LOCALDEV) || (type == VSW_VNETPORT));

	if (vswp->smode == VSW_LAYER3)
		return;

	if (type == VSW_VNETPORT) {
		ASSERT(port != NULL);
		vsw_unset_hw_addr(vswp, port, type);
	} else {
		vsw_unset_hw_addr(vswp, NULL, type);
	}

	D1(vswp, "%s: exit", __func__);
}

/*
 * Program the macaddress and vlans of a port.
 *
 * Returns 0 on sucess, 1 on failure.
 */
static int
vsw_set_port_hw_addr(vsw_port_t *port)
{
	vsw_t			*vswp = port->p_vswp;
	uint16_t		mac_flags = 0;
	mac_diag_t		diag;
	uint8_t			*macaddr;
	uint16_t		vid = VLAN_ID_NONE;
	int			rv;

	D1(vswp, "%s: enter", __func__);

	ASSERT(RW_WRITE_HELD(&port->maccl_rwlock));
	if (port->p_mch == NULL)
		return (0);

	/*
	 * If the port has a specific 'pvid', then
	 * register with that vlan-id, otherwise register
	 * with VLAN_ID_NONE.
	 */
	if (port->pvid != vswp->default_vlan_id) {
		vid = port->pvid;
	}
	macaddr = (uint8_t *)port->p_macaddr.ether_addr_octet;

	if (!(vswp->smode & VSW_LAYER2_PROMISC)) {
		mac_flags |= MAC_UNICAST_HW;
	}

	if (port->addr_set == B_FALSE) {
		port->p_muh = NULL;
		rv = mac_unicast_add(port->p_mch, macaddr, mac_flags,
		    &port->p_muh, vid, &diag);

		if (rv != 0) {
			cmn_err(CE_WARN, "vsw%d: Failed to program"
			    "macaddr,vid(%s, %d) err=%d",
			    vswp->instance, ether_sprintf((void *)macaddr),
			    vid, rv);
			return (rv);
		}
		port->addr_set = B_TRUE;

		D2(vswp, "%s:programmed macaddr(%s) vid(%d) into device %s",
		    __func__, ether_sprintf((void *)macaddr), vid,
		    vswp->physname);
	}

	/* Add vlans to the MAC layer */
	vsw_mac_add_vlans(vswp, port->p_mch, macaddr,
	    mac_flags, port->vids, port->nvids);

	mac_rx_set(port->p_mch, vsw_port_rx_cb, (void *)port);

	D1(vswp, "%s: exit", __func__);
	return (rv);
}

/*
 * Program the macaddress and vlans of a port.
 *
 * Returns 0 on sucess, 1 on failure.
 */
static int
vsw_set_if_hw_addr(vsw_t *vswp)
{
	uint16_t		mac_flags = 0;
	mac_diag_t		diag;
	uint8_t			*macaddr;
	uint8_t			primary_addr[ETHERADDRL];
	uint16_t		vid = VLAN_ID_NONE;
	int			rv;

	D1(vswp, "%s: enter", __func__);

	ASSERT(RW_WRITE_HELD(&vswp->maccl_rwlock));
	if (vswp->mch == NULL)
		return (0);

	macaddr = (uint8_t *)vswp->if_addr.ether_addr_octet;

	/* check if it is the primary macaddr of the card. */
	mac_unicast_primary_get(vswp->mh, primary_addr);
	if (ether_cmp((void *)primary_addr, (void*)macaddr) == 0) {
		mac_flags |= MAC_UNICAST_PRIMARY;
	}

	/*
	 * If the interface has a specific 'pvid', then
	 * register with that vlan-id, otherwise register
	 * with VLAN_ID_NONE.
	 */
	if (vswp->pvid != vswp->default_vlan_id) {
		vid = vswp->pvid;
	}

	if (!(vswp->smode & VSW_LAYER2_PROMISC)) {
		mac_flags |= MAC_UNICAST_HW;
	}

	if (vswp->addr_set == B_FALSE) {
		vswp->muh = NULL;
		rv = mac_unicast_add(vswp->mch, macaddr, mac_flags,
		    &vswp->muh, vid, &diag);

		if (rv != 0) {
			cmn_err(CE_WARN, "vsw%d: Failed to program"
			    "macaddr,vid(%s, %d) err=%d",
			    vswp->instance, ether_sprintf((void *)macaddr),
			    vid, rv);
			return (rv);
		}
		vswp->addr_set = B_TRUE;

		D2(vswp, "%s:programmed macaddr(%s) vid(%d) into device %s",
		    __func__, ether_sprintf((void *)macaddr), vid,
		    vswp->physname);
	}

	vsw_mac_add_vlans(vswp, vswp->mch, macaddr, mac_flags,
	    vswp->vids, vswp->nvids);

	mac_rx_set(vswp->mch, vsw_if_rx_cb, (void *)vswp);

	D1(vswp, "%s: exit", __func__);
	return (rv);
}

/*
 * Remove a unicast mac address which has previously been programmed
 * into HW.
 *
 * Returns 0 on sucess, 1 on failure.
 */
static void
vsw_unset_hw_addr(vsw_t *vswp, vsw_port_t *port, int type)
{
	vsw_vlanid_t		*vids;
	int			nvids;
	mac_client_handle_t	mch = NULL;

	D1(vswp, "%s: enter", __func__);

	ASSERT((type == VSW_LOCALDEV) || (type == VSW_VNETPORT));

	if (type == VSW_VNETPORT) {
		ASSERT(port != NULL);
		ASSERT(RW_WRITE_HELD(&port->maccl_rwlock));
		vids = port->vids;
		nvids = port->nvids;
	} else {
		ASSERT(RW_WRITE_HELD(&vswp->maccl_rwlock));
		vids = vswp->vids;
		nvids = vswp->nvids;
	}

	/* First clear the callback */
	if (type == VSW_LOCALDEV) {
		mch = vswp->mch;
	} else if (type == VSW_VNETPORT) {
		mch = port->p_mch;
	}


	if (mch == NULL) {
		return;
	}

	mac_rx_clear(mch);

	/* Remove vlans */
	vsw_mac_remove_vlans(mch, vids, nvids);

	if ((type == VSW_LOCALDEV) && (vswp->addr_set == B_TRUE)) {
		(void) mac_unicast_remove(vswp->mch, vswp->muh);
		vswp->muh = NULL;
		D2(vswp, "removed vsw interface mac-addr from "
		    "the device %s", vswp->physname);
		vswp->addr_set = B_FALSE;

	} else if ((type == VSW_VNETPORT) && (port->addr_set == B_TRUE)) {
		(void) mac_unicast_remove(port->p_mch, port->p_muh);
		port->p_muh = NULL;
		D2(vswp, "removed port(0x%p) mac-addr from "
		    "the device %s", port, vswp->physname);
		port->addr_set = B_FALSE;
	}

	D1(vswp, "%s: exit", __func__);
}

/*
 * receive callback routine for vsw interface. Invoked by MAC layer when there
 * are pkts being passed up from physical device for this vsw interface.
 */
/* ARGSUSED */
static void
vsw_if_rx_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	_NOTE(ARGUNUSED(mrh))

	vsw_t		*vswp = (vsw_t *)arg;
	mblk_t		*mpt;
	int		count;

	ASSERT(vswp != NULL);

	D1(vswp, "%s: enter", __func__);

	READ_ENTER(&vswp->if_lockrw);
	if (vswp->if_state & VSW_IF_UP) {
		RW_EXIT(&vswp->if_lockrw);
		count = vsw_vlan_frame_untag(vswp, VSW_LOCALDEV, &mp, &mpt);
		if (count != 0) {
			mac_rx(vswp->if_mh, NULL, mp);
		}
	} else {
		RW_EXIT(&vswp->if_lockrw);
		freemsgchain(mp);
	}

	D1(vswp, "%s: exit", __func__);
}

/*
 * receive callback routine for port. Invoked by MAC layer when there
 * are pkts being passed up from physical device for this port.
 */
/* ARGSUSED */
static void
vsw_port_rx_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	_NOTE(ARGUNUSED(mrh))

	vsw_t		*vswp;
	vsw_port_t	*port = arg;

	ASSERT(port != NULL);

	vswp = port->p_vswp;

	D1(vswp, "vsw_port_rx_cb: enter");

	/*
	 * Send the packets to the peer directly.
	 */
	(void) vsw_portsend(port, mp);

	D1(vswp, "vsw_port_rx_cb: exit");
}

/*
 * Send a message out over the physical device
 * via the MAC layer.
 *
 * Returns any mblks that it was unable to transmit.
 */
mblk_t *
vsw_tx_msg(vsw_t *vswp, mblk_t *mp, int caller, vsw_port_t *port)
{
	mac_client_handle_t	mch;
	mac_unicast_handle_t	muh;

	READ_MACCL_ENTER(vswp, port, caller);

	mch = (caller == VSW_LOCALDEV) ? vswp->mch : port->p_mch;
	muh = (caller == VSW_LOCALDEV) ? vswp->muh : port->p_muh;

	if ((mch != NULL) && (muh != NULL)) {
		/* packets are sent or dropped */
		(void) mac_tx(mch, mp, 0, MAC_DROP_ON_NO_DESC, NULL);
	}

	RW_MACCL_EXIT(vswp, port, caller);
	return (NULL);
}

/*
 * vsw_port_mac_reconfig -- Cleanup and close the MAC client
 * and reopen and re-configure the MAC client with new flags etc.
 * This function is useful for two different purposes:
 *	1) To update the MAC client with new vlan-ids. This is done
 *	   by freeing the existing vlan-ids and reopen with the new
 *	   vlan-ids.
 *
 *	2) If the Hybrid mode status of a port changes, then the
 *	   MAC client need to be closed and re-opened, otherwise,
 *	   Share related resources may not be freed(hybird mode disabled)
 *	   or assigned(hybrid mode enabled). To accomplish this,
 *	   this function simply closes and reopens the MAC client.
 *	   The reopen will result in using the flags based on the
 *	   new hybrid mode of the port.
 */
void
vsw_port_mac_reconfig(vsw_port_t *portp, boolean_t update_vlans,
    uint16_t new_pvid, vsw_vlanid_t *new_vids, int new_nvids)
{
	vsw_t *vswp = portp->p_vswp;
	int rv;

	D1(vswp, "%s: enter", __func__);
	/*
	 * Remove the multi-cast addresses, unicast address
	 * and close the mac-client.
	 */
	mutex_enter(&vswp->mac_lock);
	WRITE_ENTER(&portp->maccl_rwlock);
	vsw_mac_multicast_remove_all(vswp, portp, VSW_VNETPORT);
	vsw_unset_hw(vswp, portp, VSW_VNETPORT);
	vsw_maccl_close(vswp, portp, VSW_VNETPORT);

	if (update_vlans == B_TRUE) {
		if (portp->nvids != 0) {
			kmem_free(portp->vids,
			    sizeof (vsw_vlanid_t) * portp->nvids);
			portp->vids = NULL;
			portp->nvids = 0;
		}
		portp->vids = new_vids;
		portp->nvids = new_nvids;
		portp->pvid = new_pvid;
	}

	/*
	 * Now re-open the mac-client and
	 * configure unicast addr and multicast addrs.
	 */
	rv = vsw_maccl_open(vswp, portp, VSW_VNETPORT);
	if (rv != 0) {
		goto recret;
	}

	if (vsw_set_hw(vswp, portp, VSW_VNETPORT)) {
		cmn_err(CE_NOTE, "!vsw%d: port:%d failed to "
		    "set unicast address\n", vswp->instance, portp->p_instance);
		goto recret;
	}

	vsw_mac_multicast_add_all(vswp, portp, VSW_VNETPORT);

recret:
	RW_EXIT(&portp->maccl_rwlock);
	mutex_exit(&vswp->mac_lock);
	D1(vswp, "%s: exit", __func__);
}

/*
 * vsw_if_mac_reconfig -- Reconfigure the vsw interfaace's mac-client
 * by closing and re-opening it. This function is used handle the
 * following two cases:
 *
 *	1) Handle the MAC address change for the interface.
 *	2) Handle vlan update.
 */
void
vsw_if_mac_reconfig(vsw_t *vswp, boolean_t update_vlans,
    uint16_t new_pvid, vsw_vlanid_t *new_vids, int new_nvids)
{
	int rv;

	D1(vswp, "%s: enter", __func__);
	/*
	 * Remove the multi-cast addresses, unicast address
	 * and close the mac-client.
	 */
	mutex_enter(&vswp->mac_lock);
	WRITE_ENTER(&vswp->maccl_rwlock);
	vsw_mac_multicast_remove_all(vswp, NULL, VSW_LOCALDEV);
	vsw_unset_hw(vswp, NULL, VSW_LOCALDEV);
	vsw_maccl_close(vswp, NULL, VSW_LOCALDEV);

	if (update_vlans == B_TRUE) {
		if (vswp->nvids != 0) {
			kmem_free(vswp->vids,
			    sizeof (vsw_vlanid_t) * vswp->nvids);
			vswp->vids = NULL;
			vswp->nvids = 0;
		}
		vswp->vids = new_vids;
		vswp->nvids = new_nvids;
		vswp->pvid = new_pvid;
	}

	/*
	 * Now re-open the mac-client and
	 * configure unicast addr and multicast addrs.
	 */
	rv = vsw_maccl_open(vswp, NULL, VSW_LOCALDEV);
	if (rv != 0) {
		goto ifrecret;
	}

	if (vsw_set_hw(vswp, NULL, VSW_LOCALDEV)) {
		cmn_err(CE_NOTE, "!vsw%d:failed to set unicast address\n",
		    vswp->instance);
		goto ifrecret;
	}

	vsw_mac_multicast_add_all(vswp, NULL, VSW_LOCALDEV);

ifrecret:
	RW_EXIT(&vswp->maccl_rwlock);
	mutex_exit(&vswp->mac_lock);
	D1(vswp, "%s: exit", __func__);
}

/*
 * vsw_mac_port_reconfig_vlans -- Reconfigure a port to handle
 * vlan configuration update. As the removal of the last unicast-address,vid
 * from the MAC client results in releasing all resources, it expects
 * no Shares to be associated with such MAC client.
 *
 * To handle vlan configuration update for a port that already has
 * a Share bound, then we need to free that share prior to reconfiguration.
 * Initiate the hybrdIO setup again after the completion of reconfiguration.
 */
void
vsw_mac_port_reconfig_vlans(vsw_port_t *portp, uint16_t new_pvid,
    vsw_vlanid_t *new_vids, int new_nvids)
{
	/*
	 * As the reconfiguration involves the close of
	 * mac client, cleanup HybridIO and later restart
	 * HybridIO setup again.
	 */
	if (portp->p_hio_enabled == B_TRUE) {
		vsw_hio_stop_port(portp);
	}
	vsw_port_mac_reconfig(portp, B_TRUE, new_pvid, new_vids, new_nvids);
	if (portp->p_hio_enabled == B_TRUE) {
		/* reset to setup the HybridIO again. */
		vsw_hio_port_reset(portp, B_FALSE);
	}
}

/* Add vlans to MAC client */
static void
vsw_mac_add_vlans(vsw_t *vswp, mac_client_handle_t mch, uint8_t *macaddr,
    uint16_t flags, vsw_vlanid_t *vids, int nvids)
{
	vsw_vlanid_t	*vidp;
	mac_diag_t	diag;
	int		rv;
	int		i;

	/* Add vlans to the MAC layer */
	for (i = 0; i < nvids; i++) {
		vidp = &vids[i];

		if (vidp->vl_set == B_TRUE) {
			continue;
		}

		rv = mac_unicast_add(mch, macaddr, flags,
		    &vidp->vl_muh, vidp->vl_vid, &diag);
		if (rv != 0) {
			cmn_err(CE_WARN, "vsw%d: Failed to program"
			    "macaddr,vid(%s, %d) err=%d",
			    vswp->instance, ether_sprintf((void *)macaddr),
			    vidp->vl_vid, rv);
		} else {
			vidp->vl_set = B_TRUE;
			D2(vswp, "%s:programmed macaddr(%s) vid(%d) "
			    "into device %s", __func__,
			    ether_sprintf((void *)macaddr),
			    vidp->vl_vid, vswp->physname);
		}
	}
}

/* Remove vlans from the MAC client */
static void
vsw_mac_remove_vlans(mac_client_handle_t mch, vsw_vlanid_t *vids, int nvids)
{
	int i;
	vsw_vlanid_t *vidp;

	for (i = 0; i < nvids; i++) {
		vidp = &vids[i];
		if (vidp->vl_set == B_FALSE) {
			continue;
		}
		mac_unicast_remove(mch, vidp->vl_muh);
		vidp->vl_set = B_FALSE;
	}
}

#define	ARH_FIXED_LEN	8    /* Length of fixed part of ARP header(see arp.h) */

/*
 * Send a gratuitous RARP packet to notify the physical switch to update its
 * Layer2 forwarding table for the given mac address. This is done to allow the
 * switch to quickly learn the macaddr-port association when a guest is live
 * migrated or when vsw's physical device is changed dynamically. Any protocol
 * packet would serve this purpose, but we choose RARP, as it allows us to
 * accomplish this within L2 (ie, no need to specify IP addr etc in the packet)
 * The macaddr of vnet is retained across migration. Hence, we don't need to
 * update the arp cache of other hosts within the broadcast domain. Note that
 * it is harmless to send these RARP packets during normal port attach of a
 * client vnet. This can can be turned off if needed, by setting
 * vsw_publish_macaddr_count to zero in /etc/system.
 */
void
vsw_publish_macaddr(vsw_t *vswp, vsw_port_t *portp)
{
	mblk_t			*mp;
	mblk_t			*bp;
	struct arphdr		*arh;
	struct	ether_header 	*ehp;
	int			count = 0;
	int			plen = 4;
	uint8_t			*cp;

	mp = allocb(ETHERMIN, BPRI_MED);
	if (mp == NULL) {
		return;
	}

	/* Initialize eth header */
	ehp = (struct  ether_header *)mp->b_rptr;
	bcopy(&etherbroadcastaddr, &ehp->ether_dhost, ETHERADDRL);
	bcopy(&portp->p_macaddr, &ehp->ether_shost, ETHERADDRL);
	ehp->ether_type = htons(ETHERTYPE_REVARP);

	/* Initialize arp packet */
	arh = (struct arphdr *)(mp->b_rptr + sizeof (struct ether_header));
	cp = (uint8_t *)arh;

	arh->ar_hrd = htons(ARPHRD_ETHER);	/* Hardware type:  ethernet */
	arh->ar_pro = htons(ETHERTYPE_IP);	/* Protocol type:  IP */
	arh->ar_hln = ETHERADDRL;	/* Length of hardware address:  6 */
	arh->ar_pln = plen;		/* Length of protocol address:  4 */
	arh->ar_op = htons(REVARP_REQUEST);	/* Opcode: REVARP Request */

	cp += ARH_FIXED_LEN;

	/* Sender's hardware address and protocol address */
	bcopy(&portp->p_macaddr, cp, ETHERADDRL);
	cp += ETHERADDRL;
	bzero(cp, plen);	/* INADDR_ANY */
	cp += plen;

	/* Target hardware address and protocol address */
	bcopy(&portp->p_macaddr, cp, ETHERADDRL);
	cp += ETHERADDRL;
	bzero(cp, plen);	/* INADDR_ANY */
	cp += plen;

	mp->b_wptr += ETHERMIN;	/* total size is 42; round up to ETHERMIN */

	for (count = 0; count < vsw_publish_macaddr_count; count++) {

		bp = dupmsg(mp);
		if (bp == NULL) {
			continue;
		}

		/* transmit the packet */
		bp = vsw_tx_msg(vswp, bp, VSW_VNETPORT, portp);
		if (bp != NULL) {
			freemsg(bp);
		}
	}

	freemsg(mp);
}

static void
vsw_mac_set_mtu(vsw_t *vswp, uint32_t mtu)
{
	uint_t	mtu_orig;
	int	rv;

	rv = mac_set_mtu(vswp->mh, mtu, &mtu_orig);
	if (rv != 0) {
		cmn_err(CE_NOTE,
		    "!vsw%d: Unable to set the mtu:%d, in the "
		    "physical device:%s\n",
		    vswp->instance, mtu, vswp->physname);
		return;
	}

	/* save the original mtu of physdev to reset it back later if needed */
	vswp->mtu_physdev_orig = mtu_orig;
}
