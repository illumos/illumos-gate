/*
 * Copyright (c) 2013  Chris Torek <torek @ torek net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2019 Joyent, Inc.
 */

/*
 * viona - VirtIO-Net, Accelerated
 *
 * The purpose of viona is to provide high performance virtio-net devices to
 * bhyve guests.  It does so by sitting directly atop MAC, skipping all of the
 * DLS/DLD stack.
 *
 * --------------------
 * General Architecture
 * --------------------
 *
 * A single viona instance is comprised of a "link" handle and two "rings".
 * After opening the viona device, it must be associated with a MAC network
 * interface and a bhyve (vmm) instance to form its link resource.  This is
 * done with the VNA_IOC_CREATE ioctl, where the datalink ID and vmm fd are
 * passed in to perform the initialization.  With the MAC client opened, and a
 * driver handle to the vmm instance established, the device is ready to be
 * configured by the guest.
 *
 * The userspace portion of bhyve, which interfaces with the PCI device
 * emulation framework, is meant to stay out of the datapath if at all
 * possible.  Configuration changes made via PCI are mapped to actions which
 * will steer the operation of the in-kernel logic.
 *
 *
 * -----------
 * Ring Basics
 * -----------
 *
 * Each viona link has two viona_vring_t entities, RX and TX, for handling data
 * transfers to and from the guest.  They represent an interface to the
 * standard virtio ring structures.  When intiailized and active, each ring is
 * backed by a kernel worker thread (parented to the bhyve process for the
 * instance) which handles ring events.  The RX worker has the simple task of
 * watching for ring shutdown conditions.  The TX worker does that in addition
 * to processing all requests to transmit data.  Data destined for the guest is
 * delivered directly by MAC to viona_rx() when the ring is active.
 *
 *
 * -----------
 * Ring States
 * -----------
 *
 * The viona_vring_t instances follow a simple path through the possible state
 * values represented in virtio_vring_t`vr_state:
 *
 *        +<--------------------------------------------+
 *        |						|
 *        V						^
 *  +-----------+	This is the initial state when a link is created or
 *  | VRS_RESET |	when the ring has been explicitly reset.
 *  +-----------+
 *        |						^
 *        |---* ioctl(VNA_IOC_RING_INIT) issued		|
 *        |						|
 *        |						^
 *        V
 *  +-----------+	The ring parameters (size, guest physical addresses)
 *  | VRS_SETUP |	have been set and start-up of the ring worker thread
 *  +-----------+	has begun.
 *        |						^
 *        |						|
 *        |---* ring worker thread begins execution	|
 *        |						|
 *        +-------------------------------------------->+
 *        |	      |					^
 *        |	      |
 *        |	      *	If ring shutdown is requested (by ioctl or impending
 *        |		bhyve process death) while the worker thread is
 *        |		starting, the worker will transition the ring to
 *        |		VRS_RESET and exit.
 *        |						^
 *        |						|
 *        |						^
 *        V
 *  +-----------+	The worker thread associated with the ring has started
 *  | VRS_INIT  |	executing.  It has allocated any extra resources needed
 *  +-----------+	for the ring to operate.
 *        |						^
 *        |						|
 *        +-------------------------------------------->+
 *        |	      |					^
 *        |	      |
 *        |	      *	If ring shutdown is requested while the worker is
 *        |		waiting in VRS_INIT, it will free any extra resources
 *        |		and transition to VRS_RESET.
 *        |						^
 *        |						|
 *        |--* ioctl(VNA_IOC_RING_KICK) issued		|
 *        |						^
 *        V
 *  +-----------+	The worker thread associated with the ring is executing
 *  | VRS_RUN   |	workload specific to that ring.
 *  +-----------+
 *        |						^
 *        |---* ioctl(VNA_IOC_RING_RESET) issued	|
 *        |	(or bhyve process begins exit)		|
 *        V						|
 *        +-------------------------------------------->+
 *
 *
 * While the worker thread is not running, changes to vr_state are only made by
 * viona_ioc_ring_init() under vr_lock.  There, it initializes the ring, starts
 * the worker, and sets the ring state to VRS_SETUP.  Once the worker thread
 * has been started, only it may perform ring state transitions (still under
 * the protection of vr_lock), when requested by outside consumers via
 * vr_state_flags or when the containing bhyve process initiates an exit.
 *
 *
 * ----------------------------
 * Transmission mblk_t Handling
 * ----------------------------
 *
 * For incoming frames destined for a bhyve guest, the data must first land in
 * a host OS buffer from the physical NIC before it is copied into the awaiting
 * guest buffer(s).  Outbound frames transmitted by the guest are not bound by
 * this limitation and can avoid extra copying before the buffers are accessed
 * directly by the NIC.  When a guest designates buffers to be transmitted,
 * viona translates the guest-physical addresses contained in the ring
 * descriptors to host-virtual addresses via vmm_dr_gpa2kva().  That pointer is
 * wrapped in an mblk_t using a preallocated viona_desb_t for the desballoc().
 * Doing so increments vr_xfer_outstanding, preventing the ring from being
 * reset (allowing the link to drop its vmm handle to the guest) until all
 * transmit mblks referencing guest memory have been processed.  Allocation of
 * the viona_desb_t entries is done during the VRS_INIT stage of the ring
 * worker thread.  The ring size informs that allocation as the number of
 * concurrent transmissions is limited by the number of descriptors in the
 * ring.  This minimizes allocation in the transmit hot-path by aqcuiring those
 * fixed-size resources during initialization.
 *
 * This optimization depends on the underlying NIC driver freeing the mblks in
 * a timely manner after they have been transmitted by the hardware.  Some
 * drivers have been found to flush TX descriptors only when new transmissions
 * are initiated.  This means that there is no upper bound to the time needed
 * for an mblk to be flushed and can stall bhyve guests from shutting down
 * since their memory must be free of viona TX references prior to clean-up.
 *
 * This expectation of deterministic mblk_t processing is likely the reason
 * behind the notable exception to the zero-copy TX path: systems with 'bnxe'
 * loaded will copy transmit data into fresh buffers rather than passing up
 * zero-copy mblks.  It is a hold-over from the original viona sources provided
 * by Pluribus and its continued necessity has not been confirmed.
 *
 *
 * ----------------------------
 * Ring Notification Fast-paths
 * ----------------------------
 *
 * Device operation for viona requires that notifications flow to and from the
 * guest to indicate certain ring conditions.  In order to minimize latency and
 * processing overhead, the notification procedures are kept in-kernel whenever
 * possible.
 *
 * Guest-to-host notifications, when new available descriptors have been placed
 * in the ring, are posted via the 'queue notify' address in the virtio BAR.
 * The vmm_drv_ioport_hook() interface was added to bhyve which allows viona to
 * install a callback hook on an ioport address.  Guest exits for accesses to
 * viona-hooked ioport addresses will result in direct calls to notify the
 * appropriate ring worker without a trip to userland.
 *
 * Host-to-guest notifications in the form of interrupts enjoy similar
 * acceleration.  Each viona ring can be configured to send MSI notifications
 * to the guest as virtio conditions dictate.  This in-kernel interrupt
 * configuration is kept synchronized through viona ioctls which are utilized
 * during writes to the associated PCI config registers or MSI-X BAR.
 *
 * Guests which do not utilize MSI-X will result in viona falling back to the
 * slow path for interrupts.  It will poll(2) the viona handle, receiving
 * notification when ring events necessitate the assertion of an interrupt.
 *
 *
 * ---------------
 * Nethook Support
 * ---------------
 *
 * Viona provides four nethook events that consumers (e.g. ipf) can hook into
 * to intercept packets as they go up or down the stack.  Unfortunately,
 * the nethook framework does not understand raw packets, so we can only
 * generate events (in, out) for IPv4 and IPv6 packets.  At driver attach,
 * we register callbacks with the neti (netinfo) module that will be invoked
 * for each netstack already present, as well as for any additional netstack
 * instances created as the system operates.  These callbacks will
 * register/unregister the hooks with the nethook framework for each
 * netstack instance.  This registration occurs prior to creating any
 * viona instances for a given netstack, and the unregistration for a netstack
 * instance occurs after all viona instances of the netstack instance have
 * been deleted.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <sys/dlpi.h>

#include "viona_impl.h"


#define	VIONA_NAME		"Virtio Network Accelerator"
#define	VIONA_CTL_MINOR		0
#define	VIONA_CLI_NAME		"viona"		/* MAC client name */


/*
 * Host capabilities.
 */
#define	VIONA_S_HOSTCAPS	(	\
	VIRTIO_NET_F_GUEST_CSUM |	\
	VIRTIO_NET_F_MAC |		\
	VIRTIO_NET_F_GUEST_TSO4 |	\
	VIRTIO_NET_F_MRG_RXBUF |	\
	VIRTIO_NET_F_STATUS |		\
	VIRTIO_F_RING_NOTIFY_ON_EMPTY |	\
	VIRTIO_F_RING_INDIRECT_DESC)

/* MAC_CAPAB_HCKSUM specifics of interest */
#define	VIONA_CAP_HCKSUM_INTEREST	\
	(HCKSUM_INET_PARTIAL |		\
	HCKSUM_INET_FULL_V4 |		\
	HCKSUM_INET_FULL_V6)

static void		*viona_state;
static dev_info_t	*viona_dip;
static id_space_t	*viona_minors;


static int viona_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result);
static int viona_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int viona_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int viona_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int viona_close(dev_t dev, int flag, int otype, cred_t *credp);
static int viona_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);
static int viona_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp);

static int viona_ioc_create(viona_soft_state_t *, void *, int, cred_t *);
static int viona_ioc_delete(viona_soft_state_t *, boolean_t);

static int viona_ioc_set_notify_ioport(viona_link_t *, uint_t);
static int viona_ioc_ring_init(viona_link_t *, void *, int);
static int viona_ioc_ring_reset(viona_link_t *, uint_t);
static int viona_ioc_ring_kick(viona_link_t *, uint_t);
static int viona_ioc_ring_set_msi(viona_link_t *, void *, int);
static int viona_ioc_ring_intr_clear(viona_link_t *, uint_t);
static int viona_ioc_intr_poll(viona_link_t *, void *, int, int *);

static struct cb_ops viona_cb_ops = {
	viona_open,
	viona_close,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	viona_ioctl,
	nodev,
	nodev,
	nodev,
	viona_chpoll,
	ddi_prop_op,
	0,
	D_MP | D_NEW | D_HOTPLUG,
	CB_REV,
	nodev,
	nodev
};

static struct dev_ops viona_ops = {
	DEVO_REV,
	0,
	viona_info,
	nulldev,
	nulldev,
	viona_attach,
	viona_detach,
	nodev,
	&viona_cb_ops,
	NULL,
	ddi_power,
	ddi_quiesce_not_needed
};

static struct modldrv modldrv = {
	&mod_driverops,
	VIONA_NAME,
	&viona_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&viona_state, sizeof (viona_soft_state_t), 0);
	if (ret != 0) {
		return (ret);
	}

	viona_minors = id_space_create("viona_minors",
	    VIONA_CTL_MINOR + 1, UINT16_MAX);
	viona_rx_init();
	mutex_init(&viona_force_copy_lock, NULL, MUTEX_DRIVER, NULL);

	ret = mod_install(&modlinkage);
	if (ret != 0) {
		ddi_soft_state_fini(&viona_state);
		id_space_destroy(viona_minors);
		viona_rx_fini();
		mutex_destroy(&viona_force_copy_lock);
	}

	return (ret);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret != 0) {
		return (ret);
	}

	ddi_soft_state_fini(&viona_state);
	id_space_destroy(viona_minors);
	viona_rx_fini();
	mutex_destroy(&viona_force_copy_lock);

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
viona_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)viona_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}

static int
viona_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, "viona", S_IFCHR, VIONA_CTL_MINOR,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	viona_neti_attach();

	viona_dip = dip;
	ddi_report_dev(viona_dip);

	return (DDI_SUCCESS);
}

static int
viona_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	dev_info_t *old_dip = viona_dip;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	VERIFY(old_dip != NULL);

	viona_neti_detach();
	viona_dip = NULL;
	ddi_remove_minor_node(old_dip, NULL);

	return (DDI_SUCCESS);
}

static int
viona_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	int	minor;
	viona_soft_state_t *ss;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}
#if 0
	/*
	 * XXX-mg: drv_priv() is wrong, but I'm not sure what is right.
	 * Should the check be at open() or ioctl()?
	 */
	if (drv_priv(credp) != 0) {
		return (EPERM);
	}
#endif
	if (getminor(*devp) != VIONA_CTL_MINOR) {
		return (ENXIO);
	}

	minor = id_alloc_nosleep(viona_minors);
	if (minor == 0) {
		/* All minors are busy */
		return (EBUSY);
	}
	if (ddi_soft_state_zalloc(viona_state, minor) != DDI_SUCCESS) {
		id_free(viona_minors, minor);
		return (ENOMEM);
	}

	ss = ddi_get_soft_state(viona_state, minor);
	mutex_init(&ss->ss_lock, NULL, MUTEX_DEFAULT, NULL);
	*devp = makedevice(getmajor(*devp), minor);

	return (0);
}

static int
viona_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	int			minor;
	viona_soft_state_t	*ss;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	minor = getminor(dev);

	ss = ddi_get_soft_state(viona_state, minor);
	if (ss == NULL) {
		return (ENXIO);
	}

	VERIFY0(viona_ioc_delete(ss, B_TRUE));
	VERIFY(!list_link_active(&ss->ss_node));
	ddi_soft_state_free(viona_state, minor);
	id_free(viona_minors, minor);

	return (0);
}

static int
viona_ioctl(dev_t dev, int cmd, intptr_t data, int md, cred_t *cr, int *rv)
{
	viona_soft_state_t *ss;
	void *dptr = (void *)data;
	int err = 0, val;
	viona_link_t *link;

	ss = ddi_get_soft_state(viona_state, getminor(dev));
	if (ss == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	case VNA_IOC_CREATE:
		return (viona_ioc_create(ss, dptr, md, cr));
	case VNA_IOC_DELETE:
		return (viona_ioc_delete(ss, B_FALSE));
	default:
		break;
	}

	mutex_enter(&ss->ss_lock);
	if ((link = ss->ss_link) == NULL || link->l_destroyed ||
	    vmm_drv_release_reqd(link->l_vm_hold)) {
		mutex_exit(&ss->ss_lock);
		return (ENXIO);
	}

	switch (cmd) {
	case VNA_IOC_GET_FEATURES:
		val = VIONA_S_HOSTCAPS | link->l_features_hw;
		if (ddi_copyout(&val, dptr, sizeof (val), md) != 0) {
			err = EFAULT;
		}
		break;
	case VNA_IOC_SET_FEATURES:
		if (ddi_copyin(dptr, &val, sizeof (val), md) != 0) {
			err = EFAULT;
			break;
		}
		val &= (VIONA_S_HOSTCAPS | link->l_features_hw);

		if ((val & VIRTIO_NET_F_CSUM) == 0)
			val &= ~VIRTIO_NET_F_HOST_TSO4;

		if ((val & VIRTIO_NET_F_GUEST_CSUM) == 0)
			val &= ~VIRTIO_NET_F_GUEST_TSO4;

		link->l_features = val;
		break;
	case VNA_IOC_RING_INIT:
		err = viona_ioc_ring_init(link, dptr, md);
		break;
	case VNA_IOC_RING_RESET:
		err = viona_ioc_ring_reset(link, (uint_t)data);
		break;
	case VNA_IOC_RING_KICK:
		err = viona_ioc_ring_kick(link, (uint_t)data);
		break;
	case VNA_IOC_RING_SET_MSI:
		err = viona_ioc_ring_set_msi(link, dptr, md);
		break;
	case VNA_IOC_RING_INTR_CLR:
		err = viona_ioc_ring_intr_clear(link, (uint_t)data);
		break;
	case VNA_IOC_INTR_POLL:
		err = viona_ioc_intr_poll(link, dptr, md, rv);
		break;
	case VNA_IOC_SET_NOTIFY_IOP:
		err = viona_ioc_set_notify_ioport(link, (uint_t)data);
		break;
	default:
		err = ENOTTY;
		break;
	}

	mutex_exit(&ss->ss_lock);
	return (err);
}

static int
viona_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	viona_soft_state_t *ss;
	viona_link_t *link;

	ss = ddi_get_soft_state(viona_state, getminor(dev));
	if (ss == NULL) {
		return (ENXIO);
	}

	mutex_enter(&ss->ss_lock);
	if ((link = ss->ss_link) == NULL || link->l_destroyed) {
		mutex_exit(&ss->ss_lock);
		return (ENXIO);
	}

	*reventsp = 0;
	if ((events & POLLRDBAND) != 0) {
		for (uint_t i = 0; i < VIONA_VQ_MAX; i++) {
			if (link->l_vrings[i].vr_intr_enabled != 0) {
				*reventsp |= POLLRDBAND;
				break;
			}
		}
	}
	if ((*reventsp == 0 && !anyyet) || (events & POLLET)) {
		*phpp = &link->l_pollhead;
	}
	mutex_exit(&ss->ss_lock);

	return (0);
}

static void
viona_get_mac_capab(viona_link_t *link)
{
	mac_handle_t mh = link->l_mh;
	uint32_t cap = 0;
	mac_capab_lso_t lso_cap;

	link->l_features_hw = 0;
	if (mac_capab_get(mh, MAC_CAPAB_HCKSUM, &cap)) {
		/*
		 * Only report HW checksum ability if the underlying MAC
		 * resource is capable of populating the L4 header.
		 */
		if ((cap & VIONA_CAP_HCKSUM_INTEREST) != 0) {
			link->l_features_hw |= VIRTIO_NET_F_CSUM;
		}
		link->l_cap_csum = cap;
	}

	if ((link->l_features_hw & VIRTIO_NET_F_CSUM) &&
	    mac_capab_get(mh, MAC_CAPAB_LSO, &lso_cap)) {
		/*
		 * Virtio doesn't allow for negotiating a maximum LSO
		 * packet size. We have to assume that the guest may
		 * send a maximum length IP packet. Make sure the
		 * underlying MAC can handle an LSO of this size.
		 */
		if ((lso_cap.lso_flags & LSO_TX_BASIC_TCP_IPV4) &&
		    lso_cap.lso_basic_tcp_ipv4.lso_max >= IP_MAXPACKET)
			link->l_features_hw |= VIRTIO_NET_F_HOST_TSO4;
	}
}

static int
viona_ioc_create(viona_soft_state_t *ss, void *dptr, int md, cred_t *cr)
{
	vioc_create_t	kvc;
	viona_link_t	*link = NULL;
	char		cli_name[MAXNAMELEN];
	int		err = 0;
	file_t		*fp;
	vmm_hold_t	*hold = NULL;
	viona_neti_t	*nip = NULL;
	zoneid_t	zid;

	ASSERT(MUTEX_NOT_HELD(&ss->ss_lock));

	if (ddi_copyin(dptr, &kvc, sizeof (kvc), md) != 0) {
		return (EFAULT);
	}

	zid = crgetzoneid(cr);
	nip = viona_neti_lookup_by_zid(zid);
	if (nip == NULL) {
		return (EIO);
	}

	if (!nip->vni_nethook.vnh_hooked) {
		viona_neti_rele(nip);
		return (EIO);
	}

	mutex_enter(&ss->ss_lock);
	if (ss->ss_link != NULL) {
		mutex_exit(&ss->ss_lock);
		viona_neti_rele(nip);
		return (EEXIST);
	}

	if ((fp = getf(kvc.c_vmfd)) == NULL) {
		err = EBADF;
		goto bail;
	}
	err = vmm_drv_hold(fp, cr, &hold);
	releasef(kvc.c_vmfd);
	if (err != 0) {
		goto bail;
	}

	link = kmem_zalloc(sizeof (viona_link_t), KM_SLEEP);
	link->l_linkid = kvc.c_linkid;
	link->l_vm_hold = hold;

	err = mac_open_by_linkid(link->l_linkid, &link->l_mh);
	if (err != 0) {
		goto bail;
	}

	viona_get_mac_capab(link);

	(void) snprintf(cli_name, sizeof (cli_name), "%s-%d", VIONA_CLI_NAME,
	    link->l_linkid);
	err = mac_client_open(link->l_mh, &link->l_mch, cli_name, 0);
	if (err != 0) {
		goto bail;
	}

	viona_ring_alloc(link, &link->l_vrings[VIONA_VQ_RX]);
	viona_ring_alloc(link, &link->l_vrings[VIONA_VQ_TX]);

	if ((err = viona_rx_set(link)) != 0) {
		viona_ring_free(&link->l_vrings[VIONA_VQ_RX]);
		viona_ring_free(&link->l_vrings[VIONA_VQ_TX]);
		goto bail;
	}

	link->l_neti = nip;
	ss->ss_link = link;
	mutex_exit(&ss->ss_lock);

	mutex_enter(&nip->vni_lock);
	list_insert_tail(&nip->vni_dev_list, ss);
	mutex_exit(&nip->vni_lock);

	return (0);

bail:
	if (link != NULL) {
		if (link->l_mch != NULL) {
			mac_client_close(link->l_mch, 0);
		}
		if (link->l_mh != NULL) {
			mac_close(link->l_mh);
		}
		kmem_free(link, sizeof (viona_link_t));
	}
	if (hold != NULL) {
		vmm_drv_rele(hold);
	}
	viona_neti_rele(nip);

	mutex_exit(&ss->ss_lock);
	return (err);
}

static int
viona_ioc_delete(viona_soft_state_t *ss, boolean_t on_close)
{
	viona_link_t *link;
	viona_neti_t *nip = NULL;

	mutex_enter(&ss->ss_lock);
	if ((link = ss->ss_link) == NULL) {
		/* Link destruction already complete */
		mutex_exit(&ss->ss_lock);
		return (0);
	}

	if (link->l_destroyed) {
		/*
		 * Link destruction has been started by another thread, but has
		 * not completed.  This condition should be impossible to
		 * encounter when performing the on-close destroy of the link,
		 * since racing ioctl accessors must necessarily be absent.
		 */
		VERIFY(!on_close);
		mutex_exit(&ss->ss_lock);
		return (EAGAIN);
	}
	/*
	 * The link deletion cannot fail after this point, continuing until its
	 * successful completion is reached.
	 */
	link->l_destroyed = B_TRUE;

	/*
	 * Tear down the IO port hook so it cannot be used to kick any of the
	 * rings which are about to be reset and stopped.
	 */
	VERIFY0(viona_ioc_set_notify_ioport(link, 0));
	mutex_exit(&ss->ss_lock);

	/*
	 * Return the rings to their reset state, ignoring any possible
	 * interruptions from signals.
	 */
	VERIFY0(viona_ring_reset(&link->l_vrings[VIONA_VQ_RX], B_FALSE));
	VERIFY0(viona_ring_reset(&link->l_vrings[VIONA_VQ_TX], B_FALSE));

	mutex_enter(&ss->ss_lock);
	if (link->l_mch != NULL) {
		/* Unhook the receive callbacks and close out the client */
		viona_rx_clear(link);
		mac_client_close(link->l_mch, 0);
	}
	if (link->l_mh != NULL) {
		mac_close(link->l_mh);
	}
	if (link->l_vm_hold != NULL) {
		vmm_drv_rele(link->l_vm_hold);
		link->l_vm_hold = NULL;
	}

	nip = link->l_neti;
	link->l_neti = NULL;

	viona_ring_free(&link->l_vrings[VIONA_VQ_RX]);
	viona_ring_free(&link->l_vrings[VIONA_VQ_TX]);
	pollhead_clean(&link->l_pollhead);
	ss->ss_link = NULL;
	mutex_exit(&ss->ss_lock);

	mutex_enter(&nip->vni_lock);
	list_remove(&nip->vni_dev_list, ss);
	mutex_exit(&nip->vni_lock);

	viona_neti_rele(nip);

	kmem_free(link, sizeof (viona_link_t));
	return (0);
}

static int
viona_ioc_ring_init(viona_link_t *link, void *udata, int md)
{
	vioc_ring_init_t kri;
	int err;

	if (ddi_copyin(udata, &kri, sizeof (kri), md) != 0) {
		return (EFAULT);
	}

	err = viona_ring_init(link, kri.ri_index, kri.ri_qsize, kri.ri_qaddr);

	return (err);
}

static int
viona_ioc_ring_reset(viona_link_t *link, uint_t idx)
{
	viona_vring_t *ring;

	if (idx >= VIONA_VQ_MAX) {
		return (EINVAL);
	}
	ring = &link->l_vrings[idx];

	return (viona_ring_reset(ring, B_TRUE));
}

static int
viona_ioc_ring_kick(viona_link_t *link, uint_t idx)
{
	viona_vring_t *ring;
	int err;

	if (idx >= VIONA_VQ_MAX) {
		return (EINVAL);
	}
	ring = &link->l_vrings[idx];

	mutex_enter(&ring->vr_lock);
	switch (ring->vr_state) {
	case VRS_SETUP:
		/*
		 * An early kick to a ring which is starting its worker thread
		 * is fine.  Once that thread is active, it will process the
		 * start-up request immediately.
		 */
		/* FALLTHROUGH */
	case VRS_INIT:
		ring->vr_state_flags |= VRSF_REQ_START;
		/* FALLTHROUGH */
	case VRS_RUN:
		cv_broadcast(&ring->vr_cv);
		err = 0;
		break;
	default:
		err = EBUSY;
		break;
	}
	mutex_exit(&ring->vr_lock);

	return (err);
}

static int
viona_ioc_ring_set_msi(viona_link_t *link, void *data, int md)
{
	vioc_ring_msi_t vrm;
	viona_vring_t *ring;

	if (ddi_copyin(data, &vrm, sizeof (vrm), md) != 0) {
		return (EFAULT);
	}
	if (vrm.rm_index >= VIONA_VQ_MAX) {
		return (EINVAL);
	}

	ring = &link->l_vrings[vrm.rm_index];
	mutex_enter(&ring->vr_lock);
	ring->vr_msi_addr = vrm.rm_addr;
	ring->vr_msi_msg = vrm.rm_msg;
	mutex_exit(&ring->vr_lock);

	return (0);
}

static int
viona_notify_wcb(void *arg, uintptr_t ioport, uint_t sz, uint64_t val)
{
	viona_link_t *link = (viona_link_t *)arg;
	uint16_t vq = (uint16_t)val;

	if (ioport != link->l_notify_ioport || sz != sizeof (uint16_t)) {
		return (EINVAL);
	}
	return (viona_ioc_ring_kick(link, vq));
}

static int
viona_ioc_set_notify_ioport(viona_link_t *link, uint_t ioport)
{
	int err = 0;

	if (link->l_notify_ioport != 0) {
		vmm_drv_ioport_unhook(link->l_vm_hold, &link->l_notify_cookie);
		link->l_notify_ioport = 0;
	}

	if (ioport != 0) {
		err = vmm_drv_ioport_hook(link->l_vm_hold, ioport, NULL,
		    viona_notify_wcb, (void *)link, &link->l_notify_cookie);
		if (err == 0) {
			link->l_notify_ioport = ioport;
		}
	}
	return (err);
}

static int
viona_ioc_ring_intr_clear(viona_link_t *link, uint_t idx)
{
	if (idx >= VIONA_VQ_MAX) {
		return (EINVAL);
	}

	link->l_vrings[idx].vr_intr_enabled = 0;
	return (0);
}

static int
viona_ioc_intr_poll(viona_link_t *link, void *udata, int md, int *rv)
{
	uint_t cnt = 0;
	vioc_intr_poll_t vip;

	for (uint_t i = 0; i < VIONA_VQ_MAX; i++) {
		uint_t val = link->l_vrings[i].vr_intr_enabled;

		vip.vip_status[i] = val;
		if (val != 0) {
			cnt++;
		}
	}

	if (ddi_copyout(&vip, udata, sizeof (vip), md) != 0) {
		return (EFAULT);
	}
	*rv = (int)cnt;
	return (0);
}
