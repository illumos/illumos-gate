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
 * Copyright 2018 Joyent, Inc.
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
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/disp.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <vm/seg_kmem.h>

#include <sys/pattr.h>
#include <sys/dls.h>
#include <sys/dlpi.h>
#include <sys/mac_client.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_priv.h>
#include <sys/vlan.h>
#include <inet/ip.h>

#include <sys/vmm_drv.h>
#include <sys/viona_io.h>

/* Min. octets in an ethernet frame minus FCS */
#define	MIN_BUF_SIZE		60
#define	NEED_VLAN_PAD_SIZE	(MIN_BUF_SIZE - VLAN_TAGSZ)

#define	VIONA_NAME		"Virtio Network Accelerator"
#define	VIONA_CTL_MINOR		0
#define	VIONA_CLI_NAME		"viona"		/* MAC client name */

#define	VTNET_MAXSEGS		32

#define	VRING_ALIGN		4096
#define	VRING_MAX_LEN		32768

#define	VRING_DESC_F_NEXT	(1 << 0)
#define	VRING_DESC_F_WRITE	(1 << 1)
#define	VRING_DESC_F_INDIRECT	(1 << 2)

#define	VIRTIO_NET_HDR_F_NEEDS_CSUM	(1 << 0)
#define	VIRTIO_NET_HDR_F_DATA_VALID	(1 << 1)


#define	VRING_AVAIL_F_NO_INTERRUPT	1

#define	VRING_USED_F_NO_NOTIFY		1

#define	BCM_NIC_DRIVER		"bnxe"
/*
 * Host capabilities
 */
#define	VIRTIO_NET_F_CSUM	(1 <<  0)
#define	VIRTIO_NET_F_GUEST_CSUM	(1 <<  1)
#define	VIRTIO_NET_F_MAC	(1 <<  5) /* host supplies MAC */
#define	VIRTIO_NET_F_MRG_RXBUF	(1 << 15) /* host can merge RX buffers */
#define	VIRTIO_NET_F_STATUS	(1 << 16) /* config status field available */
#define	VIRTIO_F_RING_NOTIFY_ON_EMPTY	(1 << 24)
#define	VIRTIO_F_RING_INDIRECT_DESC	(1 << 28)
#define	VIRTIO_F_RING_EVENT_IDX		(1 << 29)

#define	VIONA_S_HOSTCAPS	(	\
	VIRTIO_NET_F_GUEST_CSUM |	\
	VIRTIO_NET_F_MAC |		\
	VIRTIO_NET_F_MRG_RXBUF |	\
	VIRTIO_NET_F_STATUS |		\
	VIRTIO_F_RING_NOTIFY_ON_EMPTY |	\
	VIRTIO_F_RING_INDIRECT_DESC)

/* MAC_CAPAB_HCKSUM specifics of interest */
#define	VIONA_CAP_HCKSUM_INTEREST	\
	(HCKSUM_INET_PARTIAL |		\
	HCKSUM_INET_FULL_V4 |		\
	HCKSUM_INET_FULL_V6)


#define	VIONA_PROBE(name)	DTRACE_PROBE(viona__##name)
#define	VIONA_PROBE1(name, arg1, arg2)	\
	DTRACE_PROBE1(viona__##name, arg1, arg2)
#define	VIONA_PROBE2(name, arg1, arg2, arg3, arg4)	\
	DTRACE_PROBE2(viona__##name, arg1, arg2, arg3, arg4)
#define	VIONA_PROBE3(name, arg1, arg2, arg3, arg4, arg5, arg6)	\
	DTRACE_PROBE3(viona__##name, arg1, arg2, arg3, arg4, arg5, arg6)
#define	VIONA_PROBE5(name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, \
	arg9, arg10) \
	DTRACE_PROBE5(viona__##name, arg1, arg2, arg3, arg4, arg5, arg6, arg7, \
	arg8, arg9, arg10)
#define	VIONA_PROBE_BAD_RING_ADDR(r, a)		\
	VIONA_PROBE2(bad_ring_addr, viona_vring_t *, r, void *, (void *)(a))

#define	VIONA_RING_STAT_INCR(r, name)	\
	(((r)->vr_stats.rs_ ## name)++)

#pragma pack(1)
struct virtio_desc {
	uint64_t	vd_addr;
	uint32_t	vd_len;
	uint16_t	vd_flags;
	uint16_t	vd_next;
};
#pragma pack()

#pragma pack(1)
struct virtio_used {
	uint32_t	vu_idx;
	uint32_t	vu_tlen;
};
#pragma pack()

#pragma pack(1)
struct virtio_net_mrgrxhdr {
	uint8_t		vrh_flags;
	uint8_t		vrh_gso_type;
	uint16_t	vrh_hdr_len;
	uint16_t	vrh_gso_size;
	uint16_t	vrh_csum_start;
	uint16_t	vrh_csum_offset;
	uint16_t	vrh_bufs;
};
struct virtio_net_hdr {
	uint8_t		vrh_flags;
	uint8_t		vrh_gso_type;
	uint16_t	vrh_hdr_len;
	uint16_t	vrh_gso_size;
	uint16_t	vrh_csum_start;
	uint16_t	vrh_csum_offset;
};
#pragma pack()

struct viona_link;
typedef struct viona_link viona_link_t;
struct viona_desb;
typedef struct viona_desb viona_desb_t;

enum viona_ring_state {
	VRS_RESET	= 0x0,	/* just allocated or reset */
	VRS_SETUP	= 0x1,	/* addrs setup and starting worker thread */
	VRS_INIT	= 0x2,	/* worker thread started & waiting to run */
	VRS_RUN		= 0x3,	/* running work routine */
};
enum viona_ring_state_flags {
	VRSF_REQ_START	= 0x1,	/* start running from INIT state */
	VRSF_REQ_STOP	= 0x2,	/* stop running, clean up, goto RESET state */
};

#define	VRING_NEED_BAIL(ring, proc)					\
		(((ring)->vr_state_flags & VRSF_REQ_STOP) != 0 ||	\
		((proc)->p_flag & SEXITING) != 0)

typedef struct viona_vring {
	viona_link_t	*vr_link;

	kmutex_t	vr_lock;
	kcondvar_t	vr_cv;
	uint16_t	vr_state;
	uint16_t	vr_state_flags;
	uint_t		vr_xfer_outstanding;
	kthread_t	*vr_worker_thread;
	viona_desb_t	*vr_desb;

	uint_t		vr_intr_enabled;
	uint64_t	vr_msi_addr;
	uint64_t	vr_msi_msg;

	/* Internal ring-related state */
	kmutex_t	vr_a_mutex;	/* sync consumers of 'avail' */
	kmutex_t	vr_u_mutex;	/* sync consumers of 'used' */
	uint16_t	vr_size;
	uint16_t	vr_mask;	/* cached from vr_size */
	uint16_t	vr_cur_aidx;	/* trails behind 'avail_idx' */

	/* Host-context pointers to the queue */
	volatile struct virtio_desc	*vr_descr;

	volatile uint16_t		*vr_avail_flags;
	volatile uint16_t		*vr_avail_idx;
	volatile uint16_t		*vr_avail_ring;
	volatile uint16_t		*vr_avail_used_event;

	volatile uint16_t		*vr_used_flags;
	volatile uint16_t		*vr_used_idx;
	volatile struct virtio_used	*vr_used_ring;
	volatile uint16_t		*vr_used_avail_event;

	/* Per-ring error condition statistics */
	struct viona_ring_stats {
		uint64_t	rs_ndesc_too_high;
		uint64_t	rs_bad_idx;
		uint64_t	rs_indir_bad_len;
		uint64_t	rs_indir_bad_nest;
		uint64_t	rs_indir_bad_next;
		uint64_t	rs_no_space;
		uint64_t	rs_too_many_desc;

		uint64_t	rs_bad_ring_addr;

		uint64_t	rs_fail_hcksum;
		uint64_t	rs_fail_hcksum6;
		uint64_t	rs_fail_hcksum_proto;

		uint64_t	rs_bad_rx_frame;
		uint64_t	rs_rx_merge_overrun;
		uint64_t	rs_rx_merge_underrun;
		uint64_t	rs_rx_pad_short;
		uint64_t	rs_too_short;
		uint64_t	rs_tx_absent;
	} vr_stats;
} viona_vring_t;

struct viona_link {
	vmm_hold_t		*l_vm_hold;
	boolean_t		l_destroyed;

	viona_vring_t		l_vrings[VIONA_VQ_MAX];

	uint32_t		l_features;
	uint32_t		l_features_hw;
	uint32_t		l_cap_csum;

	uintptr_t		l_notify_ioport;
	void			*l_notify_cookie;

	datalink_id_t		l_linkid;
	mac_handle_t		l_mh;
	mac_client_handle_t	l_mch;

	pollhead_t		l_pollhead;
};

struct viona_desb {
	frtn_t			d_frtn;
	viona_vring_t		*d_ring;
	uint_t			d_ref;
	uint32_t		d_len;
	uint16_t		d_cookie;
};

typedef struct viona_soft_state {
	kmutex_t		ss_lock;
	viona_link_t		*ss_link;
} viona_soft_state_t;

typedef struct used_elem {
	uint16_t	id;
	uint32_t	len;
} used_elem_t;

static void			*viona_state;
static dev_info_t		*viona_dip;
static id_space_t		*viona_minors;
static mblk_t			*viona_vlan_pad_mp;

/*
 * copy tx mbufs from virtio ring to avoid necessitating a wait for packet
 * transmission to free resources.
 */
static boolean_t		viona_force_copy_tx_mblks = B_FALSE;

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

static void *viona_gpa2kva(viona_link_t *link, uint64_t gpa, size_t len);

static void viona_ring_alloc(viona_link_t *, viona_vring_t *);
static void viona_ring_free(viona_vring_t *);
static int viona_ring_reset(viona_vring_t *, boolean_t);
static kthread_t *viona_create_worker(viona_vring_t *);

static int viona_ioc_set_notify_ioport(viona_link_t *, uint_t);
static int viona_ioc_ring_init(viona_link_t *, void *, int);
static int viona_ioc_ring_reset(viona_link_t *, uint_t);
static int viona_ioc_ring_kick(viona_link_t *, uint_t);
static int viona_ioc_ring_set_msi(viona_link_t *, void *, int);
static int viona_ioc_ring_intr_clear(viona_link_t *, uint_t);
static int viona_ioc_intr_poll(viona_link_t *, void *, int, int *);

static void viona_intr_ring(viona_vring_t *);

static void viona_desb_release(viona_desb_t *);
static void viona_rx(void *, mac_resource_handle_t, mblk_t *, boolean_t);
static void viona_tx(viona_link_t *, viona_vring_t *);

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
	int	ret;

	ret = ddi_soft_state_init(&viona_state, sizeof (viona_soft_state_t), 0);
	if (ret != 0)
		return (ret);

	ret = mod_install(&modlinkage);
	if (ret != 0) {
		ddi_soft_state_fini(&viona_state);
		return (ret);
	}

	return (ret);
}

int
_fini(void)
{
	int	ret;

	ret = mod_remove(&modlinkage);
	if (ret == 0) {
		ddi_soft_state_fini(&viona_state);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
set_viona_tx_mode()
{
	major_t bcm_nic_major;

	if ((bcm_nic_major = ddi_name_to_major(BCM_NIC_DRIVER))
	    != DDI_MAJOR_T_NONE) {
		if (ddi_hold_installed_driver(bcm_nic_major) != NULL) {
			viona_force_copy_tx_mblks = B_TRUE;
			ddi_rele_driver(bcm_nic_major);
			return;
		}
	}
	viona_force_copy_tx_mblks = B_FALSE;
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
	mblk_t *mp;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, "viona", S_IFCHR, VIONA_CTL_MINOR,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	viona_minors = id_space_create("viona_minors",
	    VIONA_CTL_MINOR + 1, UINT16_MAX);

	/* Create mblk for padding when VLAN tags are stripped */
	mp = allocb_wait(VLAN_TAGSZ, BPRI_HI, STR_NOSIG, NULL);
	bzero(mp->b_rptr, VLAN_TAGSZ);
	mp->b_wptr += VLAN_TAGSZ;
	viona_vlan_pad_mp = mp;

	set_viona_tx_mode();
	viona_dip = dip;
	ddi_report_dev(viona_dip);

	return (DDI_SUCCESS);
}

static int
viona_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	mblk_t *mp;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	/* Clean up the VLAN padding mblk */
	mp = viona_vlan_pad_mp;
	viona_vlan_pad_mp = NULL;
	VERIFY(mp != NULL && mp->b_cont == NULL);
	freemsg(mp);

	id_space_destroy(viona_minors);
	ddi_remove_minor_node(viona_dip, NULL);
	viona_dip = NULL;

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
	    vmm_drv_expired(link->l_vm_hold)) {
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

	ASSERT(MUTEX_NOT_HELD(&ss->ss_lock));

	if (ddi_copyin(dptr, &kvc, sizeof (kvc), md) != 0) {
		return (EFAULT);
	}

	mutex_enter(&ss->ss_lock);
	if (ss->ss_link != NULL) {
		mutex_exit(&ss->ss_lock);
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
	ss->ss_link = link;

	mutex_exit(&ss->ss_lock);
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

	mutex_exit(&ss->ss_lock);
	return (err);
}

static int
viona_ioc_delete(viona_soft_state_t *ss, boolean_t on_close)
{
	viona_link_t *link;

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
	mutex_exit(&ss->ss_lock);

	/*
	 * Return the rings to their reset state, ignoring any possible
	 * interruptions from signals.
	 */
	VERIFY0(viona_ring_reset(&link->l_vrings[VIONA_VQ_RX], B_FALSE));
	VERIFY0(viona_ring_reset(&link->l_vrings[VIONA_VQ_TX], B_FALSE));

	mutex_enter(&ss->ss_lock);
	VERIFY0(viona_ioc_set_notify_ioport(link, 0));
	if (link->l_mch != NULL) {
		/*
		 * The RX ring will have cleared its receive function from the
		 * mac client handle, so all that is left to do is close it.
		 */
		mac_client_close(link->l_mch, 0);
	}
	if (link->l_mh != NULL) {
		mac_close(link->l_mh);
	}
	if (link->l_vm_hold != NULL) {
		vmm_drv_rele(link->l_vm_hold);
		link->l_vm_hold = NULL;
	}

	viona_ring_free(&link->l_vrings[VIONA_VQ_RX]);
	viona_ring_free(&link->l_vrings[VIONA_VQ_TX]);
	pollhead_clean(&link->l_pollhead);
	ss->ss_link = NULL;
	mutex_exit(&ss->ss_lock);

	kmem_free(link, sizeof (viona_link_t));
	return (0);
}

/*
 * Translate a guest physical address into a kernel virtual address.
 */
static void *
viona_gpa2kva(viona_link_t *link, uint64_t gpa, size_t len)
{
	return (vmm_drv_gpa2kva(link->l_vm_hold, gpa, len));
}

static void
viona_ring_alloc(viona_link_t *link, viona_vring_t *ring)
{
	ring->vr_link = link;
	mutex_init(&ring->vr_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ring->vr_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&ring->vr_a_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ring->vr_u_mutex, NULL, MUTEX_DRIVER, NULL);
}

static void
viona_ring_free(viona_vring_t *ring)
{
	mutex_destroy(&ring->vr_lock);
	cv_destroy(&ring->vr_cv);
	mutex_destroy(&ring->vr_a_mutex);
	mutex_destroy(&ring->vr_u_mutex);
	ring->vr_link = NULL;
}

static int
viona_ring_reset(viona_vring_t *ring, boolean_t heed_signals)
{
	mutex_enter(&ring->vr_lock);
	if (ring->vr_state == VRS_RESET) {
		mutex_exit(&ring->vr_lock);
		return (0);
	}

	if ((ring->vr_state_flags & VRSF_REQ_STOP) == 0) {
		ring->vr_state_flags |= VRSF_REQ_STOP;
		cv_broadcast(&ring->vr_cv);
	}
	while (ring->vr_state != VRS_RESET) {
		if (!heed_signals) {
			cv_wait(&ring->vr_cv, &ring->vr_lock);
		} else {
			int rs;

			rs = cv_wait_sig(&ring->vr_cv, &ring->vr_lock);
			if (rs <= 0 && ring->vr_state != VRS_RESET) {
				mutex_exit(&ring->vr_lock);
				return (EINTR);
			}
		}
	}
	mutex_exit(&ring->vr_lock);
	return (0);
}

static int
viona_ioc_ring_init(viona_link_t *link, void *udata, int md)
{
	vioc_ring_init_t kri;
	viona_vring_t *ring;
	kthread_t *t;
	uintptr_t pos;
	size_t desc_sz, avail_sz, used_sz;
	uint16_t cnt;
	int err = 0;

	if (ddi_copyin(udata, &kri, sizeof (kri), md) != 0) {
		return (EFAULT);
	}

	if (kri.ri_index >= VIONA_VQ_MAX) {
		return (EINVAL);
	}
	cnt = kri.ri_qsize;
	if (cnt == 0 || cnt > VRING_MAX_LEN || (1 << (ffs(cnt) - 1)) != cnt) {
		return (EINVAL);
	}

	ring = &link->l_vrings[kri.ri_index];
	mutex_enter(&ring->vr_lock);
	if (ring->vr_state != VRS_RESET) {
		mutex_exit(&ring->vr_lock);
		return (EBUSY);
	}
	VERIFY(ring->vr_state_flags == 0);

	pos = kri.ri_qaddr;
	desc_sz = cnt * sizeof (struct virtio_desc);
	avail_sz = (cnt + 3) * sizeof (uint16_t);
	used_sz = (cnt * sizeof (struct virtio_used)) + (sizeof (uint16_t) * 3);

	ring->vr_size = kri.ri_qsize;
	ring->vr_mask = (ring->vr_size - 1);
	ring->vr_descr = viona_gpa2kva(link, pos, desc_sz);
	if (ring->vr_descr == NULL) {
		err = EINVAL;
		goto fail;
	}
	pos += desc_sz;

	ring->vr_avail_flags = viona_gpa2kva(link, pos, avail_sz);
	if (ring->vr_avail_flags == NULL) {
		err = EINVAL;
		goto fail;
	}
	ring->vr_avail_idx = ring->vr_avail_flags + 1;
	ring->vr_avail_ring = ring->vr_avail_flags + 2;
	ring->vr_avail_used_event = ring->vr_avail_ring + cnt;
	pos += avail_sz;

	pos = P2ROUNDUP(pos, VRING_ALIGN);
	ring->vr_used_flags = viona_gpa2kva(link, pos, used_sz);
	if (ring->vr_used_flags == NULL) {
		err = EINVAL;
		goto fail;
	}
	ring->vr_used_idx = ring->vr_used_flags + 1;
	ring->vr_used_ring = (struct virtio_used *)(ring->vr_used_flags + 2);
	ring->vr_used_avail_event = (uint16_t *)(ring->vr_used_ring + cnt);

	/* Initialize queue indexes */
	ring->vr_cur_aidx = 0;

	/* Allocate desb handles for TX ring if packet copying not disabled */
	if (kri.ri_index == VIONA_VQ_TX && !viona_force_copy_tx_mblks) {
		viona_desb_t *desb, *dp;

		desb = kmem_zalloc(sizeof (viona_desb_t) * cnt, KM_SLEEP);
		dp = desb;
		for (uint_t i = 0; i < cnt; i++, dp++) {
			dp->d_frtn.free_func = viona_desb_release;
			dp->d_frtn.free_arg = (void *)dp;
			dp->d_ring = ring;
		}
		ring->vr_desb = desb;
	}

	/* Zero out MSI-X configuration */
	ring->vr_msi_addr = 0;
	ring->vr_msi_msg = 0;

	/* Clear the stats */
	bzero(&ring->vr_stats, sizeof (ring->vr_stats));

	t = viona_create_worker(ring);
	if (t == NULL) {
		err = ENOMEM;
		goto fail;
	}
	ring->vr_worker_thread = t;
	ring->vr_state = VRS_SETUP;
	cv_broadcast(&ring->vr_cv);
	mutex_exit(&ring->vr_lock);
	return (0);

fail:
	if (ring->vr_desb != NULL) {
		kmem_free(ring->vr_desb, sizeof (viona_desb_t) * cnt);
		ring->vr_desb = NULL;
	}
	ring->vr_size = 0;
	ring->vr_mask = 0;
	ring->vr_descr = NULL;
	ring->vr_avail_flags = NULL;
	ring->vr_avail_idx = NULL;
	ring->vr_avail_ring = NULL;
	ring->vr_avail_used_event = NULL;
	ring->vr_used_flags = NULL;
	ring->vr_used_idx = NULL;
	ring->vr_used_ring = NULL;
	ring->vr_used_avail_event = NULL;
	mutex_exit(&ring->vr_lock);
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

/*
 * Return the number of available descriptors in the vring taking care of the
 * 16-bit index wraparound.
 *
 * Note: If the number of apparently available descriptors is larger than the
 * ring size (due to guest misbehavior), this check will still report the
 * positive count of descriptors.
 */
static inline int
viona_vr_num_avail(viona_vring_t *ring)
{
	uint16_t ndesc;

	/*
	 * We're just computing (a-b) in GF(216).
	 *
	 * The only glitch here is that in standard C, uint16_t promotes to
	 * (signed) int when int has more than 16 bits (almost always now).
	 * A cast back to unsigned is necessary for proper operation.
	 */
	ndesc = (unsigned)*ring->vr_avail_idx - (unsigned)ring->vr_cur_aidx;

	return (ndesc);
}

static void
viona_worker_rx(viona_vring_t *ring, viona_link_t *link)
{
	proc_t *p = ttoproc(curthread);

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT3U(ring->vr_state, ==, VRS_RUN);

	atomic_or_16(ring->vr_used_flags, VRING_USED_F_NO_NOTIFY);
	mac_rx_set(link->l_mch, viona_rx, link);

	do {
		/*
		 * For now, there is little to do in the RX worker as inbound
		 * data is delivered by MAC via the viona_rx callback.
		 * If tap-like functionality is added later, this would be a
		 * convenient place to inject frames into the guest.
		 */
		(void) cv_wait_sig(&ring->vr_cv, &ring->vr_lock);
	} while (!VRING_NEED_BAIL(ring, p));

	mutex_exit(&ring->vr_lock);
	/*
	 * Clearing the RX function involves MAC quiescing any flows on that
	 * client.  If MAC happens to be delivering packets to this ring via
	 * viona_rx() at the time of worker clean-up, that thread may need to
	 * acquire vr_lock for tasks such as delivering an interrupt.  In order
	 * to avoid such deadlocks, vr_lock must temporarily be dropped here.
	 */
	mac_rx_clear(link->l_mch);
	mutex_enter(&ring->vr_lock);
}

static void
viona_worker_tx(viona_vring_t *ring, viona_link_t *link)
{
	proc_t *p = ttoproc(curthread);

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT3U(ring->vr_state, ==, VRS_RUN);

	mutex_exit(&ring->vr_lock);

	for (;;) {
		boolean_t bail = B_FALSE;
		uint_t ntx = 0;

		atomic_or_16(ring->vr_used_flags, VRING_USED_F_NO_NOTIFY);
		while (viona_vr_num_avail(ring)) {
			viona_tx(link, ring);

			/*
			 * It is advantageous for throughput to keep this
			 * transmission loop tight, but periodic breaks to
			 * check for other events are of value too.
			 */
			if (ntx++ >= ring->vr_size)
				break;
		}
		atomic_and_16(ring->vr_used_flags, ~VRING_USED_F_NO_NOTIFY);

		VIONA_PROBE2(tx, viona_link_t *, link, uint_t, ntx);

		/*
		 * Check for available descriptors on the ring once more in
		 * case a late addition raced with the NO_NOTIFY flag toggle.
		 */
		bail = VRING_NEED_BAIL(ring, p);
		if (!bail && viona_vr_num_avail(ring)) {
			continue;
		}

		if ((link->l_features & VIRTIO_F_RING_NOTIFY_ON_EMPTY) != 0) {
			viona_intr_ring(ring);
		}

		mutex_enter(&ring->vr_lock);
		while (!bail && !viona_vr_num_avail(ring)) {
			(void) cv_wait_sig(&ring->vr_cv, &ring->vr_lock);
			bail = VRING_NEED_BAIL(ring, p);
		}
		if (bail) {
			break;
		}
		mutex_exit(&ring->vr_lock);
	}

	ASSERT(MUTEX_HELD(&ring->vr_lock));

	while (ring->vr_xfer_outstanding != 0) {
		/*
		 * Paying heed to signals is counterproductive here.  This is a
		 * very tight loop if pending transfers take an extended amount
		 * of time to be reclaimed while the host process is exiting.
		 */
		cv_wait(&ring->vr_cv, &ring->vr_lock);
	}

	/* Free any desb resources before the ring is completely stopped */
	if (ring->vr_desb != NULL) {
		kmem_free(ring->vr_desb, sizeof (viona_desb_t) * ring->vr_size);
		ring->vr_desb = NULL;
	}
}

static void
viona_worker(void *arg)
{
	viona_vring_t *ring = (viona_vring_t *)arg;
	viona_link_t *link = ring->vr_link;
	proc_t *p = ttoproc(curthread);

	mutex_enter(&ring->vr_lock);
	VERIFY3U(ring->vr_state, ==, VRS_SETUP);

	/* Bail immediately if ring shutdown or process exit was requested */
	if (VRING_NEED_BAIL(ring, p)) {
		goto cleanup;
	}

	/* Report worker thread as alive and notify creator */
	ring->vr_state = VRS_INIT;
	cv_broadcast(&ring->vr_cv);

	while (ring->vr_state_flags == 0) {
		(void) cv_wait_sig(&ring->vr_cv, &ring->vr_lock);

		if (VRING_NEED_BAIL(ring, p)) {
			goto cleanup;
		}
	}

	ASSERT((ring->vr_state_flags & VRSF_REQ_START) != 0);
	ring->vr_state = VRS_RUN;
	ring->vr_state_flags &= ~VRSF_REQ_START;

	/* Process actual work */
	if (ring == &link->l_vrings[VIONA_VQ_RX]) {
		viona_worker_rx(ring, link);
	} else if (ring == &link->l_vrings[VIONA_VQ_TX]) {
		viona_worker_tx(ring, link);
	} else {
		panic("unexpected ring: %p", (void *)ring);
	}

cleanup:
	/* Free any desb resources before the ring is completely stopped */
	if (ring->vr_desb != NULL) {
		VERIFY(ring->vr_xfer_outstanding == 0);
		kmem_free(ring->vr_desb, sizeof (viona_desb_t) * ring->vr_size);
		ring->vr_desb = NULL;
	}

	ring->vr_cur_aidx = 0;
	ring->vr_state = VRS_RESET;
	ring->vr_state_flags = 0;
	ring->vr_worker_thread = NULL;
	cv_broadcast(&ring->vr_cv);
	mutex_exit(&ring->vr_lock);

	mutex_enter(&ttoproc(curthread)->p_lock);
	lwp_exit();
}

static kthread_t *
viona_create_worker(viona_vring_t *ring)
{
	k_sigset_t hold_set;
	proc_t *p = curproc;
	kthread_t *t;
	klwp_t *lwp;

	ASSERT(MUTEX_HELD(&ring->vr_lock));
	ASSERT(ring->vr_state == VRS_RESET);

	sigfillset(&hold_set);
	lwp = lwp_create(viona_worker, (void *)ring, 0, p, TS_STOPPED,
	    minclsyspri - 1, &hold_set, curthread->t_cid, 0);
	if (lwp == NULL) {
		return (NULL);
	}

	t = lwptot(lwp);
	mutex_enter(&p->p_lock);
	t->t_proc_flag = (t->t_proc_flag & ~TP_HOLDLWP) | TP_KTHREAD;
	lwp_create_done(t);
	mutex_exit(&p->p_lock);

	return (t);
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

static int
vq_popchain(viona_vring_t *ring, struct iovec *iov, int niov, uint16_t *cookie)
{
	viona_link_t *link = ring->vr_link;
	uint_t i, ndesc, idx, head, next;
	struct virtio_desc vdir;
	void *buf;

	ASSERT(iov != NULL);
	ASSERT(niov > 0);

	mutex_enter(&ring->vr_a_mutex);
	idx = ring->vr_cur_aidx;
	ndesc = (uint16_t)((unsigned)*ring->vr_avail_idx - (unsigned)idx);

	if (ndesc == 0) {
		mutex_exit(&ring->vr_a_mutex);
		return (0);
	}
	if (ndesc > ring->vr_size) {
		/*
		 * Despite the fact that the guest has provided an 'avail_idx'
		 * which indicates that an impossible number of descriptors are
		 * available, continue on and attempt to process the next one.
		 *
		 * The transgression will not escape the probe or stats though.
		 */
		VIONA_PROBE2(ndesc_too_high, viona_vring_t *, ring,
		    uint16_t, ndesc);
		VIONA_RING_STAT_INCR(ring, ndesc_too_high);
	}

	head = ring->vr_avail_ring[idx & ring->vr_mask];
	next = head;

	for (i = 0; i < niov; next = vdir.vd_next) {
		if (next >= ring->vr_size) {
			VIONA_PROBE2(bad_idx, viona_vring_t *, ring,
			    uint16_t, next);
			VIONA_RING_STAT_INCR(ring, bad_idx);
			goto bail;
		}

		vdir = ring->vr_descr[next];
		if ((vdir.vd_flags & VRING_DESC_F_INDIRECT) == 0) {
			buf = viona_gpa2kva(link, vdir.vd_addr, vdir.vd_len);
			if (buf == NULL) {
				VIONA_PROBE_BAD_RING_ADDR(ring, vdir.vd_addr);
				VIONA_RING_STAT_INCR(ring, bad_ring_addr);
				goto bail;
			}
			iov[i].iov_base = buf;
			iov[i].iov_len = vdir.vd_len;
			i++;
		} else {
			const uint_t nindir = vdir.vd_len / 16;
			volatile struct virtio_desc *vindir;

			if ((vdir.vd_len & 0xf) || nindir == 0) {
				VIONA_PROBE2(indir_bad_len,
				    viona_vring_t *, ring,
				    uint32_t, vdir.vd_len);
				VIONA_RING_STAT_INCR(ring, indir_bad_len);
				goto bail;
			}
			vindir = viona_gpa2kva(link, vdir.vd_addr, vdir.vd_len);
			if (vindir == NULL) {
				VIONA_PROBE_BAD_RING_ADDR(ring, vdir.vd_addr);
				VIONA_RING_STAT_INCR(ring, bad_ring_addr);
				goto bail;
			}
			next = 0;
			for (;;) {
				struct virtio_desc vp;

				/*
				 * A copy of the indirect descriptor is made
				 * here, rather than simply using a reference
				 * pointer.  This prevents malicious or
				 * erroneous guest writes to the descriptor
				 * from fooling the flags/bounds verification
				 * through a race.
				 */
				vp = vindir[next];
				if (vp.vd_flags & VRING_DESC_F_INDIRECT) {
					VIONA_PROBE1(indir_bad_nest,
					    viona_vring_t *, ring);
					VIONA_RING_STAT_INCR(ring,
					    indir_bad_nest);
					goto bail;
				}
				buf = viona_gpa2kva(link, vp.vd_addr,
				    vp.vd_len);
				if (buf == NULL) {
					VIONA_PROBE_BAD_RING_ADDR(ring,
					    vp.vd_addr);
					VIONA_RING_STAT_INCR(ring,
					    bad_ring_addr);
					goto bail;
				}
				iov[i].iov_base = buf;
				iov[i].iov_len = vp.vd_len;
				i++;

				if ((vp.vd_flags & VRING_DESC_F_NEXT) == 0)
					break;
				if (i >= niov) {
					goto loopy;
				}

				next = vp.vd_next;
				if (next >= nindir) {
					VIONA_PROBE3(indir_bad_next,
					    viona_vring_t *, ring,
					    uint16_t, next,
					    uint_t, nindir);
					VIONA_RING_STAT_INCR(ring,
					    indir_bad_next);
					goto bail;
				}
			}
		}
		if ((vdir.vd_flags & VRING_DESC_F_NEXT) == 0) {
			*cookie = head;
			ring->vr_cur_aidx++;
			mutex_exit(&ring->vr_a_mutex);
			return (i);
		}
	}

loopy:
	VIONA_PROBE1(too_many_desc, viona_vring_t *, ring);
	VIONA_RING_STAT_INCR(ring, too_many_desc);
bail:
	mutex_exit(&ring->vr_a_mutex);
	return (-1);
}

static void
vq_pushchain(viona_vring_t *ring, uint32_t len, uint16_t cookie)
{
	volatile struct virtio_used *vu;
	uint_t uidx;

	mutex_enter(&ring->vr_u_mutex);

	uidx = *ring->vr_used_idx;
	vu = &ring->vr_used_ring[uidx++ & ring->vr_mask];
	vu->vu_idx = cookie;
	vu->vu_tlen = len;
	membar_producer();
	*ring->vr_used_idx = uidx;

	mutex_exit(&ring->vr_u_mutex);
}

static void
vq_pushchain_mrgrx(viona_vring_t *ring, int num_bufs, used_elem_t *elem)
{
	volatile struct virtio_used *vu;
	uint_t uidx, i;

	mutex_enter(&ring->vr_u_mutex);

	uidx = *ring->vr_used_idx;
	if (num_bufs == 1) {
		vu = &ring->vr_used_ring[uidx++ & ring->vr_mask];
		vu->vu_idx = elem[0].id;
		vu->vu_tlen = elem[0].len;
	} else {
		for (i = 0; i < num_bufs; i++) {
			vu = &ring->vr_used_ring[(uidx + i) & ring->vr_mask];
			vu->vu_idx = elem[i].id;
			vu->vu_tlen = elem[i].len;
		}
		uidx = uidx + num_bufs;
	}
	membar_producer();
	*ring->vr_used_idx = uidx;

	mutex_exit(&ring->vr_u_mutex);
}

static void
viona_intr_ring(viona_vring_t *ring)
{
	uint64_t addr;

	mutex_enter(&ring->vr_lock);
	/* Deliver the interrupt directly, if so configured. */
	if ((addr = ring->vr_msi_addr) != 0) {
		uint64_t msg = ring->vr_msi_msg;

		mutex_exit(&ring->vr_lock);
		(void) vmm_drv_msi(ring->vr_link->l_vm_hold, addr, msg);
		return;
	}
	mutex_exit(&ring->vr_lock);

	if (atomic_cas_uint(&ring->vr_intr_enabled, 0, 1) == 0) {
		pollwakeup(&ring->vr_link->l_pollhead, POLLRDBAND);
	}
}

static size_t
viona_copy_mblk(const mblk_t *mp, size_t seek, caddr_t buf, size_t len,
    boolean_t *end)
{
	size_t copied = 0;
	size_t off = 0;

	/* Seek past already-consumed data */
	while (seek > 0 && mp != NULL) {
		const size_t chunk = MBLKL(mp);

		if (chunk > seek) {
			off = seek;
			break;
		}
		mp = mp->b_cont;
		seek -= chunk;
	}

	while (mp != NULL) {
		const size_t chunk = MBLKL(mp) - off;
		const size_t to_copy = MIN(chunk, len);

		bcopy(mp->b_rptr + off, buf, to_copy);
		copied += to_copy;
		buf += to_copy;
		len -= to_copy;

		/*
		 * If all the remaining data in the mblk_t was copied, move on
		 * to the next one in the chain.  Any seek offset applied to
		 * the first mblk copy is zeroed out for subsequent operations.
		 */
		if (chunk == to_copy) {
			mp = mp->b_cont;
			off = 0;
		}
#ifdef DEBUG
		else {
			/*
			 * The only valid reason for the copy to consume less
			 * than the entire contents of the mblk_t is because
			 * the output buffer has been filled.
			 */
			ASSERT0(len);
		}
#endif

		/* Go no further if the buffer has been filled */
		if (len == 0) {
			break;
		}

	}
	*end = (mp == NULL);
	return (copied);
}

static int
viona_recv_plain(viona_vring_t *ring, const mblk_t *mp, size_t msz)
{
	struct iovec iov[VTNET_MAXSEGS];
	uint16_t cookie;
	int n;
	const size_t hdr_sz = sizeof (struct virtio_net_hdr);
	struct virtio_net_hdr *hdr;
	size_t len, copied = 0;
	caddr_t buf = NULL;
	boolean_t end = B_FALSE;

	ASSERT(msz >= MIN_BUF_SIZE);

	n = vq_popchain(ring, iov, VTNET_MAXSEGS, &cookie);
	if (n <= 0) {
		/* Without available buffers, the frame must be dropped. */
		return (ENOSPC);
	}
	if (iov[0].iov_len < hdr_sz) {
		/*
		 * There is little to do if there is not even space available
		 * for the sole header.  Zero the buffer and bail out as a last
		 * act of desperation.
		 */
		bzero(iov[0].iov_base, iov[0].iov_len);
		goto bad_frame;
	}

	/* Grab the address of the header before anything else */
	hdr = (struct virtio_net_hdr *)iov[0].iov_base;

	/*
	 * If there is any space remaining in the first buffer after writing
	 * the header, fill it with frame data.
	 */
	if (iov[0].iov_len > hdr_sz) {
		buf = (caddr_t)iov[0].iov_base + hdr_sz;
		len = iov[0].iov_len - hdr_sz;

		copied += viona_copy_mblk(mp, copied, buf, len, &end);
	}

	/* Copy any remaining data into subsequent buffers, if present */
	for (int i = 1; i < n && !end; i++) {
		buf = (caddr_t)iov[i].iov_base;
		len = iov[i].iov_len;

		copied += viona_copy_mblk(mp, copied, buf, len, &end);
	}

	/* Was the expected amount of data copied? */
	if (copied != msz) {
		VIONA_PROBE5(too_short, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp, size_t, copied,
		    size_t, msz);
		VIONA_RING_STAT_INCR(ring, too_short);
		goto bad_frame;
	}

	/* Populate (read: zero) the header and account for it in the size */
	bzero(hdr, hdr_sz);
	copied += hdr_sz;

	/* Add chksum bits, if needed */
	if ((ring->vr_link->l_features & VIRTIO_NET_F_GUEST_CSUM) != 0) {
		uint32_t cksum_flags;

		mac_hcksum_get((mblk_t *)mp, NULL, NULL, NULL, NULL,
		    &cksum_flags);
		if ((cksum_flags & HCK_FULLCKSUM_OK) != 0) {
			hdr->vrh_flags |= VIRTIO_NET_HDR_F_DATA_VALID;
		}
	}

	/* Release this chain */
	vq_pushchain(ring, copied, cookie);
	return (0);

bad_frame:
	VIONA_PROBE3(bad_rx_frame, viona_vring_t *, ring, uint16_t, cookie,
	    mblk_t *, mp);
	VIONA_RING_STAT_INCR(ring, bad_rx_frame);

	vq_pushchain(ring, MAX(copied, MIN_BUF_SIZE + hdr_sz), cookie);
	return (EINVAL);
}

static int
viona_recv_merged(viona_vring_t *ring, const mblk_t *mp, size_t msz)
{
	struct iovec iov[VTNET_MAXSEGS];
	used_elem_t uelem[VTNET_MAXSEGS];
	int n, i = 0, buf_idx = 0, err = 0;
	uint16_t cookie;
	caddr_t buf;
	size_t len, copied = 0, chunk = 0;
	struct virtio_net_mrgrxhdr *hdr = NULL;
	const size_t hdr_sz = sizeof (struct virtio_net_mrgrxhdr);
	boolean_t end = B_FALSE;

	ASSERT(msz >= MIN_BUF_SIZE);

	n = vq_popchain(ring, iov, VTNET_MAXSEGS, &cookie);
	if (n <= 0) {
		/* Without available buffers, the frame must be dropped. */
		VIONA_PROBE2(no_space, viona_vring_t *, ring, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, no_space);
		return (ENOSPC);
	}
	if (iov[0].iov_len < hdr_sz) {
		/*
		 * There is little to do if there is not even space available
		 * for the sole header.  Zero the buffer and bail out as a last
		 * act of desperation.
		 */
		bzero(iov[0].iov_base, iov[0].iov_len);
		uelem[0].id = cookie;
		uelem[0].len = iov[0].iov_len;
		err = EINVAL;
		goto done;
	}

	/* Grab the address of the header and do initial population */
	hdr = (struct virtio_net_mrgrxhdr *)iov[0].iov_base;
	bzero(hdr, hdr_sz);
	hdr->vrh_bufs = 1;

	/*
	 * If there is any space remaining in the first buffer after writing
	 * the header, fill it with frame data.
	 */
	if (iov[0].iov_len > hdr_sz) {
		buf = iov[0].iov_base + hdr_sz;
		len = iov[0].iov_len - hdr_sz;

		chunk += viona_copy_mblk(mp, copied, buf, len, &end);
		copied += chunk;
	}
	i = 1;

	do {
		while (i < n && !end) {
			buf = iov[i].iov_base;
			len = iov[i].iov_len;

			chunk += viona_copy_mblk(mp, copied, buf, len, &end);
			copied += chunk;
			i++;
		}

		uelem[buf_idx].id = cookie;
		uelem[buf_idx].len = chunk;

		/*
		 * Try to grab another buffer from the ring if the mblk has not
		 * yet been entirely copied out.
		 */
		if (!end) {
			if (buf_idx == (VTNET_MAXSEGS - 1)) {
				/*
				 * Our arbitrary limit on the number of buffers
				 * to offer for merge has already been reached.
				 */
				err = EOVERFLOW;
				break;
			}
			n = vq_popchain(ring, iov, VTNET_MAXSEGS, &cookie);
			if (n <= 0) {
				/*
				 * Without more immediate space to perform the
				 * copying, there is little choice left but to
				 * drop the packet.
				 */
				err = EMSGSIZE;
				break;
			}
			chunk = 0;
			i = 0;
			buf_idx++;
			/*
			 * Keep the header up-to-date with the number of
			 * buffers, but never reference its value since the
			 * guest could meddle with it.
			 */
			hdr->vrh_bufs++;
		}
	} while (!end && copied < msz);

	/* Account for the header size in the first buffer */
	uelem[0].len += hdr_sz;

	/*
	 * If no other errors were encounted during the copy, was the expected
	 * amount of data transfered?
	 */
	if (err == 0 && copied != msz) {
		VIONA_PROBE5(too_short, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp, size_t, copied,
		    size_t, msz);
		VIONA_RING_STAT_INCR(ring, too_short);
		err = EINVAL;
	}

	/* Add chksum bits, if needed */
	if ((ring->vr_link->l_features & VIRTIO_NET_F_GUEST_CSUM) != 0) {
		uint32_t cksum_flags;

		mac_hcksum_get((mblk_t *)mp, NULL, NULL, NULL, NULL,
		    &cksum_flags);
		if ((cksum_flags & HCK_FULLCKSUM_OK) != 0) {
			hdr->vrh_flags |= VIRTIO_NET_HDR_F_DATA_VALID;
		}
	}

done:
	switch (err) {
	case 0:
		/* Success can fall right through to ring delivery */
		break;

	case EMSGSIZE:
		VIONA_PROBE3(rx_merge_underrun, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, rx_merge_underrun);
		break;

	case EOVERFLOW:
		VIONA_PROBE3(rx_merge_overrun, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, rx_merge_overrun);
		break;

	default:
		VIONA_PROBE3(bad_rx_frame, viona_vring_t *, ring,
		    uint16_t, cookie, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, bad_rx_frame);
	}
	vq_pushchain_mrgrx(ring, buf_idx + 1, uelem);
	return (err);
}

static void
viona_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp, boolean_t loopback)
{
	viona_link_t *link = (viona_link_t *)arg;
	viona_vring_t *ring = &link->l_vrings[VIONA_VQ_RX];
	mblk_t *mprx = NULL, **mprx_prevp = &mprx;
	mblk_t *mpdrop = NULL, **mpdrop_prevp = &mpdrop;
	const boolean_t do_merge =
	    ((link->l_features & VIRTIO_NET_F_MRG_RXBUF) != 0);
	size_t nrx = 0, ndrop = 0;

	while (mp != NULL) {
		mblk_t *next, *pad = NULL;
		size_t size;
		int err = 0;

		next = mp->b_next;
		mp->b_next = NULL;
		size = msgsize(mp);

		/*
		 * Ethernet frames are expected to be padded out in order to
		 * meet the minimum size.
		 *
		 * A special case is made for frames which are short by
		 * VLAN_TAGSZ, having been stripped of their VLAN tag while
		 * traversing MAC.  A preallocated (and recycled) mblk is used
		 * for that specific condition.
		 *
		 * All other frames that fall short on length will have custom
		 * zero-padding allocated appended to them.
		 */
		if (size == NEED_VLAN_PAD_SIZE) {
			ASSERT(MBLKL(viona_vlan_pad_mp) == VLAN_TAGSZ);
			ASSERT(viona_vlan_pad_mp->b_cont == NULL);

			for (pad = mp; pad->b_cont != NULL; pad = pad->b_cont)
				;

			pad->b_cont = viona_vlan_pad_mp;
			size += VLAN_TAGSZ;
		} else if (size < MIN_BUF_SIZE) {
			const size_t pad_size = MIN_BUF_SIZE - size;
			mblk_t *zero_mp;

			zero_mp = allocb(pad_size, BPRI_MED);
			if (zero_mp == NULL) {
				err = ENOMEM;
				goto pad_drop;
			}

			VIONA_PROBE3(rx_pad_short, viona_vring_t *, ring,
			    mblk_t *, mp, size_t, pad_size);
			VIONA_RING_STAT_INCR(ring, rx_pad_short);
			zero_mp->b_wptr += pad_size;
			bzero(zero_mp->b_rptr, pad_size);
			linkb(mp, zero_mp);
			size += pad_size;
		}

		if (do_merge) {
			err = viona_recv_merged(ring, mp, size);
		} else {
			err = viona_recv_plain(ring, mp, size);
		}

		/*
		 * The VLAN padding mblk is meant for continual reuse, so
		 * remove it from the chain to prevent it from being freed.
		 *
		 * Custom allocated padding does not require this treatment and
		 * is freed normally.
		 */
		if (pad != NULL) {
			pad->b_cont = NULL;
		}

pad_drop:
		if (err != 0) {
			*mpdrop_prevp = mp;
			mpdrop_prevp = &mp->b_next;

			/*
			 * If the available ring is empty, do not bother
			 * attempting to deliver any more frames.  Count the
			 * rest as dropped too.
			 */
			if (err == ENOSPC) {
				mp->b_next = next;
				break;
			}
		} else {
			/* Chain successful mblks to be freed later */
			*mprx_prevp = mp;
			mprx_prevp = &mp->b_next;
			nrx++;
		}
		mp = next;
	}

	if ((*ring->vr_avail_flags & VRING_AVAIL_F_NO_INTERRUPT) == 0) {
		viona_intr_ring(ring);
	}

	/* Free successfully received frames */
	if (mprx != NULL) {
		freemsgchain(mprx);
	}

	/* Free dropped frames, also tallying them */
	mp = mpdrop;
	while (mp != NULL) {
		mblk_t *next = mp->b_next;

		mp->b_next = NULL;
		freemsg(mp);
		mp = next;
		ndrop++;
	}
	VIONA_PROBE3(rx, viona_link_t *, link, size_t, nrx, size_t, ndrop);
}

static void
viona_tx_done(viona_vring_t *ring, uint32_t len, uint16_t cookie)
{
	vq_pushchain(ring, len, cookie);

	if ((*ring->vr_avail_flags & VRING_AVAIL_F_NO_INTERRUPT) == 0) {
		viona_intr_ring(ring);
	}
}

static void
viona_desb_release(viona_desb_t *dp)
{
	viona_vring_t *ring = dp->d_ring;
	uint_t ref;
	uint32_t len;
	uint16_t cookie;

	ref = atomic_dec_uint_nv(&dp->d_ref);
	if (ref > 1) {
		return;
	}

	/*
	 * The desb corresponding to this index must be ready for reuse before
	 * the descriptor is returned to the guest via the 'used' ring.
	 */
	len = dp->d_len;
	cookie = dp->d_cookie;
	dp->d_len = 0;
	dp->d_cookie = 0;
	dp->d_ref = 0;

	viona_tx_done(ring, len, cookie);

	mutex_enter(&ring->vr_lock);
	if ((--ring->vr_xfer_outstanding) == 0) {
		cv_broadcast(&ring->vr_cv);
	}
	mutex_exit(&ring->vr_lock);
}

static int
viona_mb_get_uint8(mblk_t *mp, off_t off, uint8_t *out)
{
	size_t mpsize;
	uint8_t *bp;

	mpsize = msgsize(mp);
	if (off + sizeof (uint8_t) > mpsize)
		return (-1);

	mpsize = MBLKL(mp);
	while (off >= mpsize) {
		mp = mp->b_cont;
		off -= mpsize;
		mpsize = MBLKL(mp);
	}

	bp = mp->b_rptr + off;
	*out = *bp;
	return (0);
}

static boolean_t
viona_tx_csum(viona_vring_t *ring, const struct virtio_net_hdr *hdr,
    mblk_t *mp, uint32_t len)
{
	viona_link_t *link = ring->vr_link;
	const struct ether_header *eth;
	uint_t eth_len = sizeof (struct ether_header);
	ushort_t ftype;
	uint8_t ipproto = IPPROTO_NONE; /* NONE is not exactly right, but ok */

	eth = (const struct ether_header *)mp->b_rptr;
	if (MBLKL(mp) < sizeof (*eth)) {
		/* Buffers shorter than an ethernet header are hopeless */
		return (B_FALSE);
	}

	ftype = ntohs(eth->ether_type);
	if (ftype == ETHERTYPE_VLAN) {
		const struct ether_vlan_header *veth;

		/* punt on QinQ for now */
		eth_len = sizeof (struct ether_vlan_header);
		veth = (const struct ether_vlan_header *)eth;
		ftype = ntohs(veth->ether_type);
	}

	if (ftype == ETHERTYPE_IP) {
		const size_t off = offsetof(ipha_t, ipha_protocol) + eth_len;

		(void) viona_mb_get_uint8(mp, off, &ipproto);
	} else if (ftype == ETHERTYPE_IPV6) {
		const size_t off = offsetof(ip6_t, ip6_nxt) + eth_len;

		(void) viona_mb_get_uint8(mp, off, &ipproto);
	}

	/*
	 * Partial checksum support from the NIC is ideal, since it most
	 * closely maps to the interface defined by virtio.
	 */
	if ((link->l_cap_csum & HCKSUM_INET_PARTIAL) != 0 &&
	    (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)) {
		uint_t start, stuff, end;

		/*
		 * The lower-level driver is expecting these offsets to be
		 * relative to the start of the L3 header rather than the
		 * ethernet frame.
		 */
		start = hdr->vrh_csum_start - eth_len;
		stuff = start + hdr->vrh_csum_offset;
		end = len - eth_len;
		mac_hcksum_set(mp, start, stuff, end, 0, HCK_PARTIALCKSUM);
		return (B_TRUE);
	}

	/*
	 * Without partial checksum support, look to the L3/L4 protocol
	 * information to see if the NIC can handle it.  If not, the
	 * checksum will need to calculated inline.
	 */
	if (ftype == ETHERTYPE_IP) {
		if ((link->l_cap_csum & HCKSUM_INET_FULL_V4) != 0 &&
		    (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)) {
			mac_hcksum_set(mp, 0, 0, 0, 0, HCK_FULLCKSUM);
			return (B_TRUE);
		}

		/* XXX: Implement manual fallback checksumming? */
		VIONA_PROBE2(fail_hcksum, viona_link_t *, link, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, fail_hcksum);
		return (B_FALSE);
	} else if (ftype == ETHERTYPE_IPV6) {
		if ((link->l_cap_csum & HCKSUM_INET_FULL_V6) != 0 &&
		    (ipproto == IPPROTO_TCP || ipproto == IPPROTO_UDP)) {
			mac_hcksum_set(mp, 0, 0, 0, 0, HCK_FULLCKSUM);
			return (B_TRUE);
		}

		/* XXX: Implement manual fallback checksumming? */
		VIONA_PROBE2(fail_hcksum6, viona_link_t *, link, mblk_t *, mp);
		VIONA_RING_STAT_INCR(ring, fail_hcksum6);
		return (B_FALSE);
	}

	/* Cannot even emulate hcksum for unrecognized protocols */
	VIONA_PROBE2(fail_hcksum_proto, viona_link_t *, link, mblk_t *, mp);
	VIONA_RING_STAT_INCR(ring, fail_hcksum_proto);
	return (B_FALSE);
}

static void
viona_tx(viona_link_t *link, viona_vring_t *ring)
{
	struct iovec		iov[VTNET_MAXSEGS];
	uint16_t		cookie;
	int			n;
	uint32_t		len;
	mblk_t			*mp_head, *mp_tail, *mp;
	viona_desb_t		*dp = NULL;
	mac_client_handle_t	link_mch = link->l_mch;
	const struct virtio_net_hdr *hdr;

	mp_head = mp_tail = NULL;

	n = vq_popchain(ring, iov, VTNET_MAXSEGS, &cookie);
	if (n <= 0) {
		VIONA_PROBE1(tx_absent, viona_vring_t *, ring);
		VIONA_RING_STAT_INCR(ring, tx_absent);
		return;
	}

	if (ring->vr_desb != NULL) {
		dp = &ring->vr_desb[cookie];

		/*
		 * If the guest driver is operating properly, each desb slot
		 * should be available for use when processing a TX descriptor
		 * from the 'avail' ring.  In the case of drivers that reuse a
		 * descriptor before it has been posted to the 'used' ring, the
		 * data is simply dropped.
		 */
		if (atomic_cas_uint(&dp->d_ref, 0, 1) != 0) {
			dp = NULL;
			goto drop_fail;
		}
		dp->d_cookie = cookie;
	}

	/* Grab the header and ensure it is of adequate length */
	hdr = (const struct virtio_net_hdr *)iov[0].iov_base;
	len = iov[0].iov_len;
	if (len < sizeof (struct virtio_net_hdr)) {
		goto drop_fail;
	}

	for (uint_t i = 1; i < n; i++) {
		if (dp != NULL) {
			mp = desballoc((uchar_t *)iov[i].iov_base,
			    iov[i].iov_len, BPRI_MED, &dp->d_frtn);
			if (mp == NULL) {
				goto drop_fail;
			}
			dp->d_ref++;
		} else {
			mp = allocb(iov[i].iov_len, BPRI_MED);
			if (mp == NULL) {
				goto drop_fail;
			}
			bcopy((uchar_t *)iov[i].iov_base, mp->b_wptr,
			    iov[i].iov_len);
		}

		len += iov[i].iov_len;
		mp->b_wptr += iov[i].iov_len;
		if (mp_head == NULL) {
			ASSERT(mp_tail == NULL);
			mp_head = mp;
		} else {
			ASSERT(mp_tail != NULL);
			mp_tail->b_cont = mp;
		}
		mp_tail = mp;
	}

	/* Request hardware checksumming, if necessary */
	if ((link->l_features & VIRTIO_NET_F_CSUM) != 0 &&
	    (hdr->vrh_flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0) {
		if (!viona_tx_csum(ring, hdr, mp_head, len - iov[0].iov_len)) {
			goto drop_fail;
		}
	}

	if (dp != NULL) {
		dp->d_len = len;
		mutex_enter(&ring->vr_lock);
		ring->vr_xfer_outstanding++;
		mutex_exit(&ring->vr_lock);
	} else {
		/*
		 * If the data was cloned out of the ring, the descriptors can
		 * be marked as 'used' now, rather than deferring that action
		 * until after successful packet transmission.
		 */
		viona_tx_done(ring, len, cookie);
	}

	mac_tx(link_mch, mp_head, 0, MAC_DROP_ON_NO_DESC, NULL);
	return;

drop_fail:
	/*
	 * On the off chance that memory is not available via the desballoc or
	 * allocb calls, there are few options left besides to fail and drop
	 * the frame on the floor.
	 */

	if (dp != NULL) {
		/*
		 * Take an additional reference on the desb handle (if present)
		 * so any desballoc-sourced mblks can release their hold on it
		 * without the handle reaching its final state and executing
		 * its clean-up logic.
		 */
		dp->d_ref++;
	}

	/*
	 * Free any already-allocated blocks and sum up the total length of the
	 * dropped data to be released to the used ring.
	 */
	freemsgchain(mp_head);
	len = 0;
	for (uint_t i = 0; i < n; i++) {
		len += iov[i].iov_len;
	}

	if (dp != NULL) {
		VERIFY(dp->d_ref == 2);

		/* Clean up the desb handle, releasing the extra hold. */
		dp->d_len = 0;
		dp->d_cookie = 0;
		dp->d_ref = 0;
	}

	VIONA_PROBE3(tx_drop, viona_vring_t *, ring, uint_t, len,
	    uint16_t, cookie);
	viona_tx_done(ring, len, cookie);
}
