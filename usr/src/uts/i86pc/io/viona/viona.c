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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <vm/seg_kmem.h>

#include <sys/dls.h>
#include <sys/mac_client.h>

#include <sys/viona_io.h>

#define	MB	(1024UL * 1024)
#define	GB	(1024UL * MB)

/*
 * Min. octets in an ethernet frame minus FCS
 */
#define	MIN_BUF_SIZE	60

#define	VIONA_NAME		"Virtio Network Accelerator"

#define	VIONA_CTL_MINOR		0
#define	VIONA_CTL_NODE_NAME	"ctl"

#define	VIONA_CLI_NAME		"viona"

#define	VTNET_MAXSEGS		32

#define	VRING_ALIGN		4096

#define	VRING_DESC_F_NEXT	(1 << 0)
#define	VRING_DESC_F_WRITE	(1 << 1)
#define	VRING_DESC_F_INDIRECT	(1 << 2)

#define	VRING_AVAIL_F_NO_INTERRUPT	1

#define	VRING_USED_F_NO_NOTIFY		1

#define	BCM_NIC_DRIVER		"bnxe"
/*
 * Host capabilities
 */
#define	VIRTIO_NET_F_MAC	(1 <<  5) /* host supplies MAC */
#define	VIRTIO_NET_F_MRG_RXBUF	(1 << 15) /* host can merge RX buffers */
#define	VIRTIO_NET_F_STATUS	(1 << 16) /* config status field available */

#define	VIONA_S_HOSTCAPS		\
	(VIRTIO_NET_F_MAC | VIRTIO_NET_F_MRG_RXBUF | \
	VIRTIO_NET_F_STATUS)

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

typedef struct viona_vring_hqueue {
	/* Internal state */
	uint16_t		hq_size;
	kmutex_t		hq_a_mutex;
	kmutex_t		hq_u_mutex;
	uint16_t		hq_cur_aidx;	/* trails behind 'avail_idx' */

	/* Host-context pointers to the queue */
	caddr_t			hq_baseaddr;
	uint16_t		*hq_avail_flags;
	uint16_t		*hq_avail_idx;	/* monotonically increasing */
	uint16_t		*hq_avail_ring;

	uint16_t		*hq_used_flags;
	uint16_t		*hq_used_idx;	/* monotonically increasing */
	struct virtio_used	*hq_used_ring;
} viona_vring_hqueue_t;


typedef struct viona_link {
	datalink_id_t		l_linkid;

	struct vm		*l_vm;
	size_t			l_vm_lomemsize;
	caddr_t			l_vm_lomemaddr;
	size_t			l_vm_himemsize;
	caddr_t			l_vm_himemaddr;

	mac_handle_t		l_mh;
	mac_client_handle_t	l_mch;

	kmem_cache_t		*l_desb_kmc;

	pollhead_t		l_pollhead;

	viona_vring_hqueue_t	l_rx_vring;
	uint_t			l_rx_intr;

	viona_vring_hqueue_t	l_tx_vring;
	kcondvar_t		l_tx_cv;
	uint_t			l_tx_intr;
	kmutex_t		l_tx_mutex;
	int			l_tx_outstanding;
	uint32_t		l_features;
} viona_link_t;

typedef struct {
	frtn_t			d_frtn;
	viona_link_t		*d_link;
	uint_t			d_ref;
	uint16_t		d_cookie;
	int			d_len;
} viona_desb_t;

typedef struct viona_soft_state {
	viona_link_t		*ss_link;
} viona_soft_state_t;

typedef struct used_elem {
	uint16_t	id;
	uint32_t	len;
} used_elem_t;

static void			*viona_state;
static dev_info_t		*viona_dip;
static id_space_t		*viona_minor_ids;
/*
 * copy tx mbufs from virtio ring to avoid necessitating a wait for packet
 * transmission to free resources.
 */
static boolean_t		copy_tx_mblks = B_TRUE;

extern struct vm *vm_lookup_by_name(char *name);
extern uint64_t vm_gpa2hpa(struct vm *vm, uint64_t gpa, size_t len);

static int viona_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int viona_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int viona_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int viona_close(dev_t dev, int flag, int otype, cred_t *credp);
static int viona_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);
static int viona_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp);

static int viona_ioc_create(viona_soft_state_t *ss, vioc_create_t *u_create);
static int viona_ioc_delete(viona_soft_state_t *ss);

static int viona_vm_map(viona_link_t *link);
static caddr_t viona_gpa2kva(viona_link_t *link, uint64_t gpa);
static void viona_vm_unmap(viona_link_t *link);

static int viona_ioc_rx_ring_init(viona_link_t *link,
    vioc_ring_init_t *u_ri);
static int viona_ioc_tx_ring_init(viona_link_t *link,
    vioc_ring_init_t *u_ri);
static int viona_ioc_rx_ring_reset(viona_link_t *link);
static int viona_ioc_tx_ring_reset(viona_link_t *link);
static void viona_ioc_rx_ring_kick(viona_link_t *link);
static void viona_ioc_tx_ring_kick(viona_link_t *link);
static int viona_ioc_rx_intr_clear(viona_link_t *link);
static int viona_ioc_tx_intr_clear(viona_link_t *link);

static void viona_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback);
static void viona_tx(viona_link_t *link, viona_vring_hqueue_t *hq);

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
	nodev,
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

	ret = ddi_soft_state_init(&viona_state,
	    sizeof (viona_soft_state_t), 0);
	if (ret == 0) {
		ret = mod_install(&modlinkage);
		if (ret != 0) {
			ddi_soft_state_fini(&viona_state);
			return (ret);
		}
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
			copy_tx_mblks = B_FALSE;
			ddi_rele_driver(bcm_nic_major);
		}
	}
}

static int
viona_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	viona_minor_ids = id_space_create("viona_minor_id",
	    VIONA_CTL_MINOR + 1, UINT16_MAX);

	if (ddi_create_minor_node(dip, VIONA_CTL_NODE_NAME,
	    S_IFCHR, VIONA_CTL_MINOR, DDI_PSEUDO, 0) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	viona_dip = dip;

	set_viona_tx_mode();
	ddi_report_dev(viona_dip);

	return (DDI_SUCCESS);
}

static int
viona_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	id_space_destroy(viona_minor_ids);

	ddi_remove_minor_node(viona_dip, NULL);

	viona_dip = NULL;

	return (DDI_SUCCESS);
}

static int
viona_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	int	minor;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	if (getminor(*devp) != VIONA_CTL_MINOR) {
		return (ENXIO);
	}

	minor = id_alloc(viona_minor_ids);
	if (minor == 0) {
		/* All minors are busy */
		return (EBUSY);
	}

	if (ddi_soft_state_zalloc(viona_state, minor) != DDI_SUCCESS) {
		id_free(viona_minor_ids, minor);
	}

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

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	minor = getminor(dev);

	ss = ddi_get_soft_state(viona_state, minor);
	if (ss == NULL) {
		return (ENXIO);
	}

	viona_ioc_delete(ss);

	ddi_soft_state_free(viona_state, minor);

	id_free(viona_minor_ids, minor);

	return (0);
}

static int
viona_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval)
{
	viona_soft_state_t	*ss;
	int			err = 0;

	ss = ddi_get_soft_state(viona_state, getminor(dev));
	if (ss == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	case VNA_IOC_CREATE:
		err = viona_ioc_create(ss, (vioc_create_t *)data);
		break;
	case VNA_IOC_DELETE:
		err = viona_ioc_delete(ss);
		break;
	case VNA_IOC_SET_FEATURES:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		ss->ss_link->l_features = *(int *)data & VIONA_S_HOSTCAPS;
		break;
	case VNA_IOC_GET_FEATURES:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		*(int *)data = VIONA_S_HOSTCAPS;
		break;
	case VNA_IOC_RX_RING_INIT:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		err = viona_ioc_rx_ring_init(ss->ss_link,
		    (vioc_ring_init_t *)data);
		break;
	case VNA_IOC_RX_RING_RESET:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		err = viona_ioc_rx_ring_reset(ss->ss_link);
		break;
	case VNA_IOC_RX_RING_KICK:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		viona_ioc_rx_ring_kick(ss->ss_link);
		err = 0;
		break;
	case VNA_IOC_TX_RING_INIT:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		err = viona_ioc_tx_ring_init(ss->ss_link,
		    (vioc_ring_init_t *)data);
		break;
	case VNA_IOC_TX_RING_RESET:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		err = viona_ioc_tx_ring_reset(ss->ss_link);
		break;
	case VNA_IOC_TX_RING_KICK:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		viona_ioc_tx_ring_kick(ss->ss_link);
		err = 0;
		break;
	case VNA_IOC_RX_INTR_CLR:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		err = viona_ioc_rx_intr_clear(ss->ss_link);
		break;
	case VNA_IOC_TX_INTR_CLR:
		if (ss->ss_link == NULL) {
			return (ENOSYS);
		}
		err = viona_ioc_tx_intr_clear(ss->ss_link);
		break;
	default:
		err = ENOTTY;
		break;
	}

	return (err);
}

static int
viona_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	viona_soft_state_t	*ss;

	ss = ddi_get_soft_state(viona_state, getminor(dev));
	if (ss == NULL || ss->ss_link == NULL) {
		return (ENXIO);
	}

	*reventsp = 0;

	if (ss->ss_link->l_rx_intr && (events & POLLIN)) {
		*reventsp |= POLLIN;
	}

	if (ss->ss_link->l_tx_intr && (events & POLLOUT)) {
		*reventsp |= POLLOUT;
	}

	if (*reventsp == 0 && !anyyet) {
		*phpp = &ss->ss_link->l_pollhead;
	}

	return (0);
}

static int
viona_ioc_create(viona_soft_state_t *ss, vioc_create_t *u_create)
{
	vioc_create_t		k_create;
	viona_link_t		*link;
	char			cli_name[MAXNAMELEN];
	int			err;

	if (ss->ss_link != NULL) {
		return (ENOSYS);
	}
	if (copyin(u_create, &k_create, sizeof (k_create)) != 0) {
		return (EFAULT);
	}

	link = kmem_zalloc(sizeof (viona_link_t), KM_SLEEP);

	link->l_linkid = k_create.c_linkid;
	link->l_vm = vm_lookup_by_name(k_create.c_vmname);
	if (link->l_vm == NULL) {
		err = ENXIO;
		goto bail;
	}

	link->l_vm_lomemsize = k_create.c_lomem_size;
	link->l_vm_himemsize = k_create.c_himem_size;
	err = viona_vm_map(link);
	if (err != 0) {
		goto bail;
	}

	err = mac_open_by_linkid(link->l_linkid, &link->l_mh);
	if (err != 0) {
		cmn_err(CE_WARN, "viona create mac_open_by_linkid"
		    " returned %d\n", err);
		goto bail;
	}

	snprintf(cli_name, sizeof (cli_name), "%s-%d",
	    VIONA_CLI_NAME, link->l_linkid);
	err = mac_client_open(link->l_mh, &link->l_mch, cli_name, 0);
	if (err != 0) {
		cmn_err(CE_WARN, "viona create mac_client_open"
		    " returned %d\n", err);
		goto bail;
	}

	link->l_features = VIONA_S_HOSTCAPS;
	link->l_desb_kmc = kmem_cache_create(cli_name,
	    sizeof (viona_desb_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	mutex_init(&link->l_rx_vring.hq_a_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&link->l_rx_vring.hq_u_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&link->l_rx_vring.hq_a_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&link->l_tx_vring.hq_u_mutex, NULL, MUTEX_DRIVER, NULL);
	if (copy_tx_mblks) {
		mutex_init(&link->l_tx_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&link->l_tx_cv, NULL, CV_DRIVER, NULL);
	}
	ss->ss_link = link;

	return (0);

bail:
	if (link->l_mch != NULL) {
		mac_client_close(link->l_mch, 0);
	}
	if (link->l_mh != NULL) {
		mac_close(link->l_mh);
	}

	kmem_free(link, sizeof (viona_link_t));

	return (err);
}

static int
viona_ioc_delete(viona_soft_state_t *ss)
{
	viona_link_t	*link;

	link = ss->ss_link;
	if (link == NULL) {
		return (ENOSYS);
	}
	if (copy_tx_mblks) {
		mutex_enter(&link->l_tx_mutex);
		while (link->l_tx_outstanding != 0) {
			cv_wait(&link->l_tx_cv, &link->l_tx_mutex);
		}
		mutex_exit(&link->l_tx_mutex);
	}
	if (link->l_mch != NULL) {
		mac_rx_clear(link->l_mch);
		mac_client_close(link->l_mch, 0);
	}
	if (link->l_mh != NULL) {
		mac_close(link->l_mh);
	}

	viona_vm_unmap(link);
	mutex_destroy(&link->l_tx_vring.hq_a_mutex);
	mutex_destroy(&link->l_tx_vring.hq_u_mutex);
	mutex_destroy(&link->l_rx_vring.hq_a_mutex);
	mutex_destroy(&link->l_rx_vring.hq_u_mutex);
	if (copy_tx_mblks) {
		mutex_destroy(&link->l_tx_mutex);
		cv_destroy(&link->l_tx_cv);
	}

	kmem_cache_destroy(link->l_desb_kmc);

	kmem_free(link, sizeof (viona_link_t));

	ss->ss_link = NULL;

	return (0);
}

static caddr_t
viona_mapin_vm_chunk(viona_link_t *link, uint64_t gpa, size_t len)
{
	caddr_t		addr;
	size_t		offset;
	pfn_t		pfnum;

	if (len == 0)
		return (NULL);

	addr = vmem_alloc(heap_arena, len, VM_SLEEP);
	if (addr == NULL)
		return (NULL);

	for (offset = 0; offset < len; offset += PAGESIZE) {
		pfnum = btop(vm_gpa2hpa(link->l_vm, gpa + offset, PAGESIZE));
		ASSERT(pfnum);
		hat_devload(kas.a_hat, addr + offset, PAGESIZE, pfnum,
		    PROT_READ | PROT_WRITE, HAT_LOAD_LOCK);
	}

	return (addr);
}

/*
 * Map the guest physical address space into the kernel virtual address space.
 */
static int
viona_vm_map(viona_link_t *link)
{
	link->l_vm_lomemaddr = viona_mapin_vm_chunk(link,
	    0, link->l_vm_lomemsize);
	if (link->l_vm_lomemaddr == NULL)
		return (-1);
	link->l_vm_himemaddr = viona_mapin_vm_chunk(link,
	    4 * (1024 * 1024 * 1024UL), link->l_vm_himemsize);
	if (link->l_vm_himemsize && link->l_vm_himemaddr == NULL)
		return (-1);

	return (0);
}

/*
 * Translate a guest physical address into a kernel virtual address.
 */
static caddr_t
viona_gpa2kva(viona_link_t *link, uint64_t gpa)
{
	if (gpa < link->l_vm_lomemsize)
		return (link->l_vm_lomemaddr + gpa);

	gpa -= (4 * GB);
	if (gpa < link->l_vm_himemsize)
		return (link->l_vm_himemaddr + gpa);

	return (NULL);
}

static void
viona_vm_unmap(viona_link_t *link)
{
	if (link->l_vm_lomemaddr) {
		hat_unload(kas.a_hat, link->l_vm_lomemaddr,
		    link->l_vm_lomemsize, HAT_UNLOAD_UNLOCK);
		vmem_free(heap_arena, link->l_vm_lomemaddr,
		    link->l_vm_lomemsize);
	}
	if (link->l_vm_himemaddr) {
		hat_unload(kas.a_hat, link->l_vm_himemaddr,
		    link->l_vm_himemsize, HAT_UNLOAD_UNLOCK);
		vmem_free(heap_arena, link->l_vm_himemaddr,
		    link->l_vm_himemsize);
	}
}

static int
viona_ioc_ring_init_common(viona_link_t *link, viona_vring_hqueue_t *hq,
    vioc_ring_init_t *u_ri)
{
	vioc_ring_init_t	k_ri;

	if (copyin(u_ri, &k_ri, sizeof (k_ri)) != 0) {
		return (EFAULT);
	}

	hq->hq_size = k_ri.ri_qsize;
	hq->hq_baseaddr = viona_gpa2kva(link, k_ri.ri_qaddr);
	if (hq->hq_baseaddr == NULL)
		return (EINVAL);

	hq->hq_avail_flags = (uint16_t *)(viona_gpa2kva(link,
	    k_ri.ri_qaddr + hq->hq_size * sizeof (struct virtio_desc)));
	if (hq->hq_avail_flags == NULL)
		return (EINVAL);
	hq->hq_avail_idx = hq->hq_avail_flags + 1;
	hq->hq_avail_ring = hq->hq_avail_flags + 2;

	hq->hq_used_flags = (uint16_t *)(viona_gpa2kva(link,
	    P2ROUNDUP(k_ri.ri_qaddr +
	    hq->hq_size * sizeof (struct virtio_desc) + 2, VRING_ALIGN)));
	if (hq->hq_used_flags == NULL)
		return (EINVAL);
	hq->hq_used_idx = hq->hq_used_flags + 1;
	hq->hq_used_ring = (struct virtio_used *)(hq->hq_used_flags + 2);

	/*
	 * Initialize queue indexes
	 */
	hq->hq_cur_aidx = 0;

	return (0);
}

static int
viona_ioc_rx_ring_init(viona_link_t *link, vioc_ring_init_t *u_ri)
{
	viona_vring_hqueue_t	*hq;
	int			rval;

	hq = &link->l_rx_vring;

	rval = viona_ioc_ring_init_common(link, hq, u_ri);
	if (rval != 0) {
		return (rval);
	}

	return (0);
}

static int
viona_ioc_tx_ring_init(viona_link_t *link, vioc_ring_init_t *u_ri)
{
	viona_vring_hqueue_t	*hq;

	hq = &link->l_tx_vring;

	return (viona_ioc_ring_init_common(link, hq, u_ri));
}

static int
viona_ioc_ring_reset_common(viona_vring_hqueue_t *hq)
{
	/*
	 * Reset all soft state
	 */
	hq->hq_cur_aidx = 0;

	return (0);
}

static int
viona_ioc_rx_ring_reset(viona_link_t *link)
{
	viona_vring_hqueue_t	*hq;

	mac_rx_clear(link->l_mch);

	hq = &link->l_rx_vring;

	return (viona_ioc_ring_reset_common(hq));
}

static int
viona_ioc_tx_ring_reset(viona_link_t *link)
{
	viona_vring_hqueue_t	*hq;

	hq = &link->l_tx_vring;

	return (viona_ioc_ring_reset_common(hq));
}

static void
viona_ioc_rx_ring_kick(viona_link_t *link)
{
	viona_vring_hqueue_t	*hq = &link->l_rx_vring;

	atomic_or_16(hq->hq_used_flags, VRING_USED_F_NO_NOTIFY);

	mac_rx_set(link->l_mch, viona_rx, link);
}

/*
 * Return the number of available descriptors in the vring taking care
 * of the 16-bit index wraparound.
 */
static inline int
viona_hq_num_avail(viona_vring_hqueue_t *hq)
{
	uint16_t ndesc;

	/*
	 * We're just computing (a-b) in GF(216).
	 *
	 * The only glitch here is that in standard C,
	 * uint16_t promotes to (signed) int when int has
	 * more than 16 bits (pretty much always now), so
	 * we have to force it back to unsigned.
	 */
	ndesc = (unsigned)*hq->hq_avail_idx - (unsigned)hq->hq_cur_aidx;

	ASSERT(ndesc <= hq->hq_size);

	return (ndesc);
}

static void
viona_ioc_tx_ring_kick(viona_link_t *link)
{
	viona_vring_hqueue_t	*hq = &link->l_tx_vring;

	do {
		atomic_or_16(hq->hq_used_flags, VRING_USED_F_NO_NOTIFY);
		while (viona_hq_num_avail(hq)) {
			viona_tx(link, hq);
		}
		if (copy_tx_mblks) {
			mutex_enter(&link->l_tx_mutex);
			if (link->l_tx_outstanding != 0) {
				cv_wait_sig(&link->l_tx_cv, &link->l_tx_mutex);
			}
			mutex_exit(&link->l_tx_mutex);
		}
		atomic_and_16(hq->hq_used_flags, ~VRING_USED_F_NO_NOTIFY);
	} while (viona_hq_num_avail(hq));
}

static int
viona_ioc_rx_intr_clear(viona_link_t *link)
{
	link->l_rx_intr = 0;

	return (0);
}

static int
viona_ioc_tx_intr_clear(viona_link_t *link)
{
	link->l_tx_intr = 0;

	return (0);
}
#define	VQ_MAX_DESCRIPTORS	512

static int
vq_popchain(viona_link_t *link, viona_vring_hqueue_t *hq, struct iovec *iov,
    int n_iov, uint16_t *cookie)
{
	int			i;
	int			ndesc, nindir;
	int			idx, head, next;
	struct virtio_desc	*vdir, *vindir, *vp;

	idx = hq->hq_cur_aidx;
	ndesc = (uint16_t)((unsigned)*hq->hq_avail_idx - (unsigned)idx);

	if (ndesc == 0)
		return (0);
	if (ndesc > hq->hq_size) {
		cmn_err(CE_NOTE, "ndesc (%d) out of range\n", ndesc);
		return (-1);
	}

	head = hq->hq_avail_ring[idx & (hq->hq_size - 1)];
	next = head;

	for (i = 0; i < VQ_MAX_DESCRIPTORS; next = vdir->vd_next) {
		if (next >= hq->hq_size) {
			cmn_err(CE_NOTE, "descriptor index (%d)"
			    "out of range\n", next);
			return (-1);
		}

		vdir = (struct virtio_desc *)(hq->hq_baseaddr +
		    next * sizeof (struct virtio_desc));
		if ((vdir->vd_flags & VRING_DESC_F_INDIRECT) == 0) {
			if (i > n_iov)
				return (-1);
			iov[i].iov_base = viona_gpa2kva(link, vdir->vd_addr);
			if (iov[i].iov_base == NULL) {
				cmn_err(CE_NOTE, "invalid guest physical"
				    " address 0x%"PRIx64"\n", vdir->vd_addr);
				return (-1);
			}
			iov[i++].iov_len = vdir->vd_len;
		} else {
			nindir = vdir->vd_len / 16;
			if ((vdir->vd_len & 0xf) || nindir == 0) {
				cmn_err(CE_NOTE, "invalid indir len 0x%x\n",
				    vdir->vd_len);
				return (-1);
			}
			vindir = (struct virtio_desc *)
			    viona_gpa2kva(link, vdir->vd_addr);
			if (vindir == NULL) {
				cmn_err(CE_NOTE, "invalid guest physical"
				    " address 0x%"PRIx64"\n", vdir->vd_addr);
				return (-1);
			}
			next = 0;
			for (;;) {
				vp = &vindir[next];
				if (vp->vd_flags & VRING_DESC_F_INDIRECT) {
					cmn_err(CE_NOTE, "indirect desc"
					    " has INDIR flag\n");
					return (-1);
				}
				if (i > n_iov)
					return (-1);
				iov[i].iov_base =
				    viona_gpa2kva(link, vp->vd_addr);
				if (iov[i].iov_base == NULL) {
					cmn_err(CE_NOTE, "invalid guest"
					    " physical address 0x%"PRIx64"\n",
					    vp->vd_addr);
					return (-1);
				}
				iov[i++].iov_len = vp->vd_len;

				if (i > VQ_MAX_DESCRIPTORS)
					goto loopy;
				if ((vp->vd_flags & VRING_DESC_F_NEXT) == 0)
					break;

				next = vp->vd_next;
				if (next >= nindir) {
					cmn_err(CE_NOTE, "invalid next"
					    " %d > %d\n", next, nindir);
					return (-1);
				}
			}
		}
		if ((vdir->vd_flags & VRING_DESC_F_NEXT) == 0) {
			*cookie = head;
			hq->hq_cur_aidx++;
			return (i);
		}
	}

loopy:
	cmn_err(CE_NOTE, "%d > descriptor loop count\n", i);

	return (-1);
}

static void
vq_pushchain(viona_vring_hqueue_t *hq, uint32_t len, uint16_t cookie)
{
	struct virtio_used	*vu;
	int			uidx;

	uidx = *hq->hq_used_idx;
	vu = &hq->hq_used_ring[uidx++ & (hq->hq_size - 1)];
	vu->vu_idx = cookie;
	vu->vu_tlen = len;
	membar_producer();
	*hq->hq_used_idx = uidx;
}

static void
vq_pushchain_mrgrx(viona_vring_hqueue_t *hq, int num_bufs, used_elem_t *elem)
{
	struct virtio_used	*vu;
	int			uidx;
	int			i;

	uidx = *hq->hq_used_idx;
	if (num_bufs == 1) {
		vu = &hq->hq_used_ring[uidx++ & (hq->hq_size - 1)];
		vu->vu_idx = elem[0].id;
		vu->vu_tlen = elem[0].len;
	} else {
		for (i = 0; i < num_bufs; i++) {
			vu = &hq->hq_used_ring[(uidx + i) & (hq->hq_size - 1)];
			vu->vu_idx = elem[i].id;
			vu->vu_tlen = elem[i].len;
		}
		uidx = uidx + num_bufs;
	}
	membar_producer();
	*hq->hq_used_idx = uidx;
}

/*
 * Copy bytes from mp to iov.
 * copied_buf: Total num_bytes copied from mblk to iov array.
 * buf: pointer to iov_base.
 * i: index of iov array. Mainly used to identify if we are
 *    dealing with first iov array element.
 * rxhdr_size: Virtio header size. Two possibilities in case
 *    of MRGRX buf, header has 2 additional bytes.
 *    In case of mrgrx, virtio header should be part of iov[0].
 *    In case of non-mrgrx, virtio header may or may not be part
 *    of iov[0].
 */
static int
copy_in_mblk(mblk_t *mp, int copied_buf, caddr_t buf, struct iovec *iov,
    int i, int rxhdr_size)
{
	int copied_chunk = 0;
	mblk_t *ml;
	int total_buf_len = iov->iov_len;
	/*
	 * iov[0] might have header, adjust
	 * total_buf_len accordingly
	 */
	if (i == 0) {
		total_buf_len = iov->iov_len - rxhdr_size;
	}
	for (ml = mp; ml != NULL; ml = ml->b_cont) {
		size_t	chunk = MBLKL(ml);
		/*
		 * If chunk is less than
		 * copied_buf we should move
		 * to correct msgblk
		 */
		if (copied_buf != 0) {
			if (copied_buf < chunk) {
				chunk -= copied_buf;
			} else {
				copied_buf -= chunk;
				continue;
			}
		}
		/*
		 * iov[0] already has virtio header.
		 * and if copied chunk is length of iov_len break
		 */
		if (copied_chunk == total_buf_len) {
			break;
		}
		/*
		 * Sometimes chunk is total mblk len, sometimes mblk is
		 * divided into multiple chunks.
		 */
		if (chunk > copied_buf) {
			if (chunk > copied_chunk) {
				if ((chunk + copied_chunk) > total_buf_len)
					chunk = (size_t)total_buf_len
					    - copied_chunk;
			} else {
				if (chunk > (total_buf_len - copied_chunk))
					chunk = (size_t)((total_buf_len
					    - copied_chunk) - chunk);
			}
			bcopy(ml->b_rptr + copied_buf, buf, chunk);
		} else {
			if (chunk > (total_buf_len - copied_chunk)) {
				chunk = (size_t)(total_buf_len - copied_chunk);
			}
			bcopy(ml->b_rptr + copied_buf, buf, chunk);
		}
		buf += chunk;
		copied_chunk += chunk;
	}
	return (copied_chunk);
}

static void
viona_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	viona_link_t		*link = arg;
	viona_vring_hqueue_t	*hq = &link->l_rx_vring;
	mblk_t			*mp0 = mp;

	while (viona_hq_num_avail(hq)) {
		struct iovec		iov[VTNET_MAXSEGS];
		size_t			mblklen;
		int			n, i = 0;
		uint16_t		cookie;
		struct virtio_net_hdr	*vrx = NULL;
		struct virtio_net_mrgrxhdr *vmrgrx = NULL;
#if notyet
		mblk_t			*ml;
#endif
		caddr_t			buf = NULL;
		int			total_len = 0;
		int			copied_buf = 0;
		int			num_bufs = 0;
		int			num_pops = 0;
		used_elem_t		uelem[VTNET_MAXSEGS];

		if (mp == NULL) {
			break;
		}
		mblklen = msgsize(mp);
		if (mblklen == 0) {
			break;
		}

		mutex_enter(&hq->hq_a_mutex);
		n = vq_popchain(link, hq, iov, VTNET_MAXSEGS, &cookie);
		mutex_exit(&hq->hq_a_mutex);
		if (n <= 0) {
			break;
		}
		num_pops++;
		if (link->l_features & VIRTIO_NET_F_MRG_RXBUF) {
			int total_n = n;
			int mrgrxhdr_size = sizeof (struct virtio_net_mrgrxhdr);
			/*
			 * Get a pointer to the rx header, and use the
			 * data immediately following it for the packet buffer.
			 */
			vmrgrx = (struct virtio_net_mrgrxhdr *)iov[0].iov_base;
			if (n == 1) {
				buf = iov[0].iov_base + mrgrxhdr_size;
			}
			while (mblklen > copied_buf) {
				if (total_n == i) {
					mutex_enter(&hq->hq_a_mutex);
					n = vq_popchain(link, hq, &iov[i],
					    VTNET_MAXSEGS, &cookie);
					mutex_exit(&hq->hq_a_mutex);
					if (n <= 0) {
						freemsgchain(mp0);
						return;
					}
					num_pops++;
					total_n += n;
				}
				if (total_n > i) {
					int copied_chunk = 0;
					if (i != 0) {
						buf = iov[i].iov_base;
					}
					copied_chunk = copy_in_mblk(mp,
					    copied_buf, buf, &iov[i], i,
					    mrgrxhdr_size);
					copied_buf += copied_chunk;
					uelem[i].id = cookie;
					uelem[i].len = copied_chunk;
					if (i == 0) {
						uelem[i].len += mrgrxhdr_size;
					}
				}
				num_bufs++;
				i++;
			}
		} else {
			boolean_t virt_hdr_incl_iov = B_FALSE;
			int rxhdr_size = sizeof (struct virtio_net_hdr);
			/* First element is header */
			vrx = (struct virtio_net_hdr *)iov[0].iov_base;
			if (n == 1 || iov[0].iov_len > rxhdr_size) {
				buf = iov[0].iov_base + rxhdr_size;
				virt_hdr_incl_iov = B_TRUE;
				total_len += rxhdr_size;
				if (iov[0].iov_len < rxhdr_size) {
					// Buff too small to fit pkt. Drop it.
					freemsgchain(mp0);
					return;
				}
			} else {
				total_len = iov[0].iov_len;
			}
			if (iov[0].iov_len == rxhdr_size)
				i++;
			while (mblklen > copied_buf) {
				if (n > i) {
					int copied_chunk = 0;
					if (i != 0) {
						buf = iov[i].iov_base;
					}
					/*
					 * In case of non-mrgrx buf, first
					 * descriptor always has header and
					 * rest of the descriptors have data.
					 * But it is not guaranteed that first
					 * descriptor will only have virtio
					 * header. It might also have data.
					 */
					if (virt_hdr_incl_iov) {
						copied_chunk = copy_in_mblk(mp,
						    copied_buf, buf, &iov[i],
						    i, rxhdr_size);
					} else {
						copied_chunk = copy_in_mblk(mp,
						    copied_buf, buf, &iov[i],
						    i, 0);
					}
					copied_buf += copied_chunk;
					total_len += copied_chunk;
				} else {
					/*
					 * Drop packet as it cant fit
					 * in buf provided by guest.
					 */
					freemsgchain(mp0);
					return;
				}
				i++;
			}
		}
		/*
		 * The only valid field in the rx packet header is the
		 * number of buffers, which is always 1 without TSO
		 * support.
		 */
		if (link->l_features & VIRTIO_NET_F_MRG_RXBUF) {
			memset(vmrgrx, 0, sizeof (struct virtio_net_mrgrxhdr));
			vmrgrx->vrh_bufs = num_bufs;
			/*
			 * Make sure iov[0].iov_len >= MIN_BUF_SIZE
			 * otherwise guest will consider it as invalid frame.
			 */
			if (num_bufs == 1 && uelem[0].len < MIN_BUF_SIZE) {
				uelem[0].len = MIN_BUF_SIZE;
			}
			/*
			 * Release this chain and handle more chains.
			 */
			mutex_enter(&hq->hq_u_mutex);
			vq_pushchain_mrgrx(hq, num_pops, uelem);
			mutex_exit(&hq->hq_u_mutex);
		} else {
			memset(vrx, 0, sizeof (struct virtio_net_hdr));
			if (total_len < MIN_BUF_SIZE) {
				total_len = MIN_BUF_SIZE;
			}
			/*
			 * Release this chain and handle more chains.
			 */
			mutex_enter(&hq->hq_u_mutex);
			vq_pushchain(hq, total_len, cookie);
			mutex_exit(&hq->hq_u_mutex);
		}

		mp = mp->b_next;
	}

	if ((*hq->hq_avail_flags & VRING_AVAIL_F_NO_INTERRUPT) == 0) {
		if (atomic_cas_uint(&link->l_rx_intr, 0, 1) == 0) {
			pollwakeup(&link->l_pollhead, POLLIN);
		}
	}

	freemsgchain(mp0);
}

static void
viona_desb_free(viona_desb_t *dp)
{
	viona_link_t		*link;
	viona_vring_hqueue_t	*hq;
#if notyet
	struct virtio_used	*vu;
	int			uidx;
#endif
	uint_t			ref;

	ref = atomic_dec_uint_nv(&dp->d_ref);
	if (ref != 0)
		return;

	link = dp->d_link;
	hq = &link->l_tx_vring;

	mutex_enter(&hq->hq_u_mutex);
	vq_pushchain(hq, dp->d_len, dp->d_cookie);
	mutex_exit(&hq->hq_u_mutex);

	kmem_cache_free(link->l_desb_kmc, dp);

	if ((*hq->hq_avail_flags & VRING_AVAIL_F_NO_INTERRUPT) == 0) {
		if (atomic_cas_uint(&link->l_tx_intr, 0, 1) == 0) {
			pollwakeup(&link->l_pollhead, POLLOUT);
		}
	}
	if (copy_tx_mblks) {
		mutex_enter(&link->l_tx_mutex);
		if (--link->l_tx_outstanding == 0) {
			cv_broadcast(&link->l_tx_cv);
		}
		mutex_exit(&link->l_tx_mutex);
	}
}

static void
viona_tx(viona_link_t *link, viona_vring_hqueue_t *hq)
{
	struct iovec		iov[VTNET_MAXSEGS];
	uint16_t		cookie;
	int			i, n;
	mblk_t			*mp_head, *mp_tail, *mp;
	viona_desb_t		*dp;
	mac_client_handle_t	link_mch = link->l_mch;

	mp_head = mp_tail = NULL;

	mutex_enter(&hq->hq_a_mutex);
	n = vq_popchain(link, hq, iov, VTNET_MAXSEGS, &cookie);
	mutex_exit(&hq->hq_a_mutex);
	ASSERT(n != 0);

	dp = kmem_cache_alloc(link->l_desb_kmc, KM_SLEEP);
	dp->d_frtn.free_func = viona_desb_free;
	dp->d_frtn.free_arg = (void *)dp;
	dp->d_link = link;
	dp->d_cookie = cookie;

	dp->d_ref = 0;
	dp->d_len = iov[0].iov_len;

	for (i = 1; i < n; i++) {
		dp->d_ref++;
		dp->d_len += iov[i].iov_len;
		if (copy_tx_mblks) {
			mp = desballoc((uchar_t *)iov[i].iov_base,
			    iov[i].iov_len, BPRI_MED, &dp->d_frtn);
			ASSERT(mp);
		} else {
			mp = allocb(iov[i].iov_len, BPRI_MED);
			ASSERT(mp);
			bcopy((uchar_t *)iov[i].iov_base, mp->b_wptr,
			    iov[i].iov_len);
		}
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
	if (copy_tx_mblks == B_FALSE) {
		viona_desb_free(dp);
	}
	if (copy_tx_mblks) {
		mutex_enter(&link->l_tx_mutex);
		link->l_tx_outstanding++;
		mutex_exit(&link->l_tx_mutex);
	}
	mac_tx(link_mch, mp_head, 0, MAC_DROP_ON_NO_DESC, NULL);
}
