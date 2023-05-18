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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/modctl.h>
#include <sys/prom_plat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/ethernet.h>
#include <sys/machsystm.h>
#include <sys/hypervisor_api.h>
#include <sys/mach_descrip.h>
#include <sys/drctl.h>
#include <sys/dr_util.h>
#include <sys/mac.h>
#include <sys/vnet.h>
#include <sys/vnet_mailbox.h>
#include <sys/vnet_common.h>
#include <sys/hsvc.h>


#define	VDDS_MAX_RANGES		6	/* 6 possible VRs */
#define	VDDS_MAX_VRINTRS	8	/* limited to 8 intrs/VR */
#define	VDDS_MAX_INTR_NUM	64	/* 0-63 or valid */

#define	VDDS_INO_RANGE_START(x) (x * VDDS_MAX_VRINTRS)
#define	HVCOOKIE(c)	((c) & 0xFFFFFFFFF)
#define	NIUCFGHDL(c)	((c) >> 32)


/* For "ranges" property */
typedef struct vdds_ranges {
	uint32_t child_hi;
	uint32_t child_lo;
	uint32_t parent_hi;
	uint32_t parent_lo;
	uint32_t size_hi;
	uint32_t size_lo;
} vdds_ranges_t;

/* For "reg" property */
typedef struct vdds_reg {
	uint32_t addr_hi;
	uint32_t addr_lo;
	uint32_t size_hi;
	uint32_t size_lo;
} vdds_reg_t;

/* For ddi callback argument */
typedef struct vdds_cb_arg {
	dev_info_t *dip;
	uint64_t cookie;
	uint64_t macaddr;
	uint32_t max_frame_size;
} vdds_cb_arg_t;


/* Functions exported to other files */
void vdds_mod_init(void);
void vdds_mod_fini(void);
int vdds_init(vnet_t *vnetp);
void vdds_cleanup(vnet_t *vnetp);
void vdds_process_dds_msg(vnet_t *vnetp, vio_dds_msg_t *dmsg);
void vdds_cleanup_hybrid_res(void *arg);
void vdds_cleanup_hio(vnet_t *vnetp);

/* Support functions to create/destory Hybrid device */
static dev_info_t *vdds_create_niu_node(uint64_t cookie,
    uint64_t macaddr, uint32_t max_frame_size);
static int vdds_destroy_niu_node(dev_info_t *niu_dip, uint64_t cookie);
static dev_info_t *vdds_create_new_node(vdds_cb_arg_t *cba,
    dev_info_t *pdip, int (*new_node_func)(dev_info_t *dip,
    void *arg, uint_t flags));
static int vdds_new_nexus_node(dev_info_t *dip, void *arg, uint_t flags);
static int vdds_new_niu_node(dev_info_t *dip, void *arg, uint_t flags);
static dev_info_t *vdds_find_node(uint64_t cookie, dev_info_t *sdip,
	int (*match_func)(dev_info_t *dip, void *arg));
static int vdds_match_niu_nexus(dev_info_t *dip, void *arg);
static int vdds_match_niu_node(dev_info_t *dip, void *arg);
static int vdds_get_interrupts(uint64_t cookie, int ino_range,
    int *intrs, int *nintr);

/* DDS message processing related functions */
static void vdds_process_dds_msg_task(void *arg);
static int vdds_send_dds_resp_msg(vnet_t *vnetp, vio_dds_msg_t *dmsg, int ack);
static int vdds_send_dds_rel_msg(vnet_t *vnetp);
static void vdds_release_range_prop(dev_info_t *nexus_dip, uint64_t cookie);

/* Functions imported from other files */
extern int vnet_send_dds_msg(vnet_t *vnetp, void *dmsg);
extern int vnet_hio_mac_init(vnet_t *vnetp, char *ifname);
extern void vnet_hio_mac_cleanup(vnet_t *vnetp);

/* HV functions that are used in this file */
extern uint64_t vdds_hv_niu_vr_getinfo(uint32_t hvcookie,
    uint64_t *real_start, uint64_t *size);
extern uint64_t vdds_hv_niu_vr_get_txmap(uint32_t hvcookie, uint64_t *dma_map);
extern uint64_t vdds_hv_niu_vr_get_rxmap(uint32_t hvcookie, uint64_t *dma_map);
extern uint64_t vdds_hv_niu_vrtx_set_ino(uint32_t cookie, uint64_t vch_idx,
    uint32_t ino);
extern uint64_t vdds_hv_niu_vrrx_set_ino(uint32_t cookie, uint64_t vch_idx,
    uint32_t ino);


#ifdef DEBUG

#define	DEBUG_PRINTF	debug_printf

extern int vnet_dbglevel;

static void
debug_printf(const char *fname, void *arg,  const char *fmt, ...)
{
	char    buf[512];
	va_list ap;
	char    *bufp = buf;
	vnet_dds_info_t *vdds = arg;

	if (vdds != NULL) {
		(void) sprintf(bufp, "vnet%d: %s: ",
		    vdds->vnetp->instance, fname);
	} else {
		(void) sprintf(bufp, "%s: ", fname);
	}
	bufp += strlen(bufp);
	va_start(ap, fmt);
	(void) vsprintf(bufp, fmt, ap);
	va_end(ap);
	cmn_err(CE_CONT, "%s\n", buf);
}
#endif

/*
 * Hypervisor N2/NIU services information:
 *
 * The list of HV versions that support NIU HybridIO. Note,
 * the order is higher version to a lower version, as the
 * registration is attempted in this order.
 */
static hsvc_info_t niu_hsvc[] = {
	{HSVC_REV_1, NULL, HSVC_GROUP_NIU, 2, 0, "vnet_dds"},
	{HSVC_REV_1, NULL, HSVC_GROUP_NIU, 1, 1, "vnet_dds"}
};

/*
 * Index that points to the successful HV version that
 * is registered.
 */
static int niu_hsvc_index = -1;

/*
 * Lock to serialize the NIU device node related operations.
 */
kmutex_t vdds_dev_lock;

boolean_t vdds_hv_hio_capable = B_FALSE;

/*
 * vdds_mod_init -- one time initialization.
 */
void
vdds_mod_init(void)
{
	int i;
	int rv;
	uint64_t minor = 0;

	/*
	 * Try register one by one from niu_hsvc.
	 */
	for (i = 0; i < (sizeof (niu_hsvc) / sizeof (hsvc_info_t)); i++) {
		rv = hsvc_register(&niu_hsvc[i], &minor);
		if (rv == 0) {
			if (minor == niu_hsvc[i].hsvc_minor) {
				vdds_hv_hio_capable = B_TRUE;
				niu_hsvc_index = i;
				break;
			} else {
				(void) hsvc_unregister(&niu_hsvc[i]);
			}
		}
	}
	mutex_init(&vdds_dev_lock, NULL, MUTEX_DRIVER, NULL);
	DBG2(NULL, "HV HIO capable=%d ver(%ld.%ld)", vdds_hv_hio_capable,
	    (niu_hsvc_index == -1) ? 0 : niu_hsvc[niu_hsvc_index].hsvc_major,
	    minor);
}

/*
 * vdds_mod_fini -- one time cleanup.
 */
void
vdds_mod_fini(void)
{
	if (niu_hsvc_index != -1) {
		(void) hsvc_unregister(&niu_hsvc[niu_hsvc_index]);
	}
	mutex_destroy(&vdds_dev_lock);
}

/*
 * vdds_init -- vnet instance related DDS related initialization.
 */
int
vdds_init(vnet_t *vnetp)
{
	vnet_dds_info_t *vdds = &vnetp->vdds_info;
	char		qname[TASKQ_NAMELEN];

	vdds->vnetp = vnetp;
	DBG1(vdds, "Initializing..");
	(void) snprintf(qname, TASKQ_NAMELEN, "vdds_taskq%d", vnetp->instance);
	if ((vdds->dds_taskqp = ddi_taskq_create(vnetp->dip, qname, 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		cmn_err(CE_WARN, "!vnet%d: Unable to create DDS task queue",
		    vnetp->instance);
		return (ENOMEM);
	}
	mutex_init(&vdds->lock, NULL, MUTEX_DRIVER, NULL);
	return (0);
}

/*
 * vdds_cleanup -- vnet instance related cleanup.
 */
void
vdds_cleanup(vnet_t *vnetp)
{
	vnet_dds_info_t *vdds = &vnetp->vdds_info;

	DBG1(vdds, "Cleanup...");
	/* Cleanup/destroy any hybrid resouce that exists */
	vdds_cleanup_hybrid_res(vnetp);

	/* taskq_destroy will wait for all taskqs to complete */
	ddi_taskq_destroy(vdds->dds_taskqp);
	vdds->dds_taskqp = NULL;
	mutex_destroy(&vdds->lock);
	DBG1(vdds, "Cleanup complete");
}

/*
 * vdds_cleanup_hybrid_res -- Cleanup Hybrid resource.
 */
void
vdds_cleanup_hybrid_res(void *arg)
{
	vnet_t *vnetp = arg;
	vnet_dds_info_t *vdds = &vnetp->vdds_info;

	DBG1(vdds, "Hybrid device cleanup...");
	mutex_enter(&vdds->lock);
	if (vdds->task_flags == VNET_DDS_TASK_ADD_SHARE) {
		/*
		 * Task for ADD_SHARE is pending, simply
		 * cleanup the flags, the task will quit without
		 * any changes.
		 */
		vdds->task_flags = 0;
		DBG2(vdds, "Task for ADD is pending, clean flags only");
	} else if ((vdds->hio_dip != NULL) && (vdds->task_flags == 0)) {
		/*
		 * There is no task pending and a hybrid device
		 * is present, so dispatch a task to release the share.
		 */
		vdds->task_flags = VNET_DDS_TASK_REL_SHARE;
		(void) ddi_taskq_dispatch(vdds->dds_taskqp,
		    vdds_process_dds_msg_task, vnetp, DDI_NOSLEEP);
		DBG2(vdds, "Dispatched a task to destroy HIO device");
	}
	/*
	 * Other possible cases include either DEL_SHARE or
	 * REL_SHARE as pending. In that case, there is nothing
	 * to do as a task is already pending to do the cleanup.
	 */
	mutex_exit(&vdds->lock);
	DBG1(vdds, "Hybrid device cleanup complete");
}

/*
 * vdds_cleanup_hio -- An interface to cleanup the hio resources before
 *	resetting the vswitch port.
 */
void
vdds_cleanup_hio(vnet_t *vnetp)
{
	vnet_dds_info_t *vdds = &vnetp->vdds_info;

	/* Wait for any pending vdds tasks to complete */
	ddi_taskq_wait(vdds->dds_taskqp);
	vdds_cleanup_hybrid_res(vnetp);
	/* Wait for the cleanup task to complete */
	ddi_taskq_wait(vdds->dds_taskqp);
}

/*
 * vdds_process_dds_msg -- Process a DDS message.
 */
void
vdds_process_dds_msg(vnet_t *vnetp, vio_dds_msg_t *dmsg)
{
	vnet_dds_info_t *vdds = &vnetp->vdds_info;
	int rv;

	DBG1(vdds, "DDS message received...");

	if (dmsg->dds_class != DDS_VNET_NIU) {
		DBG2(vdds, "Invalid class send NACK");
		(void) vdds_send_dds_resp_msg(vnetp, dmsg, B_FALSE);
		return;
	}
	mutex_enter(&vdds->lock);
	switch (dmsg->dds_subclass) {
	case DDS_VNET_ADD_SHARE:
		DBG2(vdds, "DDS_VNET_ADD_SHARE message...");
		if ((vdds->task_flags != 0) || (vdds->hio_dip != NULL)) {
			/*
			 * Either a task is already pending or
			 * a hybrid device already exists.
			 */
			DWARN(vdds, "NACK: Already pending DDS task");
			(void) vdds_send_dds_resp_msg(vnetp, dmsg, B_FALSE);
			mutex_exit(&vdds->lock);
			return;
		}
		vdds->task_flags = VNET_DDS_TASK_ADD_SHARE;
		bcopy(dmsg, &vnetp->vdds_info.dmsg, sizeof (vio_dds_msg_t));
		DBG2(vdds, "Dispatching task for ADD_SHARE");
		rv = ddi_taskq_dispatch(vdds->dds_taskqp,
		    vdds_process_dds_msg_task, vnetp, DDI_NOSLEEP);
		if (rv != 0) {
			/* Send NACK */
			DBG2(vdds, "NACK: Failed to dispatch task");
			(void) vdds_send_dds_resp_msg(vnetp, dmsg, B_FALSE);
			vdds->task_flags = 0;
		}
		break;

	case DDS_VNET_DEL_SHARE:
		DBG2(vdds, "DDS_VNET_DEL_SHARE message...");
		if (vdds->task_flags == VNET_DDS_TASK_ADD_SHARE) {
			/*
			 * ADD_SHARE task still pending, simply clear
			 * task falgs and ACK.
			 */
			DBG2(vdds, "ACK:ADD_SHARE task still pending");
			vdds->task_flags = 0;
			(void) vdds_send_dds_resp_msg(vnetp, dmsg, B_TRUE);
			mutex_exit(&vdds->lock);
			return;
		}
		if ((vdds->task_flags == 0) && (vdds->hio_dip == NULL)) {
			/* Send NACK */
			DBG2(vdds, "NACK:No HIO device exists");
			(void) vdds_send_dds_resp_msg(vnetp, dmsg, B_FALSE);
			mutex_exit(&vdds->lock);
			return;
		}
		vdds->task_flags = VNET_DDS_TASK_DEL_SHARE;
		bcopy(dmsg, &vdds->dmsg, sizeof (vio_dds_msg_t));
		DBG2(vdds, "Dispatching DEL_SHARE task");
		rv = ddi_taskq_dispatch(vdds->dds_taskqp,
		    vdds_process_dds_msg_task, vnetp, DDI_NOSLEEP);
		if (rv != 0) {
			/* Send NACK */
			DBG2(vdds, "NACK: failed to dispatch task");
			(void) vdds_send_dds_resp_msg(vnetp, dmsg, B_FALSE);
			vdds->task_flags = 0;
		}
		break;
	case DDS_VNET_REL_SHARE:
		DBG2(vdds, "Reply for REL_SHARE reply=%d",
		    dmsg->tag.vio_subtype);
		break;
	default:
		DWARN(vdds, "Discarding Unknown DDS message");
		break;
	}
	mutex_exit(&vdds->lock);
}

/*
 * vdds_process_dds_msg_task -- Called from a taskq to process the
 *	DDS message.
 */
static void
vdds_process_dds_msg_task(void *arg)
{
	vnet_t		*vnetp = arg;
	vnet_dds_info_t	*vdds = &vnetp->vdds_info;
	vio_dds_msg_t	*dmsg = &vdds->dmsg;
	dev_info_t	*dip;
	uint32_t	max_frame_size;
	uint64_t	hio_cookie;
	int		rv;

	DBG1(vdds, "DDS task started...");
	mutex_enter(&vdds->lock);
	switch (vdds->task_flags) {
	case VNET_DDS_TASK_ADD_SHARE:
		DBG2(vdds, "ADD_SHARE task...");
		hio_cookie = dmsg->msg.share_msg.cookie;
		/*
		 * max-frame-size value need to be set to
		 * the full ethernet frame size. That is,
		 * header + payload + checksum.
		 */
		max_frame_size = vnetp->mtu +
		    sizeof (struct  ether_vlan_header) + ETHERFCSL;
		dip = vdds_create_niu_node(hio_cookie,
		    dmsg->msg.share_msg.macaddr, max_frame_size);
		if (dip == NULL) {
			(void) vdds_send_dds_resp_msg(vnetp, dmsg, B_FALSE);
			DERR(vdds, "Failed to create HIO node");
		} else {
			vdds->hio_dip = dip;
			vdds->hio_cookie = hio_cookie;
			(void) snprintf(vdds->hio_ifname,
			    sizeof (vdds->hio_ifname), "%s%d",
			    ddi_driver_name(dip), ddi_get_instance(dip));

			rv = vnet_hio_mac_init(vnetp, vdds->hio_ifname);
			if (rv != 0) {
				/* failed - cleanup, send failed DDS message */
				DERR(vdds, "HIO mac init failed, cleaning up");
				rv = vdds_destroy_niu_node(dip, hio_cookie);
				if (rv == 0) {
					/* use DERR to print by default */
					DERR(vdds, "Successfully destroyed"
					    " Hybrid node");
				} else {
					cmn_err(CE_WARN, "vnet%d:Failed to "
					    "destroy Hybrid node",
					    vnetp->instance);
				}
				vdds->hio_dip = NULL;
				vdds->hio_cookie = 0;
				(void) vdds_send_dds_resp_msg(vnetp,
				    dmsg, B_FALSE);
			} else {
				(void) vdds_send_dds_resp_msg(vnetp,
				    dmsg, B_TRUE);
			}
			/* DERR used only print by default */
			DERR(vdds, "Successfully created HIO node");
		}
		break;

	case VNET_DDS_TASK_DEL_SHARE:
		DBG2(vdds, "DEL_SHARE task...");
		if (vnetp->vdds_info.hio_dip == NULL) {
			DBG2(vdds, "NACK: No HIO device destroy");
			(void) vdds_send_dds_resp_msg(vnetp, dmsg, B_FALSE);
		} else {
			vnet_hio_mac_cleanup(vnetp);
			rv = vdds_destroy_niu_node(vnetp->vdds_info.hio_dip,
			    vdds->hio_cookie);
			if (rv == 0) {
				/* use DERR to print by default */
				DERR(vdds, "Successfully destroyed"
				    " Hybrid node");
			} else {
				cmn_err(CE_WARN, "vnet%d:Failed to "
				    "destroy Hybrid node", vnetp->instance);
			}
			/* TODO: send ACK even for failure? */
			DBG2(vdds, "ACK: HIO device destroyed");
			(void) vdds_send_dds_resp_msg(vnetp, dmsg, B_TRUE);
			vdds->hio_dip = 0;
			vdds->hio_cookie = 0;
		}
		break;
	case VNET_DDS_TASK_REL_SHARE:
		DBG2(vdds, "REL_SHARE task...");
		if (vnetp->vdds_info.hio_dip != NULL) {
			vnet_hio_mac_cleanup(vnetp);
			rv = vdds_destroy_niu_node(vnetp->vdds_info.hio_dip,
			    vdds->hio_cookie);
			if (rv == 0) {
				DERR(vdds, "Successfully destroyed "
				    "Hybrid node");
			} else {
				cmn_err(CE_WARN, "vnet%d:Failed to "
				    "destroy HIO node", vnetp->instance);
			}
			/* TODO: failure case */
			(void) vdds_send_dds_rel_msg(vnetp);
			vdds->hio_dip = 0;
			vdds->hio_cookie = 0;
		}
		break;
	default:
		break;
	}
	vdds->task_flags = 0;
	mutex_exit(&vdds->lock);
}

/*
 * vdds_send_dds_rel_msg -- Send a DDS_REL_SHARE message.
 */
static int
vdds_send_dds_rel_msg(vnet_t *vnetp)
{
	vnet_dds_info_t *vdds = &vnetp->vdds_info;
	vio_dds_msg_t	vmsg;
	dds_share_msg_t	*smsg = &vmsg.msg.share_msg;
	int rv;

	DBG1(vdds, "Sending DDS_VNET_REL_SHARE message");
	vmsg.tag.vio_msgtype = VIO_TYPE_CTRL;
	vmsg.tag.vio_subtype = VIO_SUBTYPE_INFO;
	vmsg.tag.vio_subtype_env = VIO_DDS_INFO;
	/* vio_sid filled by the LDC module */
	vmsg.dds_class = DDS_VNET_NIU;
	vmsg.dds_subclass = DDS_VNET_REL_SHARE;
	vmsg.dds_req_id = (++vdds->dds_req_id);
	smsg->macaddr = vnet_macaddr_strtoul(vnetp->curr_macaddr);
	smsg->cookie = vdds->hio_cookie;
	rv = vnet_send_dds_msg(vnetp, &vmsg);
	return (rv);
}

/*
 * vdds_send_dds_resp_msg -- Send a DDS response message.
 */
static int
vdds_send_dds_resp_msg(vnet_t *vnetp, vio_dds_msg_t *dmsg, int ack)
{
	vnet_dds_info_t *vdds = &vnetp->vdds_info;
	int rv;

	DBG1(vdds, "Sending a response mesage=%d", ack);
	if (ack == B_TRUE) {
		dmsg->tag.vio_subtype = VIO_SUBTYPE_ACK;
		dmsg->msg.share_resp_msg.status = DDS_VNET_SUCCESS;
	} else {
		dmsg->tag.vio_subtype = VIO_SUBTYPE_NACK;
		dmsg->msg.share_resp_msg.status = DDS_VNET_FAIL;
	}
	rv = vnet_send_dds_msg(vnetp, dmsg);
	return (rv);
}

/*
 * vdds_create_niu_node -- Create NIU Hybrid node. The NIU nexus
 *	node also created if it doesn't exist already.
 */
dev_info_t *
vdds_create_niu_node(uint64_t cookie, uint64_t macaddr, uint32_t max_frame_size)
{
	dev_info_t *nexus_dip;
	dev_info_t *niu_dip;
	vdds_cb_arg_t cba;

	DBG1(NULL, "Called");

	if (vdds_hv_hio_capable == B_FALSE) {
		return (NULL);
	}
	mutex_enter(&vdds_dev_lock);
	/* Check if the nexus node exists already */
	nexus_dip = vdds_find_node(cookie, ddi_root_node(),
	    vdds_match_niu_nexus);
	if (nexus_dip == NULL) {
		/*
		 * NIU nexus node not found, so create it now.
		 */
		cba.dip = NULL;
		cba.cookie = cookie;
		cba.macaddr = macaddr;
		cba.max_frame_size = max_frame_size;
		nexus_dip = vdds_create_new_node(&cba, NULL,
		    vdds_new_nexus_node);
		if (nexus_dip == NULL) {
			mutex_exit(&vdds_dev_lock);
			return (NULL);
		}
	}
	DBG2(NULL, "nexus_dip = 0x%p", nexus_dip);

	/* Check if NIU node exists already before creating one */
	niu_dip = vdds_find_node(cookie, nexus_dip,
	    vdds_match_niu_node);
	if (niu_dip == NULL) {
		cba.dip = NULL;
		cba.cookie = cookie;
		cba.macaddr = macaddr;
		cba.max_frame_size = max_frame_size;
		niu_dip = vdds_create_new_node(&cba, nexus_dip,
		    vdds_new_niu_node);
		/*
		 * Hold the niu_dip to prevent it from
		 * detaching.
		 */
		if (niu_dip != NULL) {
			e_ddi_hold_devi(niu_dip);
		} else {
			DWARN(NULL, "niumx/network node creation failed");
		}
	} else {
		DWARN(NULL, "niumx/network node already exists(dip=0x%p)",
		    niu_dip);
	}
	/* release the hold that was done in find/create */
	if ((niu_dip != NULL) && (e_ddi_branch_held(niu_dip)))
		e_ddi_branch_rele(niu_dip);
	if (e_ddi_branch_held(nexus_dip))
		e_ddi_branch_rele(nexus_dip);
	mutex_exit(&vdds_dev_lock);
	DBG1(NULL, "returning niu_dip=0x%p", niu_dip);
	return (niu_dip);
}

/*
 * vdds_destroy_niu_node -- Destroy the NIU node.
 */
int
vdds_destroy_niu_node(dev_info_t *niu_dip, uint64_t cookie)
{
	int rv;
	dev_info_t *fdip = NULL;
	dev_info_t *nexus_dip = ddi_get_parent(niu_dip);


	DBG1(NULL, "Called");
	ASSERT(nexus_dip != NULL);
	mutex_enter(&vdds_dev_lock);

	if (!e_ddi_branch_held(niu_dip))
		e_ddi_branch_hold(niu_dip);
	/*
	 * As we are destroying now, release the
	 * hold that was done in during the creation.
	 */
	ddi_release_devi(niu_dip);
	rv = e_ddi_branch_destroy(niu_dip, &fdip, 0);
	if (rv != 0) {
		DERR(NULL, "Failed to destroy niumx/network node dip=0x%p",
		    niu_dip);
		if (fdip != NULL) {
			ddi_release_devi(fdip);
		}
		rv = EBUSY;
		goto dest_exit;
	}
	/*
	 * Cleanup the parent's ranges property set
	 * for this Hybrid device.
	 */
	vdds_release_range_prop(nexus_dip, cookie);

dest_exit:
	mutex_exit(&vdds_dev_lock);
	DBG1(NULL, "returning rv=%d", rv);
	return (rv);
}

/*
 * vdds_match_niu_nexus -- callback function to verify a node is the
 *	NIU nexus node.
 */
static int
vdds_match_niu_nexus(dev_info_t *dip, void *arg)
{
	vdds_cb_arg_t	*warg = (vdds_cb_arg_t *)arg;
	vdds_reg_t	*reg_p;
	char		*name;
	uint64_t	hdl;
	uint_t		reglen;
	int		rv;

	if (dip == ddi_root_node()) {
		return (DDI_WALK_CONTINUE);
	}

	name = ddi_node_name(dip);
	if (strcmp(name, "niu")  != 0) {
		return (DDI_WALK_CONTINUE);
	}
	rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&reg_p, &reglen);
	if (rv != DDI_PROP_SUCCESS) {
		DWARN(NULL, "Failed to get reg property dip=0x%p", dip);
		return (DDI_WALK_CONTINUE);
	}

	hdl =  reg_p->addr_hi & 0x0FFFFFFF;
	ddi_prop_free(reg_p);

	DBG2(NULL, "Handle = 0x%lx dip=0x%p", hdl, dip);
	if (hdl == NIUCFGHDL(warg->cookie)) {
		/* Hold before returning */
		if (!e_ddi_branch_held(dip))
			e_ddi_branch_hold(dip);
		warg->dip = dip;
		DBG2(NULL, "Found dip = 0x%p", dip);
		return (DDI_WALK_TERMINATE);
	}
	return (DDI_WALK_CONTINUE);
}

/*
 * vdds_match_niu_node -- callback function to verify a node is the
 *	NIU Hybrid node.
 */
static int
vdds_match_niu_node(dev_info_t *dip, void *arg)
{
	vdds_cb_arg_t	*warg = (vdds_cb_arg_t *)arg;
	char		*name;
	vdds_reg_t	*reg_p;
	uint_t		reglen;
	int		rv;
	uint32_t	addr_hi;

	name = ddi_node_name(dip);
	if (strcmp(name, "network")  != 0) {
		return (DDI_WALK_CONTINUE);
	}
	rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&reg_p, &reglen);
	if (rv != DDI_PROP_SUCCESS) {
		DWARN(NULL, "Failed to get reg property dip=0x%p", dip);
		return (DDI_WALK_CONTINUE);
	}

	addr_hi = reg_p->addr_hi;
	DBG1(NULL, "addr_hi = 0x%x dip=0x%p", addr_hi, dip);
	ddi_prop_free(reg_p);
	if (addr_hi == HVCOOKIE(warg->cookie)) {
		warg->dip = dip;
		if (!e_ddi_branch_held(dip))
			e_ddi_branch_hold(dip);
		DBG1(NULL, "Found dip = 0x%p", dip);
		return (DDI_WALK_TERMINATE);
	}
	return (DDI_WALK_CONTINUE);
}

/*
 * vdds_new_nexus_node -- callback function to set all the properties
 *	a new NIU nexus node.
 */
static int
vdds_new_nexus_node(dev_info_t *dip, void *arg, uint_t flags)
{
	vdds_cb_arg_t	*cba = (vdds_cb_arg_t *)arg;
	char		*compat[] = { "SUNW,niumx" };
	vdds_ranges_t	*rangesp;
	vdds_reg_t	reg;
	uint64_t	nranges;
	int		n;

	DBG1(NULL, "Called dip=0x%p, flags=0x%X", dip, flags);

	/* create "niu" property */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip, "name", "niu") !=
	    DDI_SUCCESS) {
		DERR(NULL, "Failed to create name property(dip=0x%p)", dip);
		return (DDI_WALK_ERROR);
	}

	/* create "compatible" property */
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, dip, "compatible",
	    compat, 1) != DDI_SUCCESS) {
		DERR(NULL, "Failed to create compatible property(dip=0x%p)",
		    dip);
		return (DDI_WALK_ERROR);
	}

	/* create "device_type" property */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "device_type", "sun4v") != DDI_SUCCESS) {
		DERR(NULL, "Failed to create device_type property(dip=0x%p)",
		    dip);
		return (DDI_WALK_ERROR);
	}

	/*
	 * create "reg" property. The first 28 bits of
	 * 'addr_hi'  are NIU cfg_handle, the 0xc in 28-31 bits
	 * indicates non-cacheable config.
	 */
	reg.addr_hi = 0xc0000000 | NIUCFGHDL(cba->cookie);
	reg.addr_lo = 0;
	reg.size_hi = 0;
	reg.size_lo = 0;
	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "reg", (int *)&reg, sizeof (reg)/sizeof (int)) != DDI_SUCCESS) {
		DERR(NULL, "Failed to create reg property(dip=0x%p)", dip);
		return (DDI_WALK_ERROR);
	}

	/*
	 * Create VDDS_MAX_RANGES so that they are already in place
	 * before the children are created. While creating the child
	 * we just modify one of this ranges entries.
	 */
	nranges = VDDS_MAX_RANGES;  /* One range for each VR */
	rangesp = (vdds_ranges_t *)kmem_zalloc(
	    (sizeof (vdds_ranges_t) * nranges), KM_SLEEP);

	for (n = 0; n < nranges; n++) {
		/* zero all child_hi/lo */
		rangesp[n].child_hi = 0;
		rangesp[n].child_lo = 0;
	}

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "ranges",
	    (int *)rangesp, (nranges * 6)) != DDI_SUCCESS) {
		DERR(NULL, "Failed to create ranges property(dip=0x%p)", dip);
		kmem_free(rangesp, (sizeof (vdds_ranges_t) * nranges));
		return (DDI_WALK_ERROR);
	}

	/* create "#size-cells" property */
	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 2) != DDI_SUCCESS) {
		DERR(NULL, "Failed to create #size-cells property(dip=0x%p)",
		    dip);
		kmem_free(rangesp, (sizeof (vdds_ranges_t) * nranges));
		return (DDI_WALK_ERROR);
	}

	/* create "#address-cells" property */
	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 2) != DDI_SUCCESS) {
		DERR(NULL, "Failed to create #address-cells prop(dip=0x%p)",
		    dip);
		kmem_free(rangesp, (sizeof (vdds_ranges_t) * nranges));
		return (DDI_WALK_ERROR);
	}

	kmem_free(rangesp, (sizeof (vdds_ranges_t) * nranges));
	cba->dip = dip;
	DBG1(NULL, "Returning (dip=0x%p)", dip);
	return (DDI_WALK_TERMINATE);
}

/*
 * vdds_new_niu_node -- callback function to create a new NIU Hybrid node.
 */
static int
vdds_new_niu_node(dev_info_t *dip, void *arg, uint_t flags)
{
	vdds_cb_arg_t *cba = (vdds_cb_arg_t *)arg;
	char *compat[] = { "SUNW,niusl" };
	uint8_t macaddrbytes[ETHERADDRL];
	int interrupts[VDDS_MAX_VRINTRS];
	vdds_ranges_t	*prng;
	vdds_ranges_t	*prp;
	vdds_reg_t	reg;
	dev_info_t	*pdip;
	uint64_t	start;
	uint64_t	size;
	int		prnglen;
	int		nintr = 0;
	int		nrng;
	int		rnum;
	int		rv;

	DBG1(NULL, "Called dip=0x%p flags=0x%X", dip, flags);
	pdip = ddi_get_parent(dip);

	if (pdip == NULL) {
		DWARN(NULL, "Failed to get parent dip(dip=0x%p)", dip);
		return (DDI_WALK_ERROR);
	}

	/* create "network" property */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip, "name", "network") !=
	    DDI_SUCCESS) {
		DERR(NULL, "Failed to create name property(dip=0x%p)", dip);
		return (DDI_WALK_ERROR);
	}

	/*
	 * create "niutype" property, it is set to n2niu to
	 * indicate NIU Hybrid node.
	 */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip, "niutype",
	    "n2niu") != DDI_SUCCESS) {
		DERR(NULL, "Failed to create niuopmode property(dip=0x%p)",
		    dip);
		return (DDI_WALK_ERROR);
	}

	/* create "compatible" property */
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, dip, "compatible",
	    compat, 1) != DDI_SUCCESS) {
		DERR(NULL, "Failed to create compatible property(dip=0x%p)",
		    dip);
		return (DDI_WALK_ERROR);
	}

	/* create "device_type" property */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "device_type", "network") != DDI_SUCCESS) {
		DERR(NULL, "Failed to create device_type property(dip=0x%p)",
		    dip);
		return (DDI_WALK_ERROR);
	}

	/* create "reg" property */
	if (vdds_hv_niu_vr_getinfo(HVCOOKIE(cba->cookie),
	    &start, &size) != H_EOK) {
		DERR(NULL, "Failed to get vrinfo for cookie(0x%lX)",
		    cba->cookie);
			return (DDI_WALK_ERROR);
	}
	reg.addr_hi = HVCOOKIE(cba->cookie);
	reg.addr_lo = 0;
	reg.size_hi = 0;
	reg.size_lo = size;

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "reg",
	    (int *)&reg, sizeof (reg) / sizeof (int)) != DDI_SUCCESS) {
		DERR(NULL, "Failed to create reg property(dip=0x%p)", dip);
		return (DDI_WALK_ERROR);
	}

	/*
	 * Modify the parent's ranges property to map the "reg" property
	 * of the new child.
	 */
	if ((rv = ddi_getlongprop(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS,
	    "ranges", (caddr_t)&prng, &prnglen)) != DDI_SUCCESS) {
		DERR(NULL,
		    "Failed to get parent's ranges property(pdip=0x%p) rv=%d",
		    pdip, rv);
		return (DDI_WALK_ERROR);
	}
	nrng = prnglen/(sizeof (vdds_ranges_t));
	/*
	 * First scan all ranges to see if a range corresponding
	 * to this virtual NIU exists already.
	 */
	for (rnum = 0; rnum < nrng; rnum++) {
		prp = &prng[rnum];
		if (prp->child_hi == HVCOOKIE(cba->cookie)) {
			break;
		}
	}
	if (rnum == nrng) {
		/* Now to try to find an empty range */
		for (rnum = 0; rnum < nrng; rnum++) {
			prp = &prng[rnum];
			if (prp->child_hi == 0) {
				break;
			}
		}
	}
	if (rnum == nrng) {
		DERR(NULL, "No free ranges entry found");
		return (DDI_WALK_ERROR);
	}

	/*
	 * child_hi will have HV cookie as HV cookie is more like
	 * a port in the HybridIO.
	 */
	prp->child_hi = HVCOOKIE(cba->cookie);
	prp->child_lo = 0;
	prp->parent_hi = 0x80000000 | (start >> 32);
	prp->parent_lo = start & 0x00000000FFFFFFFF;
	prp->size_hi = (size >> 32);
	prp->size_lo = size & 0x00000000FFFFFFFF;

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, pdip, "ranges",
	    (int *)prng, (nrng * 6)) != DDI_SUCCESS) {
		DERR(NULL, "Failed to update parent ranges prop(pdip=0x%p)",
		    pdip);
		return (DDI_WALK_ERROR);
	}
	kmem_free((void *)prng, prnglen);

	vnet_macaddr_ultostr(cba->macaddr, macaddrbytes);

	/*
	 * create "local-mac-address" property, this will be same as
	 * the vnet's mac-address.
	 */
	if (ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip, "local-mac-address",
	    macaddrbytes, ETHERADDRL) != DDI_SUCCESS) {
		DERR(NULL, "Failed to update mac-addresses property(dip=0x%p)",
		    dip);
		return (DDI_WALK_ERROR);
	}

	rv = vdds_get_interrupts(cba->cookie, rnum, interrupts, &nintr);
	if (rv != 0) {
		DERR(NULL, "Failed to get interrupts for cookie=0x%lx",
		    cba->cookie);
		return (DDI_WALK_ERROR);
	}

	/* create "interrupts" property */
	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "interrupts",
	    interrupts, nintr) != DDI_SUCCESS) {
		DERR(NULL, "Failed to update interrupts property(dip=0x%p)",
		    dip);
		return (DDI_WALK_ERROR);
	}


	/* create "max_frame_size" property */
	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip, "max-frame-size",
	    cba->max_frame_size) != DDI_SUCCESS) {
		DERR(NULL, "Failed to update max-frame-size property(dip=0x%p)",
		    dip);
		return (DDI_WALK_ERROR);
	}

	cba->dip = dip;
	DBG1(NULL, "Returning dip=0x%p", dip);
	return (DDI_WALK_TERMINATE);
}


/*
 * vdds_find_node -- A common function to find a NIU nexus or NIU node.
 */
static dev_info_t *
vdds_find_node(uint64_t cookie, dev_info_t *sdip,
    int (*match_func)(dev_info_t *dip, void *arg))
{
	vdds_cb_arg_t arg;
	dev_info_t *pdip;

	DBG1(NULL, "Called cookie=%lx\n", cookie);

	arg.dip = NULL;
	arg.cookie = cookie;

	if (pdip = ddi_get_parent(sdip)) {
		ndi_devi_enter(pdip);
	}

	ddi_walk_devs(sdip, match_func, (void *)&arg);
	if (pdip != NULL) {
		ndi_devi_exit(pdip);
	}

	DBG1(NULL, "Returning dip=0x%p", arg.dip);
	return (arg.dip);
}

/*
 * vdds_create_new_node -- A common function to create NIU nexus/NIU node.
 */
static dev_info_t *
vdds_create_new_node(vdds_cb_arg_t *cbap, dev_info_t *pdip,
    int (*new_node_func)(dev_info_t *dip, void *arg, uint_t flags))
{
	devi_branch_t br;
	int rv;

	DBG1(NULL, "Called cookie=0x%lx", cbap->cookie);

	br.arg = (void *)cbap;
	br.type = DEVI_BRANCH_SID;
	br.create.sid_branch_create = new_node_func;
	br.devi_branch_callback = NULL;

	if (pdip == NULL) {
		pdip = ddi_root_node();
	}
	DBG1(NULL, "calling e_ddi_branch_create");
	if ((rv = e_ddi_branch_create(pdip, &br, NULL,
	    DEVI_BRANCH_CHILD | DEVI_BRANCH_CONFIGURE))) {
		DERR(NULL, "e_ddi_branch_create failed=%d", rv);
		return (NULL);
	}
	DBG1(NULL, "Returning(dip=0x%p", cbap->dip);
	return (cbap->dip);
}

/*
 * vdds_get_interrupts -- A function that binds ino's to channels and
 *	then provides them to create interrupts property.
 */
static int
vdds_get_interrupts(uint64_t cookie, int ino_range, int *intrs, int *nintr)
{
	uint32_t hvcookie = HVCOOKIE(cookie);
	uint64_t txmap;
	uint64_t rxmap;
	uint32_t ino = VDDS_INO_RANGE_START(ino_range);
	int rv;
	uint64_t i;

	*nintr = 0;
	rv = vdds_hv_niu_vr_get_txmap(hvcookie, &txmap);
	if (rv != H_EOK) {
		DWARN(NULL, "Failed to get txmap for hvcookie=0x%X rv=%d\n",
		    hvcookie, rv);
		return (EIO);
	}
	rv = vdds_hv_niu_vr_get_rxmap(hvcookie, &rxmap);
	if (rv != H_EOK) {
		DWARN(NULL, "Failed to get rxmap for hvcookie=0x%X, rv=%d\n",
		    hvcookie, rv);
		return (EIO);
	}
	/* Check if the number of total channels to be more than 8 */
	for (i = 0; i < 4; i++) {
		if (rxmap & (((uint64_t)0x1) << i)) {
			rv = vdds_hv_niu_vrrx_set_ino(hvcookie, i, ino);
			if (rv != H_EOK) {
				DWARN(NULL, "Failed to get Rx ino for "
				    "hvcookie=0x%X vch_idx=0x%lx rv=%d\n",
				    hvcookie, i, rv);
				return (EIO);
			}
			DWARN(NULL,
			    "hvcookie=0x%X RX vch_idx=0x%lx ino=0x%X\n",
			    hvcookie, i, ino);
			*intrs = ino;
			ino++;
		} else {
			*intrs = VDDS_MAX_INTR_NUM;
		}
		intrs++;
		*nintr += 1;
	}
	for (i = 0; i < 4; i++) {
		if (txmap & (((uint64_t)0x1) << i)) {
			rv = vdds_hv_niu_vrtx_set_ino(hvcookie, i, ino);
			if (rv != H_EOK) {
				DWARN(NULL, "Failed to get Tx ino for "
				    "hvcookie=0x%X vch_idx=0x%lx rv=%d\n",
				    hvcookie, i, rv);
				return (EIO);
			}
			DWARN(NULL, "hvcookie=0x%X TX vch_idx=0x%lx ino=0x%X\n",
			    hvcookie, i, ino);
			*intrs = ino;
			ino++;
		} else {
			*intrs = VDDS_MAX_INTR_NUM;
		}
		intrs++;
		*nintr += 1;
	}
	return (0);
}

/*
 * vdds_release_range_prop -- cleanups an entry in the ranges property
 *	corresponding to a cookie.
 */
static void
vdds_release_range_prop(dev_info_t *nexus_dip, uint64_t cookie)
{
	vdds_ranges_t *prng;
	vdds_ranges_t *prp;
	int prnglen;
	int nrng;
	int rnum;
	boolean_t success = B_FALSE;
	int rv;

	if ((rv = ddi_getlongprop(DDI_DEV_T_ANY, nexus_dip, DDI_PROP_DONTPASS,
	    "ranges", (caddr_t)&prng, &prnglen)) != DDI_SUCCESS) {
		DERR(NULL,
		    "Failed to get nexus ranges property(dip=0x%p) rv=%d",
		    nexus_dip, rv);
		return;
	}
	nrng = prnglen/(sizeof (vdds_ranges_t));
	for (rnum = 0; rnum < nrng; rnum++) {
		prp = &prng[rnum];
		if (prp->child_hi == HVCOOKIE(cookie)) {
			prp->child_hi = 0;
			success = B_TRUE;
			break;
		}
	}
	if (success) {
		if (ndi_prop_update_int_array(DDI_DEV_T_NONE, nexus_dip,
		    "ranges", (int *)prng, (nrng * 6)) != DDI_SUCCESS) {
			DERR(NULL,
			    "Failed to update nexus ranges prop(dip=0x%p)",
			    nexus_dip);
		}
	}
}
