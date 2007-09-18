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

/*
 * Virtual Network Interface Card (VNIC)
 */

#include <sys/ddi.h>
#include <sys/strsun.h>
#include <sys/dld.h>
#include <sys/dld_impl.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/vnic.h>
#include <sys/vnic_impl.h>
#include <inet/common.h>

/* module description */
#define	VNIC_LINKINFO		"VNIC MAC"
#define	VNIC_DRIVER_NAME	"vnic"

/* device info ptr, only one for instance 0 */
static dev_info_t *vnic_dip = NULL;

/* for control interface */
static int vnic_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int vnic_attach(dev_info_t *, ddi_attach_cmd_t);
static int vnic_detach(dev_info_t *, ddi_detach_cmd_t);
static int vnic_open(queue_t *, dev_t *, int, int, cred_t *);
static int vnic_close(queue_t *);
static void vnic_wput(queue_t *, mblk_t *);

typedef struct vnic_taskq_args_s {
	queue_t	*tq_vnic_q;
	mblk_t	*tq_vnic_mp;
	int	tq_vnic_flag;
} vnic_taskq_args_t;

static void vnic_ioc_create(vnic_taskq_args_t *);
static void vnic_ioc_modify(vnic_taskq_args_t *);
static void vnic_ioc_delete(vnic_taskq_args_t *);
static void vnic_ioc_info(vnic_taskq_args_t *);

typedef struct ioc_cmd_s {
	int ic_cmd;
	void (*ic_func)(vnic_taskq_args_t *);
} ioc_cmd_t;

static ioc_cmd_t ioc_cmd[] = {
	{VNIC_IOC_CREATE, vnic_ioc_create},
	{VNIC_IOC_DELETE, vnic_ioc_delete},
	{VNIC_IOC_INFO, vnic_ioc_info},
	{VNIC_IOC_MODIFY, vnic_ioc_modify}
};

#define	IOC_CMD_SZ (sizeof (ioc_cmd) / sizeof (ioc_cmd_t))

/*
 * mi_hiwat is set to 1 because of the flow control mechanism implemented
 * in dld. refer to the comments in dld_str.c for details.
 */
static struct module_info vnic_module_info = {
	0,
	VNIC_DRIVER_NAME,
	0,
	INFPSZ,
	1,
	0
};

static struct qinit vnic_r_qinit = {	/* read queues */
	NULL,
	NULL,
	vnic_open,
	vnic_close,
	NULL,
	&vnic_module_info
};

static struct qinit vnic_w_qinit = {	/* write queues */
	(pfi_t)dld_wput,
	(pfi_t)dld_wsrv,
	NULL,
	NULL,
	NULL,
	&vnic_module_info
};

/*
 * Entry points for vnic control node
 */
static struct qinit vnic_w_ctl_qinit = {
	(pfi_t)vnic_wput,
	NULL,
	NULL,
	NULL,
	NULL,
	&vnic_module_info
};

static struct streamtab vnic_streamtab = {
	&vnic_r_qinit,
	&vnic_w_qinit
};

DDI_DEFINE_STREAM_OPS(vnic_dev_ops, nulldev, nulldev, vnic_attach, vnic_detach,
    nodev, vnic_getinfo, D_MP, &vnic_streamtab);

static struct modldrv vnic_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	VNIC_LINKINFO,		/* short description */
	&vnic_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&vnic_modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
vnic_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	if (q->q_ptr != NULL)
		return (EBUSY);

	if (getminor(*devp) == VNIC_CTL_NODE_MINOR) {
		dld_str_t	*dsp;

		dsp = dld_str_create(q, DLD_CONTROL, getmajor(*devp),
		    DL_STYLE1);
		if (dsp == NULL)
			return (ENOSR);

		/*
		 * The VNIC control node uses its own set of entry points.
		 */
		WR(q)->q_qinfo = &vnic_w_ctl_qinit;
		*devp = makedevice(getmajor(*devp), dsp->ds_minor);
		qprocson(q);
		return (0);
	}
	return (dld_open(q, devp, flag, sflag, credp));
}

static int
vnic_close(queue_t *q)
{
	dld_str_t	*dsp = q->q_ptr;

	if (dsp->ds_type == DLD_CONTROL) {
		qprocsoff(q);
		dld_str_destroy(dsp);
		return (0);
	}
	return (dld_close(q));
}

void
vnic_ioctl(queue_t *wq, mblk_t *mp)
{
	/* LINTED alignment */
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	int i, err = 0;
	mblk_t *nmp;
	void (*func)();
	vnic_taskq_args_t *taskq_args;

	if (mp->b_cont == NULL) {
		err = EINVAL;
		goto done;
	}

	/*
	 * Construct contiguous message
	 */
	if ((nmp = msgpullup(mp->b_cont, -1)) == NULL) {
		freemsg(mp->b_cont);
		err = ENOMEM;
		goto done;
	}

	freemsg(mp->b_cont);
	mp->b_cont = nmp;

	for (i = 0; i < IOC_CMD_SZ; i++) {
		if (iocp->ioc_cmd == ioc_cmd[i].ic_cmd) {
			func = ioc_cmd[i].ic_func;
			break;
		}
	}

	if (i == IOC_CMD_SZ) {
		freemsg(mp->b_cont);
		err = EINVAL;
		goto done;
	}

	taskq_args = kmem_zalloc(sizeof (vnic_taskq_args_t), KM_NOSLEEP);
	if (taskq_args == NULL) {
		freemsg(mp->b_cont);
		err = ENOMEM;
		goto done;
	}

	taskq_args->tq_vnic_q = wq;
	taskq_args->tq_vnic_mp = mp;
	taskq_args->tq_vnic_flag = (int)iocp->ioc_flag;
	if (taskq_dispatch(system_taskq,
	    func, taskq_args, TQ_NOSLEEP) == NULL) {
		kmem_free(taskq_args, sizeof (vnic_taskq_args_t));
		freemsg(mp->b_cont);
		err = ENOMEM;
		goto done;
	}

done:
	if (err != 0)
		miocnak(wq, mp, 0, err);
}

static void
vnic_wput(queue_t *q, mblk_t *mp)
{
	if (DB_TYPE(mp) == M_IOCTL)
		vnic_ioctl(q, mp);
	else
		freemsg(mp);
}

static void
vnic_init(void)
{
	vnic_dev_init();
	vnic_bcast_init();
	vnic_classifier_init();
}

static void
vnic_fini(void)
{
	vnic_dev_fini();
	vnic_bcast_fini();
	vnic_classifier_fini();
}

dev_info_t *
vnic_get_dip(void)
{
	return (vnic_dip);
}

/*ARGSUSED*/
static int
vnic_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = vnic_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
vnic_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_get_instance(dip) != 0) {
			/* we only allow instance 0 to attach */
			return (DDI_FAILURE);
		}

		/* create minor node for control interface */
		if (ddi_create_minor_node(dip, VNIC_CTL_NODE_NAME, S_IFCHR,
		    VNIC_CTL_NODE_MINOR, DDI_PSEUDO, 0) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		vnic_dip = dip;
		vnic_init();

		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
vnic_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		/*
		 * Allow the VNIC instance to be detached only if there
		 * are not VNICs configured.
		 */
		if (vnic_dev_count() > 0)
			return (DDI_FAILURE);

		vnic_dip = NULL;
		vnic_fini();
		ddi_remove_minor_node(dip, VNIC_CTL_NODE_NAME);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Process a VNICIOC_CREATE request.
 */
static void
vnic_ioc_create(vnic_taskq_args_t *taskq_args)
{
	STRUCT_HANDLE(vnic_ioc_create, create_arg);
	queue_t *wq = taskq_args->tq_vnic_q;
	mblk_t *mp = taskq_args->tq_vnic_mp;
	int mode = taskq_args->tq_vnic_flag;
	int rc = 0;
	int mac_len;
	uchar_t mac_addr[MAXMACADDRLEN];
	uint_t vnic_id;
	char dev_name[MAXNAMELEN + 1];
	vnic_mac_addr_type_t mac_addr_type;

	kmem_free(taskq_args, sizeof (vnic_taskq_args_t));
	STRUCT_SET_HANDLE(create_arg, mode, (void *)mp->b_cont->b_rptr);
	if (MBLKL(mp->b_cont) < STRUCT_SIZE(create_arg)) {
		rc = EINVAL;
		goto bail;
	}

	/*
	 * VNIC id. For now it is specified by the user. Once we have
	 * vanity naming, we can pick a value for the user, and let
	 * the user assign a generic name to the VNIC (XXXND)
	 */
	vnic_id = STRUCT_FGET(create_arg, vc_vnic_id);

	/*
	 * Device name and number of the MAC port the VNIC is defined
	 * on top of.
	 */
	bcopy(STRUCT_FGET(create_arg, vc_dev_name), dev_name, MAXNAMELEN);

	/* MAC address */
	mac_addr_type = STRUCT_FGET(create_arg, vc_mac_addr_type);
	mac_len = STRUCT_FGET(create_arg, vc_mac_len);

	switch (mac_addr_type) {
	case VNIC_MAC_ADDR_TYPE_FIXED:
		bcopy(STRUCT_FGET(create_arg, vc_mac_addr), mac_addr,
		    MAXMACADDRLEN);
		break;
	default:
		rc = ENOTSUP;
		goto bail;
	}

	rc = vnic_dev_create(vnic_id, dev_name, mac_len, mac_addr);
	if (rc != 0) {
		cmn_err(CE_WARN, "vnic_dev_create failed with %d", rc);
		goto bail;
	}

bail:
	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	if (rc != 0)
		miocnak(wq, mp, 0, rc);
	else
		miocack(wq, mp, 0, 0);
}

static void
vnic_ioc_modify(vnic_taskq_args_t *taskq_args)
{
	STRUCT_HANDLE(vnic_ioc_modify, modify_arg);
	queue_t *wq = taskq_args->tq_vnic_q;
	mblk_t *mp = taskq_args->tq_vnic_mp;
	int mode = taskq_args->tq_vnic_flag;
	int err = 0;
	uint_t vnic_id;
	uint_t modify_mask;
	vnic_mac_addr_type_t mac_addr_type;
	uint_t mac_len;
	uchar_t mac_addr[MAXMACADDRLEN];

	kmem_free(taskq_args, sizeof (vnic_taskq_args_t));
	STRUCT_SET_HANDLE(modify_arg, mode, (void *)mp->b_cont->b_rptr);
	if (MBLKL(mp->b_cont) < STRUCT_SIZE(modify_arg)) {
		err = EINVAL;
		goto done;
	}

	vnic_id = STRUCT_FGET(modify_arg, vm_vnic_id);
	modify_mask = STRUCT_FGET(modify_arg, vm_modify_mask);

	if (modify_mask & VNIC_IOC_MODIFY_ADDR) {
		mac_addr_type = STRUCT_FGET(modify_arg, vm_mac_addr_type);
		mac_len = STRUCT_FGET(modify_arg, vm_mac_len);
		bcopy(STRUCT_FGET(modify_arg, vm_mac_addr), mac_addr,
		    MAXMACADDRLEN);
	}

	err = vnic_dev_modify(vnic_id, modify_mask, mac_addr_type,
	    mac_len, mac_addr);
done:
	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	if (err != 0)
		miocnak(wq, mp, 0, err);
	else
		miocack(wq, mp, 0, 0);
}

static void
vnic_ioc_delete(vnic_taskq_args_t *taskq_args)
{
	STRUCT_HANDLE(vnic_ioc_delete, delete_arg);
	queue_t *wq = taskq_args->tq_vnic_q;
	mblk_t *mp = taskq_args->tq_vnic_mp;
	int mode = taskq_args->tq_vnic_flag;
	uint_t vnic_id;
	int err = 0;

	kmem_free(taskq_args, sizeof (vnic_taskq_args_t));
	STRUCT_SET_HANDLE(delete_arg, mode, (void *)mp->b_cont->b_rptr);
	if (STRUCT_SIZE(delete_arg) > MBLKL(mp)) {
		err = EINVAL;
		goto fail;
	}

	vnic_id = STRUCT_FGET(delete_arg, vd_vnic_id);
	err = vnic_dev_delete(vnic_id);

fail:
	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	if (err != 0)
		miocnak(wq, mp, 0, err);
	else
		miocack(wq, mp, 0, err);
}

typedef struct vnic_ioc_info_state {
	uint32_t bytes_left;
	uchar_t *where;
} vnic_ioc_info_state_t;

static int
vnic_ioc_info_new_vnic(void *arg, uint32_t id, vnic_mac_addr_type_t addr_type,
    uint_t mac_len, uint8_t *mac_addr, char *dev_name)
{
	vnic_ioc_info_state_t *state = arg;
	/*LINTED*/
	vnic_ioc_info_vnic_t *vn = (vnic_ioc_info_vnic_t *)state->where;

	if (state->bytes_left < sizeof (*vn))
		return (ENOSPC);

	vn->vn_vnic_id = id;
	vn->vn_mac_addr_type = addr_type;
	vn->vn_mac_len = mac_len;
	bcopy(mac_addr, &(vn->vn_mac_addr), mac_len);
	bcopy(dev_name, &(vn->vn_dev_name), MAXNAMELEN);

	state->where += sizeof (*vn);
	state->bytes_left -= sizeof (*vn);

	return (0);
}

static void
vnic_ioc_info(vnic_taskq_args_t *taskq_args)
{
	queue_t *wq = taskq_args->tq_vnic_q;
	mblk_t *mp = taskq_args->tq_vnic_mp;
	vnic_ioc_info_t *info_argp;
	int rc, len;
	uint32_t nvnics, vnic_id;
	char dev_name[MAXNAMELEN];
	vnic_ioc_info_state_t state;

	kmem_free(taskq_args, sizeof (vnic_taskq_args_t));
	if ((len = MBLKL(mp->b_cont)) < sizeof (*info_argp)) {
		rc = EINVAL;
		goto bail;
	}

	/* LINTED alignment */
	info_argp = (vnic_ioc_info_t *)mp->b_cont->b_rptr;

	/*
	 * ID of the vnic to return or vnic device.
	 * If zero, the call returns information
	 * regarding all vnics currently defined.
	 */
	vnic_id = info_argp->vi_vnic_id;
	if (info_argp->vi_dev_name)
		bcopy(info_argp->vi_dev_name, dev_name, MAXNAMELEN);

	state.bytes_left = len - sizeof (vnic_ioc_info_t);
	state.where = (uchar_t *)(info_argp +1);

	rc = vnic_info(&nvnics, vnic_id, dev_name, &state,
	    vnic_ioc_info_new_vnic);

bail:
	if (rc == 0) {
		info_argp->vi_nvnics = nvnics;
		miocack(wq, mp, len, 0);
	} else {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		miocnak(wq, mp, 0, rc);
	}
}
