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

/*
 * Virtual Network Interface Card (VNIC)
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/vnic.h>
#include <sys/vnic_impl.h>
#include <inet/common.h>

/* module description */
#define	VNIC_LINKINFO		"VNIC MAC"

/* device info ptr, only one for instance 0 */
static dev_info_t *vnic_dip = NULL;
static int vnic_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int vnic_attach(dev_info_t *, ddi_attach_cmd_t);
static int vnic_detach(dev_info_t *, ddi_detach_cmd_t);
static dld_ioc_func_t vnic_ioc_create, vnic_ioc_modify, vnic_ioc_delete,
    vnic_ioc_info;

static dld_ioc_info_t vnic_ioc_list[] = {
	{VNIC_IOC_CREATE, DLDCOPYIN | DLDDLCONFIG, sizeof (vnic_ioc_create_t),
	    vnic_ioc_create},
	{VNIC_IOC_DELETE, DLDCOPYIN | DLDDLCONFIG, sizeof (vnic_ioc_delete_t),
	    vnic_ioc_delete},
	{VNIC_IOC_INFO, DLDCOPYINOUT, sizeof (vnic_ioc_info_t),
	    vnic_ioc_info},
	{VNIC_IOC_MODIFY, DLDCOPYIN | DLDDLCONFIG, sizeof (vnic_ioc_modify_t),
	    vnic_ioc_modify}
};

static struct cb_ops vnic_cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_MP			/* Driver compatibility flag */
};

static struct dev_ops vnic_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	vnic_getinfo,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	vnic_attach,		/* attach */
	vnic_detach,		/* detach */
	nodev,			/* reset */
	&vnic_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev			/* dev power */
};

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
	int	err;

	mac_init_ops(&vnic_dev_ops, "vnic");
	if ((err = mod_install(&modlinkage)) != 0)
		mac_fini_ops(&vnic_dev_ops);
	return (err);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) == 0)
		mac_fini_ops(&vnic_dev_ops);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
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
		*result = 0;
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

		if (dld_ioc_register(VNIC_IOC, vnic_ioc_list,
		    DLDIOCCNT(vnic_ioc_list)) != 0)
			return (DDI_FAILURE);

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
		dld_ioc_unregister(VNIC_IOC);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Process a VNIC_IOC_CREATE request.
 */
/* ARGSUSED */
static int
vnic_ioc_create(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	vnic_ioc_create_t *create_arg = karg;
	int mac_len;
	uchar_t mac_addr[MAXMACADDRLEN];
	datalink_id_t vnic_id, linkid;
	vnic_mac_addr_type_t mac_addr_type;

	/*
	 * VNIC link id
	 */
	vnic_id = create_arg->vc_vnic_id;

	/*
	 * Linkid of the link the VNIC is defined on top of.
	 */
	linkid = create_arg->vc_link_id;

	/* MAC address */
	mac_addr_type = create_arg->vc_mac_addr_type;
	mac_len = create_arg->vc_mac_len;

	switch (mac_addr_type) {
	case VNIC_MAC_ADDR_TYPE_FIXED:
		bcopy(create_arg->vc_mac_addr, mac_addr, MAXMACADDRLEN);
		break;
	default:
		return (ENOTSUP);
	}

	return (vnic_dev_create(vnic_id, linkid, mac_len, mac_addr));
}

/* ARGSUSED */
static int
vnic_ioc_modify(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	vnic_ioc_modify_t *modify_arg = karg;
	datalink_id_t vnic_id;
	uint_t modify_mask;
	vnic_mac_addr_type_t mac_addr_type;
	uint_t mac_len;
	uchar_t mac_addr[MAXMACADDRLEN];

	vnic_id = modify_arg->vm_vnic_id;
	modify_mask = modify_arg->vm_modify_mask;

	if (modify_mask & VNIC_IOC_MODIFY_ADDR) {
		mac_addr_type = modify_arg->vm_mac_addr_type;
		mac_len = modify_arg->vm_mac_len;
		bcopy(modify_arg->vm_mac_addr, mac_addr, MAXMACADDRLEN);
	}

	return (vnic_dev_modify(vnic_id, modify_mask, mac_addr_type,
	    mac_len, mac_addr));
}

/* ARGSUSED */
static int
vnic_ioc_delete(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	vnic_ioc_delete_t *delete_arg = karg;

	return (vnic_dev_delete(delete_arg->vd_vnic_id));
}

typedef struct vnic_ioc_info_state {
	uint32_t	bytes_left;
	uchar_t		*where;
	int		mode;
} vnic_ioc_info_state_t;

static int
vnic_ioc_info_new_vnic(void *arg, datalink_id_t id,
    vnic_mac_addr_type_t addr_type, uint_t mac_len, uint8_t *mac_addr,
    datalink_id_t linkid)
{
	vnic_ioc_info_state_t *state = arg;
	/*LINTED*/
	vnic_ioc_info_vnic_t *vn = (vnic_ioc_info_vnic_t *)state->where;

	if (state->bytes_left < sizeof (*vn))
		return (ENOSPC);

	vn->vn_vnic_id = id;
	vn->vn_link_id = linkid;
	vn->vn_mac_addr_type = addr_type;
	vn->vn_mac_len = mac_len;
	if (ddi_copyout(mac_addr, &(vn->vn_mac_addr), mac_len,
	    state->mode) != 0)
		return (EFAULT);

	state->where += sizeof (*vn);
	state->bytes_left -= sizeof (*vn);

	return (0);
}

/* ARGSUSED */
static int
vnic_ioc_info(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	vnic_ioc_info_t *info_argp = karg;
	uint32_t nvnics;
	datalink_id_t vnic_id, linkid;
	vnic_ioc_info_state_t state;

	/*
	 * ID of the vnic to return or vnic device.
	 * If zero, the call returns information
	 * regarding all vnics currently defined.
	 */
	vnic_id = info_argp->vi_vnic_id;
	linkid = info_argp->vi_linkid;

	state.bytes_left = info_argp->vi_size;
	state.where = (uchar_t *)(arg + sizeof (vnic_ioc_info_t));
	state.mode = mode;

	return (vnic_info(&nvnics, vnic_id, linkid, &state,
	    vnic_ioc_info_new_vnic));
}
