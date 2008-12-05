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
#include <sys/priv_names.h>

/* module description */
#define	VNIC_LINKINFO		"Virtual NIC"

/* device info ptr, only one for instance 0 */
static dev_info_t *vnic_dip = NULL;
static int vnic_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int vnic_attach(dev_info_t *, ddi_attach_cmd_t);
static int vnic_detach(dev_info_t *, ddi_detach_cmd_t);

static int vnic_ioc_create(void *, intptr_t, int, cred_t *, int *);
static int vnic_ioc_delete(void *, intptr_t, int, cred_t *, int *);
static int vnic_ioc_info(void *, intptr_t, int, cred_t *, int *);
static int vnic_ioc_modify(void *, intptr_t, int, cred_t *, int *);

static dld_ioc_info_t vnic_ioc_list[] = {
	{VNIC_IOC_CREATE, DLDCOPYINOUT, sizeof (vnic_ioc_create_t),
	    vnic_ioc_create, {PRIV_SYS_DL_CONFIG}},
	{VNIC_IOC_DELETE, DLDCOPYIN, sizeof (vnic_ioc_delete_t),
	    vnic_ioc_delete, {PRIV_SYS_DL_CONFIG}},
	{VNIC_IOC_INFO, DLDCOPYINOUT, sizeof (vnic_ioc_info_t),
	    vnic_ioc_info, {NULL}},
	{VNIC_IOC_MODIFY, DLDCOPYIN, sizeof (vnic_ioc_modify_t),
	    vnic_ioc_modify, {PRIV_SYS_DL_CONFIG}},
};

DDI_DEFINE_STREAM_OPS(vnic_dev_ops, nulldev, nulldev, vnic_attach, vnic_detach,
    nodev, vnic_getinfo, D_MP, NULL, ddi_quiesce_not_supported);

static struct modldrv vnic_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	VNIC_LINKINFO,		/* short description */
	&vnic_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &vnic_modldrv, NULL
};

int
_init(void)
{
	int	status;

	mac_init_ops(&vnic_dev_ops, "vnic");
	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS)
		mac_fini_ops(&vnic_dev_ops);

	return (status);
}

int
_fini(void)
{
	int	status;

	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS)
		mac_fini_ops(&vnic_dev_ops);

	return (status);
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
}

static void
vnic_fini(void)
{
	vnic_dev_fini();
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
 * Process a VNICIOC_CREATE request.
 */
/* ARGSUSED */
static int
vnic_ioc_create(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	vnic_ioc_create_t *create_arg = karg;
	int err = 0, mac_len = 0, mac_slot;
	uchar_t mac_addr[MAXMACADDRLEN];
	uint_t mac_prefix_len;
	vnic_mac_addr_type_t mac_addr_type;
	vnic_ioc_diag_t diag = VNIC_IOC_DIAG_NONE;
	boolean_t is_anchor = create_arg->vc_flags & VNIC_IOC_CREATE_ANCHOR;

	/* MAC address */
	mac_addr_type = create_arg->vc_mac_addr_type;

	if (is_anchor)
		goto create;

	switch (mac_addr_type) {
	case VNIC_MAC_ADDR_TYPE_FIXED:
		mac_len = create_arg->vc_mac_len;
		/*
		 * Sanity check the MAC address length. vnic_dev_create()
		 * will perform additional checks to ensure that the
		 * address is a valid unicast address of the appropriate
		 * length.
		 */
		if (mac_len == 0 || mac_len > MAXMACADDRLEN) {
			err = EINVAL;
			diag = VNIC_IOC_DIAG_MACADDRLEN_INVALID;
			goto bail;
		}
		bcopy(create_arg->vc_mac_addr, mac_addr, MAXMACADDRLEN);
		break;
	case VNIC_MAC_ADDR_TYPE_FACTORY:
		mac_slot = create_arg->vc_mac_slot;
		/* sanity check the specified slot number */
		if (mac_slot < 0 && mac_slot != -1) {
			err = EINVAL;
			diag = VNIC_IOC_DIAG_MACFACTORYSLOTINVALID;
			goto bail;
		}
		break;
	case VNIC_MAC_ADDR_TYPE_AUTO:
		mac_slot = -1;
		/* FALLTHROUGH */
	case VNIC_MAC_ADDR_TYPE_RANDOM:
		mac_prefix_len = create_arg->vc_mac_prefix_len;
		if (mac_prefix_len > MAXMACADDRLEN) {
			err = EINVAL;
			diag = VNIC_IOC_DIAG_MACPREFIXLEN_INVALID;
			goto bail;
		}
		mac_len = create_arg->vc_mac_len;
		if (mac_len > MAXMACADDRLEN) {
			err = EINVAL;
			diag = VNIC_IOC_DIAG_MACADDRLEN_INVALID;
			goto bail;
		}
		bcopy(create_arg->vc_mac_addr, mac_addr, MAXMACADDRLEN);
		break;
	case VNIC_MAC_ADDR_TYPE_PRIMARY:
		/*
		 * We will get the primary address when we add this
		 * client
		 */
		break;
	default:
		err = ENOTSUP;
		goto bail;
	}

create:
	err = vnic_dev_create(create_arg->vc_vnic_id, create_arg->vc_link_id,
	    &mac_addr_type, &mac_len, mac_addr, &mac_slot, mac_prefix_len,
	    create_arg->vc_vid, &create_arg->vc_resource_props,
	    create_arg->vc_flags, &diag);
	if (err != 0)
		goto bail;

	create_arg->vc_mac_addr_type = mac_addr_type;

	if (is_anchor)
		goto bail;

	switch (mac_addr_type) {
	case VNIC_MAC_ADDR_TYPE_FACTORY:
		create_arg->vc_mac_slot = mac_slot;
		break;
	case VNIC_MAC_ADDR_TYPE_RANDOM:
		bcopy(mac_addr, create_arg->vc_mac_addr, MAXMACADDRLEN);
		create_arg->vc_mac_len = mac_len;
		break;
	}

bail:
	create_arg->vc_diag = diag;
	create_arg->vc_status = err;
	return (err);
}

/* ARGSUSED */
static int
vnic_ioc_modify(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	vnic_ioc_modify_t *modify_arg = karg;

	return (vnic_dev_modify(modify_arg->vm_vnic_id,
	    modify_arg->vm_modify_mask, modify_arg->vm_mac_addr_type,
	    modify_arg->vm_mac_len, modify_arg->vm_mac_addr,
	    modify_arg->vm_mac_slot, &modify_arg->vm_resource_props));
}

/* ARGSUSED */
static int
vnic_ioc_delete(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	vnic_ioc_delete_t *delete_arg = karg;

	return (vnic_dev_delete(delete_arg->vd_vnic_id, 0));
}

/* ARGSUSED */
static int
vnic_ioc_info(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	vnic_ioc_info_t *info_arg = karg;

	return (vnic_info(&info_arg->vi_info));
}
