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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/model.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/open.h>
#include <sys/user.h>
#include <sys/t_lock.h>
#include <sys/vm.h>
#include <sys/stat.h>
#include <vm/hat.h>
#include <vm/seg.h>
#include <vm/as.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/avintr.h>
#include <sys/autoconf.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi.h>
#include <sys/kstat.h>
#include <sys/conf.h>
#include <sys/ddi_impldefs.h>	/* include implementation structure defs */
#include <sys/ndi_impldefs.h>
#include <sys/hwconf.h>
#include <sys/pathname.h>
#include <sys/modctl.h>
#include <sys/epm.h>
#include <sys/devctl.h>
#include <sys/callb.h>
#include <sys/bootconf.h>
#include <sys/dacf_impl.h>
#include <sys/nvpair.h>
#include <sys/sunmdi.h>
#include <sys/fs/dv_node.h>
#include <sys/sunldi_impl.h>

#ifdef __sparc
#include <sys/archsystm.h>	/* getpil/setpil */
#include <sys/membar.h>		/* membar_sync */
#endif

/*
 * ndi property handling
 */
int
ndi_prop_update_int(dev_t match_dev, dev_info_t *dip,
    char *name, int data)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_HW_DEF | DDI_PROP_TYPE_INT | DDI_PROP_DONTSLEEP,
	    name, &data, 1, ddi_prop_fm_encode_ints));
}

int
ndi_prop_update_int64(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t data)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_HW_DEF | DDI_PROP_TYPE_INT64 | DDI_PROP_DONTSLEEP,
	    name, &data, 1, ddi_prop_fm_encode_int64));
}

int
ndi_prop_create_boolean(dev_t match_dev, dev_info_t *dip,
    char *name)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_HW_DEF | DDI_PROP_TYPE_ANY | DDI_PROP_DONTSLEEP,
	    name, NULL, 0, ddi_prop_fm_encode_bytes));
}

int
ndi_prop_update_int_array(dev_t match_dev, dev_info_t *dip,
    char *name, int *data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_HW_DEF | DDI_PROP_TYPE_INT | DDI_PROP_DONTSLEEP,
	    name, data, nelements, ddi_prop_fm_encode_ints));
}

int
ndi_prop_update_int64_array(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t *data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_HW_DEF | DDI_PROP_TYPE_INT64 | DDI_PROP_DONTSLEEP,
	    name, data, nelements, ddi_prop_fm_encode_int64));
}

int
ndi_prop_update_string(dev_t match_dev, dev_info_t *dip,
    char *name, char *data)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_HW_DEF | DDI_PROP_TYPE_STRING | DDI_PROP_DONTSLEEP,
	    name, &data, 1, ddi_prop_fm_encode_string));
}

int
ndi_prop_update_string_array(dev_t match_dev, dev_info_t *dip,
    char *name, char **data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_HW_DEF | DDI_PROP_TYPE_STRING | DDI_PROP_DONTSLEEP,
	    name, data, nelements,
	    ddi_prop_fm_encode_strings));
}

int
ndi_prop_update_byte_array(dev_t match_dev, dev_info_t *dip,
    char *name, uchar_t *data, uint_t nelements)
{
	if (nelements == 0)
		return (DDI_PROP_INVAL_ARG);

	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_HW_DEF | DDI_PROP_TYPE_BYTE | DDI_PROP_DONTSLEEP,
	    name, data, nelements, ddi_prop_fm_encode_bytes));
}

int
ndi_prop_remove(dev_t dev, dev_info_t *dip, char *name)
{
	return (ddi_prop_remove_common(dev, dip, name, DDI_PROP_HW_DEF));
}

void
ndi_prop_remove_all(dev_info_t *dip)
{
	i_ddi_prop_dyn_parent_set(dip, NULL);
	ddi_prop_remove_all_common(dip, (int)DDI_PROP_HW_DEF);
}

/*
 * Post an event notification to nexus driver responsible for handling
 * the event.  The responsible nexus is defined in the cookie passed in as
 * the third parameter.
 * The dip parameter is an artifact of an older implementation in which all
 * requests to remove an eventcall would bubble up the tree.  Today, this
 * parameter is ignored.
 * Input Parameters:
 *	dip	- Ignored.
 *	rdip	- device driver posting the event
 *	cookie	- valid ddi_eventcookie_t, obtained by caller prior to
 *		  invocation of this routine
 *	impl_data - used by framework
 */
/*ARGSUSED*/
int
ndi_post_event(dev_info_t *dip, dev_info_t *rdip,
		ddi_eventcookie_t cookie, void *impl_data)
{
	dev_info_t *ddip;

	ASSERT(cookie);
	ddip = NDI_EVENT_DDIP(cookie);

	/*
	 * perform sanity checks.  These conditions should never be true.
	 */

	ASSERT(DEVI(ddip)->devi_ops->devo_bus_ops != NULL);
	ASSERT(DEVI(ddip)->devi_ops->devo_bus_ops->busops_rev >= BUSO_REV_6);
	ASSERT(DEVI(ddip)->devi_ops->devo_bus_ops->bus_post_event != NULL);

	/*
	 * post the event to the responsible ancestor
	 */
	return ((*(DEVI(ddip)->devi_ops->devo_bus_ops->bus_post_event))
	    (ddip, rdip, cookie, impl_data));
}

/*
 * Calls the bus nexus driver's implementation of the
 * (*bus_remove_eventcall)() interface.
 */
int
ndi_busop_remove_eventcall(dev_info_t *ddip, ddi_callback_id_t id)
{

	ASSERT(id);
	/* check for a correct revno before calling up the device tree. */
	ASSERT(DEVI(ddip)->devi_ops->devo_bus_ops != NULL);
	ASSERT(DEVI(ddip)->devi_ops->devo_bus_ops->busops_rev >= BUSO_REV_6);

	if (DEVI(ddip)->devi_ops->devo_bus_ops->bus_remove_eventcall == NULL)
		return (DDI_FAILURE);

	/*
	 * request responsible nexus to remove the eventcall
	 */
	return ((*(DEVI(ddip)->devi_ops->devo_bus_ops->bus_remove_eventcall))
	    (ddip, id));
}

/*
 * Calls the bus nexus driver's implementation of the
 * (*bus_add_eventcall)() interface.  The dip parameter is an
 * artifact of an older implementation in which all requests to
 * add an eventcall would bubble up the tree.  Today, this parameter is
 * ignored.
 */
/*ARGSUSED*/
int
ndi_busop_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
		ddi_eventcookie_t cookie, void (*callback)(), void *arg,
		ddi_callback_id_t *cb_id)
{
	dev_info_t *ddip = (dev_info_t *)NDI_EVENT_DDIP(cookie);

	/*
	 * check for a correct revno before calling up the device tree.
	 */
	ASSERT(DEVI(ddip)->devi_ops->devo_bus_ops != NULL);
	ASSERT(DEVI(ddip)->devi_ops->devo_bus_ops->busops_rev >= BUSO_REV_6);

	if (DEVI(ddip)->devi_ops->devo_bus_ops->bus_add_eventcall == NULL)
		return (DDI_FAILURE);

	/*
	 * request responsible ancestor to add the eventcall
	 */
	return ((*(DEVI(ddip)->devi_ops->devo_bus_ops->bus_add_eventcall))
	    (ddip, rdip, cookie, callback, arg, cb_id));
}

/*
 * Calls the bus nexus driver's implementation of the
 * (*bus_get_eventcookie)() interface up the device tree hierarchy.
 */
int
ndi_busop_get_eventcookie(dev_info_t *dip, dev_info_t *rdip, char *name,
		ddi_eventcookie_t *event_cookiep)
{
	dev_info_t *pdip = (dev_info_t *)DEVI(dip)->devi_parent;

	/* Can not be called from rootnex. */
	ASSERT(pdip);

	/*
	 * check for a correct revno before calling up the device tree.
	 */
	ASSERT(DEVI(pdip)->devi_ops->devo_bus_ops != NULL);

	if ((DEVI(pdip)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_6) ||
	    (DEVI(pdip)->devi_ops->devo_bus_ops->bus_get_eventcookie == NULL)) {
#ifdef DEBUG
		if ((DEVI(pdip)->devi_ops->devo_bus_ops->busops_rev >=
		    BUSO_REV_3) &&
		    (DEVI(pdip)->devi_ops->devo_bus_ops->bus_get_eventcookie)) {
			cmn_err(CE_WARN,
			    "Warning: %s%d busops_rev=%d no longer supported"
			    " by the NDI event framework.\nBUSO_REV_6 or "
			    "greater must be used.",
			    DEVI(pdip)->devi_binding_name,
			    DEVI(pdip)->devi_instance,
			    DEVI(pdip)->devi_ops->devo_bus_ops->busops_rev);
		}
#endif /* DEBUG */

		return (ndi_busop_get_eventcookie(pdip, rdip, name,
		    event_cookiep));
	}

	return ((*(DEVI(pdip)->devi_ops->devo_bus_ops->bus_get_eventcookie))
	    (pdip, rdip, name, event_cookiep));
}

/*
 * Copy in the devctl IOCTL data and return a handle to
 * the data.
 */
int
ndi_dc_allochdl(void *iocarg, struct devctl_iocdata **rdcp)
{
	struct devctl_iocdata *dcp;
	char *cpybuf;

	ASSERT(rdcp != NULL);

	dcp = kmem_zalloc(sizeof (*dcp), KM_SLEEP);

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(iocarg, dcp, sizeof (*dcp)) != 0) {
			kmem_free(dcp, sizeof (*dcp));
			return (NDI_FAULT);
		}
	}
#ifdef _SYSCALL32_IMPL
	else {
		struct devctl_iocdata32 dcp32;

		if (copyin(iocarg, &dcp32, sizeof (dcp32)) != 0) {
			kmem_free(dcp, sizeof (*dcp));
			return (NDI_FAULT);
		}
		dcp->cmd = (uint_t)dcp32.cmd;
		dcp->flags = (uint_t)dcp32.flags;
		dcp->cpyout_buf = (uint_t *)(uintptr_t)dcp32.cpyout_buf;
		dcp->nvl_user = (nvlist_t *)(uintptr_t)dcp32.nvl_user;
		dcp->nvl_usersz = (size_t)dcp32.nvl_usersz;
		dcp->c_nodename = (char *)(uintptr_t)dcp32.c_nodename;
		dcp->c_unitaddr = (char *)(uintptr_t)dcp32.c_unitaddr;
	}
#endif
	if (dcp->c_nodename != NULL) {
		cpybuf = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		if (copyinstr(dcp->c_nodename, cpybuf, MAXNAMELEN, 0) != 0) {
			kmem_free(cpybuf, MAXNAMELEN);
			kmem_free(dcp, sizeof (*dcp));
			return (NDI_FAULT);
		}
		cpybuf[MAXNAMELEN - 1] = '\0';
		dcp->c_nodename = cpybuf;
	}

	if (dcp->c_unitaddr != NULL) {
		cpybuf = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		if (copyinstr(dcp->c_unitaddr, cpybuf, MAXNAMELEN, 0) != 0) {
			kmem_free(cpybuf, MAXNAMELEN);
			if (dcp->c_nodename != NULL)
				kmem_free(dcp->c_nodename, MAXNAMELEN);
			kmem_free(dcp, sizeof (*dcp));
			return (NDI_FAULT);
		}
		cpybuf[MAXNAMELEN - 1] = '\0';
		dcp->c_unitaddr = cpybuf;
	}

	/*
	 * copyin and unpack a user defined nvlist if one was passed
	 */
	if (dcp->nvl_user != NULL) {
		if ((dcp->nvl_usersz == 0) ||
		    (dcp->nvl_usersz > DEVCTL_MAX_NVL_USERSZ)) {
			if (dcp->c_nodename != NULL)
				kmem_free(dcp->c_nodename, MAXNAMELEN);
			if (dcp->c_unitaddr != NULL)
				kmem_free(dcp->c_unitaddr, MAXNAMELEN);
			kmem_free(dcp, sizeof (*dcp));
			return (NDI_FAILURE);
		}
		cpybuf = kmem_alloc(dcp->nvl_usersz, KM_SLEEP);
		if (copyin(dcp->nvl_user, cpybuf, dcp->nvl_usersz) != 0) {
			kmem_free(cpybuf, dcp->nvl_usersz);
			if (dcp->c_nodename != NULL)
				kmem_free(dcp->c_nodename, MAXNAMELEN);
			if (dcp->c_unitaddr != NULL)
				kmem_free(dcp->c_unitaddr, MAXNAMELEN);
			kmem_free(dcp, sizeof (*dcp));
			return (NDI_FAULT);
		}

		if (nvlist_unpack(cpybuf, dcp->nvl_usersz, &dcp->nvl_user,
		    KM_SLEEP)) {
			kmem_free(cpybuf, dcp->nvl_usersz);
			if (dcp->c_nodename != NULL)
				kmem_free(dcp->c_nodename, MAXNAMELEN);
			if (dcp->c_unitaddr != NULL)
				kmem_free(dcp->c_unitaddr, MAXNAMELEN);
			kmem_free(dcp, sizeof (*dcp));
			return (NDI_FAULT);
		}
		/*
		 * free the buffer containing the packed nvlist
		 */
		kmem_free(cpybuf, dcp->nvl_usersz);

	}

	*rdcp = dcp;
	return (NDI_SUCCESS);
}

/*
 * free all space allocated to a handle.
 */
void
ndi_dc_freehdl(struct devctl_iocdata *dcp)
{
	ASSERT(dcp != NULL);

	if (dcp->c_nodename != NULL)
		kmem_free(dcp->c_nodename, MAXNAMELEN);

	if (dcp->c_unitaddr != NULL)
		kmem_free(dcp->c_unitaddr, MAXNAMELEN);

	nvlist_free(dcp->nvl_user);

	kmem_free(dcp, sizeof (*dcp));
}

char *
ndi_dc_getname(struct devctl_iocdata *dcp)
{
	ASSERT(dcp != NULL);
	return (dcp->c_nodename);

}

char *
ndi_dc_getaddr(struct devctl_iocdata *dcp)
{
	ASSERT(dcp != NULL);
	return (dcp->c_unitaddr);
}

nvlist_t *
ndi_dc_get_ap_data(struct devctl_iocdata *dcp)
{
	ASSERT(dcp != NULL);

	return (dcp->nvl_user);
}

/*
 * Transition the child named by "devname@devaddr" to the online state.
 * For use by a driver's DEVCTL_DEVICE_ONLINE handler.
 */
int
ndi_devctl_device_online(dev_info_t *dip, struct devctl_iocdata *dcp,
	uint_t flags)
{
	int	rval;
	char	*name;
	dev_info_t *rdip;

	if (ndi_dc_getname(dcp) == NULL || ndi_dc_getaddr(dcp) == NULL)
		return (EINVAL);

	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) snprintf(name, MAXNAMELEN, "%s@%s",
	    ndi_dc_getname(dcp), ndi_dc_getaddr(dcp));

	if ((rval = ndi_devi_config_one(dip, name, &rdip,
	    flags | NDI_DEVI_ONLINE | NDI_CONFIG)) == NDI_SUCCESS) {
		ndi_rele_devi(rdip);

		/*
		 * Invalidate devfs cached directory contents. For the checks
		 * in the "if" condition see the comment in ndi_devi_online().
		 */
		if (i_ddi_devi_attached(dip) && !DEVI_BUSY_OWNED(dip))
			(void) devfs_clean(dip, NULL, 0);

	} else if (rval == NDI_BUSY) {
		rval = EBUSY;
	} else if (rval == NDI_FAILURE) {
		rval = EIO;
	}

	NDI_DEBUG(flags, (CE_CONT, "%s%d: online: %s: %s\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), name,
	    ((rval == NDI_SUCCESS) ? "ok" : "failed")));

	kmem_free(name, MAXNAMELEN);

	return (rval);
}

/*
 * Transition the child named by "devname@devaddr" to the offline state.
 * For use by a driver's DEVCTL_DEVICE_OFFLINE handler.
 */
int
ndi_devctl_device_offline(dev_info_t *dip, struct devctl_iocdata *dcp,
	uint_t flags)
{
	int	rval;
	char	*name;

	if (ndi_dc_getname(dcp) == NULL || ndi_dc_getaddr(dcp) == NULL)
		return (EINVAL);

	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) snprintf(name, MAXNAMELEN, "%s@%s",
	    ndi_dc_getname(dcp), ndi_dc_getaddr(dcp));

	(void) devfs_clean(dip, name, DV_CLEAN_FORCE);
	rval = ndi_devi_unconfig_one(dip, name, NULL,
	    flags | NDI_DEVI_OFFLINE);

	if (rval == NDI_BUSY) {
		rval = EBUSY;
	} else if (rval == NDI_FAILURE) {
		rval = EIO;
	}

	NDI_DEBUG(flags, (CE_CONT, "%s%d: offline: %s: %s\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), name,
	    (rval == NDI_SUCCESS) ? "ok" : "failed"));

	kmem_free(name, MAXNAMELEN);

	return (rval);
}

/*
 * Remove the child named by "devname@devaddr".
 * For use by a driver's DEVCTL_DEVICE_REMOVE handler.
 */
int
ndi_devctl_device_remove(dev_info_t *dip, struct devctl_iocdata *dcp,
	uint_t flags)
{
	int	rval;
	char	*name;

	if (ndi_dc_getname(dcp) == NULL || ndi_dc_getaddr(dcp) == NULL)
		return (EINVAL);

	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) snprintf(name, MAXNAMELEN, "%s@%s",
	    ndi_dc_getname(dcp), ndi_dc_getaddr(dcp));

	(void) devfs_clean(dip, name, DV_CLEAN_FORCE);

	rval = ndi_devi_unconfig_one(dip, name, NULL, flags | NDI_DEVI_REMOVE);

	if (rval == NDI_BUSY) {
		rval = EBUSY;
	} else if (rval == NDI_FAILURE) {
		rval = EIO;
	}

	NDI_DEBUG(flags, (CE_CONT, "%s%d: remove: %s: %s\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), name,
	    (rval == NDI_SUCCESS) ? "ok" : "failed"));

	kmem_free(name, MAXNAMELEN);

	return (rval);
}

/*
 * Return devctl state of the child named by "name@addr".
 * For use by a driver's DEVCTL_DEVICE_GETSTATE handler.
 */
int
ndi_devctl_device_getstate(dev_info_t *parent, struct devctl_iocdata *dcp,
	uint_t *state)
{
	dev_info_t *dip;
	char *name, *addr;
	char *devname;
	int devnamelen;
	int circ;

	if (parent == NULL ||
	    ((name = ndi_dc_getname(dcp)) == NULL) ||
	    ((addr = ndi_dc_getaddr(dcp)) == NULL))
		return (NDI_FAILURE);

	devnamelen = strlen(name) + strlen(addr) + 2;
	devname = kmem_alloc(devnamelen, KM_SLEEP);
	if (strlen(addr) > 0) {
		(void) snprintf(devname, devnamelen, "%s@%s", name, addr);
	} else {
		(void) snprintf(devname, devnamelen, "%s", name);
	}

	ndi_devi_enter(parent, &circ);

	dip = ndi_devi_findchild(parent, devname);
	kmem_free(devname, devnamelen);

	if (dip == NULL) {
		ndi_devi_exit(parent, circ);
		return (NDI_FAILURE);
	}

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (DEVI_IS_DEVICE_OFFLINE(dip)) {
		*state = DEVICE_OFFLINE;
	} else if (DEVI_IS_DEVICE_DOWN(dip)) {
		*state = DEVICE_DOWN;
	} else {
		*state = DEVICE_ONLINE;
		if (devi_stillreferenced(dip) == DEVI_REFERENCED)
			*state |= DEVICE_BUSY;
	}

	mutex_exit(&(DEVI(dip)->devi_lock));
	ndi_devi_exit(parent, circ);

	return (NDI_SUCCESS);
}

/*
 * return the current state of the device "dip"
 *
 * recommend using ndi_devctl_ioctl() or
 * ndi_devctl_device_getstate() instead
 */
int
ndi_dc_return_dev_state(dev_info_t *dip, struct devctl_iocdata *dcp)
{
	dev_info_t *pdip;
	uint_t devstate = 0;
	int circ;

	if ((dip == NULL) || (dcp == NULL))
		return (NDI_FAILURE);

	pdip = ddi_get_parent(dip);

	ndi_devi_enter(pdip, &circ);
	mutex_enter(&(DEVI(dip)->devi_lock));
	if (DEVI_IS_DEVICE_OFFLINE(dip)) {
		devstate = DEVICE_OFFLINE;
	} else if (DEVI_IS_DEVICE_DOWN(dip)) {
		devstate = DEVICE_DOWN;
	} else {
		devstate = DEVICE_ONLINE;
		if (devi_stillreferenced(dip) == DEVI_REFERENCED)
			devstate |= DEVICE_BUSY;
	}

	mutex_exit(&(DEVI(dip)->devi_lock));
	ndi_devi_exit(pdip, circ);

	if (copyout(&devstate, dcp->cpyout_buf, sizeof (uint_t)) != 0)
		return (NDI_FAULT);

	return (NDI_SUCCESS);
}

/*
 * Return device's bus state
 * For use by a driver's DEVCTL_BUS_GETSTATE handler.
 */
int
ndi_devctl_bus_getstate(dev_info_t *dip, struct devctl_iocdata *dcp,
	uint_t *state)
{
	if ((dip == NULL) || (dcp == NULL))
		return (NDI_FAILURE);

	return (ndi_get_bus_state(dip, state));
}

/*
 * Generic devctl ioctl handler
 */
int
ndi_devctl_ioctl(dev_info_t *dip, int cmd, intptr_t arg, int mode, uint_t flags)
{
	_NOTE(ARGUNUSED(mode))
	struct devctl_iocdata *dcp;
	uint_t state;
	int rval = ENOTTY;

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {

	case DEVCTL_BUS_GETSTATE:
		rval = ndi_devctl_bus_getstate(dip, dcp, &state);
		if (rval == NDI_SUCCESS) {
			if (copyout(&state, dcp->cpyout_buf,
			    sizeof (uint_t)) != 0)
				rval = NDI_FAULT;
		}
		break;

	case DEVCTL_DEVICE_ONLINE:
		rval = ndi_devctl_device_online(dip, dcp, flags);
		break;

	case DEVCTL_DEVICE_OFFLINE:
		rval = ndi_devctl_device_offline(dip, dcp, flags);
		break;

	case DEVCTL_DEVICE_GETSTATE:
		rval = ndi_devctl_device_getstate(dip, dcp, &state);
		if (rval == NDI_SUCCESS) {
			if (copyout(&state, dcp->cpyout_buf,
			    sizeof (uint_t)) != 0)
				rval = NDI_FAULT;
		}
		break;

	case DEVCTL_DEVICE_REMOVE:
		rval = ndi_devctl_device_remove(dip, dcp, flags);
		break;

	case DEVCTL_BUS_DEV_CREATE:
		rval = ndi_dc_devi_create(dcp, dip, 0, NULL);
		break;

	/*
	 * ioctls for which a generic implementation makes no sense
	 */
	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:
	case DEVCTL_DEVICE_RESET:
	case DEVCTL_AP_CONNECT:
	case DEVCTL_AP_DISCONNECT:
	case DEVCTL_AP_INSERT:
	case DEVCTL_AP_REMOVE:
	case DEVCTL_AP_CONFIGURE:
	case DEVCTL_AP_UNCONFIGURE:
	case DEVCTL_AP_GETSTATE:
	case DEVCTL_AP_CONTROL:
	case DEVCTL_BUS_QUIESCE:
	case DEVCTL_BUS_UNQUIESCE:
		rval = ENOTSUP;
		break;
	}

	ndi_dc_freehdl(dcp);
	return (rval);
}

/*
 * Copyout the state of the Attachment Point "ap" to the requesting
 * user process.
 */
int
ndi_dc_return_ap_state(devctl_ap_state_t *ap, struct devctl_iocdata *dcp)
{
	if ((ap == NULL) || (dcp == NULL))
		return (NDI_FAILURE);


	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(ap, dcp->cpyout_buf,
		    sizeof (devctl_ap_state_t)) != 0)
			return (NDI_FAULT);
	}
#ifdef _SYSCALL32_IMPL
	else {
		struct devctl_ap_state32 ap_state32;

		ap_state32.ap_rstate = ap->ap_rstate;
		ap_state32.ap_ostate = ap->ap_ostate;
		ap_state32.ap_condition = ap->ap_condition;
		ap_state32.ap_error_code = ap->ap_error_code;
		ap_state32.ap_in_transition = ap->ap_in_transition;
		ap_state32.ap_last_change = (time32_t)ap->ap_last_change;
		if (copyout(&ap_state32, dcp->cpyout_buf,
		    sizeof (devctl_ap_state32_t)) != 0)
			return (NDI_FAULT);
	}
#endif

	return (NDI_SUCCESS);
}

/*
 * Copyout the bus state of the bus nexus device "dip" to the requesting
 * user process.
 */
int
ndi_dc_return_bus_state(dev_info_t *dip, struct devctl_iocdata *dcp)
{
	uint_t devstate = 0;

	if ((dip == NULL) || (dcp == NULL))
		return (NDI_FAILURE);

	if (ndi_get_bus_state(dip, &devstate) != NDI_SUCCESS)
		return (NDI_FAILURE);

	if (copyout(&devstate, dcp->cpyout_buf, sizeof (uint_t)) != 0)
		return (NDI_FAULT);

	return (NDI_SUCCESS);
}

static int
i_dc_devi_create(struct devctl_iocdata *, dev_info_t *, dev_info_t **);

/*
 * create a child device node given the property definitions
 * supplied by the userland process
 */
int
ndi_dc_devi_create(struct devctl_iocdata *dcp, dev_info_t *pdip, int flags,
    dev_info_t **rdip)
{
	dev_info_t *cdip;
	int rv, circular = 0;
	char devnm[MAXNAMELEN];
	int nmlen;

	/*
	 * The child device may have been pre-constructed by an earlier
	 * call to this function with the flag DEVCTL_CONSTRUCT set.
	 */

	if ((cdip = (rdip != NULL) ? *rdip : NULL) == NULL)
		if ((rv = i_dc_devi_create(dcp, pdip, &cdip)) != 0)
			return (rv);

	ASSERT(cdip != NULL);

	/*
	 * Return the device node partially constructed if the
	 * DEVCTL_CONSTRUCT flag is set.
	 */
	if (flags & DEVCTL_CONSTRUCT) {
		if (rdip == NULL) {
			(void) ndi_devi_free(cdip);
			return (EINVAL);
		}
		*rdip = cdip;
		return (0);
	}

	/*
	 * Bring the node up to a named but OFFLINE state.  The calling
	 * application will need to manage the node from here on.
	 */
	if (dcp->flags & DEVCTL_OFFLINE) {
		/*
		 * In the unlikely event that the dip was somehow attached by
		 * the userland process (and device contracts or LDI opens
		 * were registered against the dip) after it was created by
		 * a previous DEVCTL_CONSTRUCT call, we start notify
		 * proceedings on this dip. Note that we don't need to
		 * return the dip after a failure of the notify since
		 * for a contract or LDI handle to be created the dip was
		 * already available to the user.
		 */
		if (e_ddi_offline_notify(cdip) == DDI_FAILURE) {
			return (EBUSY);
		}

		/*
		 * hand set the OFFLINE flag to prevent any asynchronous
		 * autoconfiguration operations from attaching this node.
		 */
		mutex_enter(&(DEVI(cdip)->devi_lock));
		DEVI_SET_DEVICE_OFFLINE(cdip);
		mutex_exit(&(DEVI(cdip)->devi_lock));

		e_ddi_offline_finalize(cdip, DDI_SUCCESS);

		rv = ndi_devi_bind_driver(cdip, flags);
		if (rv != NDI_SUCCESS) {
			(void) ndi_devi_offline(cdip, NDI_DEVI_REMOVE);
			return (ENXIO);
		}

		/*
		 * remove the dev_info node if it failed to bind to a
		 * driver above.
		 */
		if (i_ddi_node_state(cdip) < DS_BOUND) {
			(void) ndi_devi_offline(cdip, NDI_DEVI_REMOVE);
			return (ENXIO);
		}

		/*
		 * add the node to the per-driver list and INITCHILD it
		 * to give it a name.
		 */
		ndi_devi_enter(pdip, &circular);
		if ((rv = ddi_initchild(pdip, cdip)) != DDI_SUCCESS) {
			(void) ndi_devi_offline(cdip, NDI_DEVI_REMOVE);
			ndi_devi_exit(pdip, circular);
			return (EINVAL);
		}
		ndi_devi_exit(pdip, circular);

	} else {
		/*
		 * Attempt to bring the device ONLINE. If the request to
		 * fails, remove the dev_info node.
		 */
		if (ndi_devi_online(cdip, NDI_ONLINE_ATTACH) != NDI_SUCCESS) {
			(void) ndi_devi_offline(cdip, NDI_DEVI_REMOVE);
			return (ENXIO);
		}

		/*
		 * if the node was successfully added but there was
		 * no driver available for the device, remove the node
		 */
		if (i_ddi_node_state(cdip) < DS_BOUND) {
			(void) ndi_devi_offline(cdip, NDI_DEVI_REMOVE);
			return (ENODEV);
		}
	}

	/*
	 * return a handle to the child device
	 * copy out the name of the newly attached child device if
	 * the IOCTL request has provided a copyout buffer.
	 */
	if (rdip != NULL)
		*rdip = cdip;

	if (dcp->cpyout_buf == NULL)
		return (0);

	ASSERT(ddi_node_name(cdip) != NULL);
	ASSERT(ddi_get_name_addr(cdip) != NULL);

	nmlen = snprintf(devnm, MAXNAMELEN, "%s@%s",
	    ddi_node_name(cdip), ddi_get_name_addr(cdip));

	if (copyout(&devnm, dcp->cpyout_buf, nmlen) != 0) {
		(void) ndi_devi_offline(cdip, NDI_DEVI_REMOVE);
		return (EFAULT);
	}
	return (0);
}

static int
i_dc_devi_create(struct devctl_iocdata *dcp, dev_info_t *pdip,
    dev_info_t **rdip)
{

	dev_info_t *cdip;
	char *cname = NULL;
	nvlist_t *nvlp = dcp->nvl_user;
	nvpair_t *npp;
	char *np;
	int rv = 0;

	ASSERT(rdip != NULL && *rdip == NULL);

	if ((nvlp == NULL) ||
	    (nvlist_lookup_string(nvlp, DC_DEVI_NODENAME, &cname) != 0))
		return (EINVAL);

	/*
	 * construct a new dev_info node with a user-provided nodename
	 */
	ndi_devi_alloc_sleep(pdip, cname, (pnode_t)DEVI_SID_NODEID, &cdip);

	/*
	 * create hardware properties for each member in the property
	 * list.
	 */
	for (npp = nvlist_next_nvpair(nvlp, NULL); (npp != NULL && !rv);
	    npp = nvlist_next_nvpair(nvlp, npp)) {

		np = nvpair_name(npp);

		/*
		 * skip the nodename property
		 */
		if (strcmp(np, DC_DEVI_NODENAME) == 0)
			continue;

		switch (nvpair_type(npp)) {

		case DATA_TYPE_INT32: {
			int32_t prop_val;

			if ((rv = nvpair_value_int32(npp, &prop_val)) != 0)
				break;

			(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip, np,
			    (int)prop_val);
			break;
		}

		case DATA_TYPE_STRING: {
			char *prop_val;

			if ((rv = nvpair_value_string(npp, &prop_val)) != 0)
				break;

			(void) ndi_prop_update_string(DDI_DEV_T_NONE, cdip,
			    np, prop_val);
			break;
		}

		case DATA_TYPE_BYTE_ARRAY: {
			uchar_t *val;
			uint_t nelms;

			if ((rv = nvpair_value_byte_array(npp, &val,
			    &nelms)) != 0)
				break;

			(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE,
			    cdip, np, (uchar_t *)val, nelms);
			break;
		}

		case DATA_TYPE_INT32_ARRAY: {
			int32_t *val;
			uint_t nelms;

			if ((rv = nvpair_value_int32_array(npp, &val,
			    &nelms)) != 0)
				break;

			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
			    cdip, np, val, nelms);
			break;
		}

		case DATA_TYPE_STRING_ARRAY: {
			char **val;
			uint_t nelms;

			if ((rv = nvpair_value_string_array(npp, &val,
			    &nelms)) != 0)
				break;

			(void) ndi_prop_update_string_array(DDI_DEV_T_NONE,
			    cdip, np, val, nelms);
			break;
		}

		/*
		 * unsupported property data type
		 */
		default:
			rv = EINVAL;
		}
	}

	/*
	 * something above failed
	 * destroy the partially child device and abort the request
	 */
	if (rv != 0) {
		(void) ndi_devi_free(cdip);
		return (rv);
	}

	*rdip = cdip;
	return (0);
}

/*
 * return current soft bus state of bus nexus "dip"
 */
int
ndi_get_bus_state(dev_info_t *dip, uint_t *rstate)
{
	if (dip == NULL || rstate == NULL)
		return (NDI_FAILURE);

	if (DEVI(dip)->devi_ops->devo_bus_ops == NULL)
		return (NDI_FAILURE);

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (DEVI_IS_BUS_QUIESCED(dip))
		*rstate = BUS_QUIESCED;
	else if (DEVI_IS_BUS_DOWN(dip))
		*rstate = BUS_SHUTDOWN;
	else
		*rstate = BUS_ACTIVE;
	mutex_exit(&(DEVI(dip)->devi_lock));
	return (NDI_SUCCESS);
}

/*
 * Set the soft state of bus nexus "dip"
 */
int
ndi_set_bus_state(dev_info_t *dip, uint_t state)
{
	int rv = NDI_SUCCESS;

	if (dip == NULL)
		return (NDI_FAILURE);

	mutex_enter(&(DEVI(dip)->devi_lock));

	switch (state) {
	case BUS_QUIESCED:
		DEVI_SET_BUS_QUIESCE(dip);
		break;

	case BUS_ACTIVE:
		DEVI_SET_BUS_ACTIVE(dip);
		DEVI_SET_BUS_UP(dip);
		break;

	case BUS_SHUTDOWN:
		DEVI_SET_BUS_DOWN(dip);
		break;

	default:
		rv = NDI_FAILURE;
	}

	mutex_exit(&(DEVI(dip)->devi_lock));
	return (rv);
}

/*
 * These dummy functions are obsolete and may be removed.
 * Retained for existing driver compatibility only.
 * Drivers should be fixed not to use these functions.
 * Don't write new code using these obsolete interfaces.
 */
/*ARGSUSED*/
void
i_ndi_block_device_tree_changes(uint_t *lkcnt)	/* obsolete */
{
	/* obsolete dummy function */
}

/*ARGSUSED*/
void
i_ndi_allow_device_tree_changes(uint_t lkcnt)	/* obsolete */
{
	/* obsolete dummy function */
}

/*
 * Single thread entry into per-driver list
 */
/*ARGSUSED*/
void
e_ddi_enter_driver_list(struct devnames *dnp, int *listcnt)	/* obsolete */
{
	/* obsolete dummy function */
}

/*
 * release the per-driver list
 */
/*ARGSUSED*/
void
e_ddi_exit_driver_list(struct devnames *dnp, int listcnt)	/* obsolete */
{
	/* obsolete dummy function */
}

/*
 * Attempt to enter driver list
 */
/*ARGSUSED*/
int
e_ddi_tryenter_driver_list(struct devnames *dnp, int *listcnt)	/* obsolete */
{
	return (1);	/* obsolete dummy function */
}

/*
 * ndi event handling support functions:
 * The NDI event support model is as follows:
 *
 * The nexus driver defines a set of events using some static structures (so
 * these structures can be shared by all instances of the nexus driver).
 * The nexus driver allocates an event handle and binds the event set
 * to this handle. The nexus driver's event busop functions can just
 * call the appropriate NDI event support function using this handle
 * as the first argument.
 *
 * The reasoning for tying events to the device tree is that the entity
 * generating the callback will typically be one of the device driver's
 * ancestors in the tree.
 */
static int ndi_event_debug = 0;

#ifdef DEBUG
#define	NDI_EVENT_DEBUG	ndi_event_debug
#endif /* DEBUG */

/*
 * allocate a new ndi event handle
 */
int
ndi_event_alloc_hdl(dev_info_t *dip, ddi_iblock_cookie_t cookie,
	ndi_event_hdl_t *handle, uint_t flag)
{
	struct ndi_event_hdl *ndi_event_hdl;

	ndi_event_hdl = kmem_zalloc(sizeof (struct ndi_event_hdl),
	    ((flag & NDI_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP));

	if (!ndi_event_hdl) {
		return (NDI_FAILURE);
	}

	ndi_event_hdl->ndi_evthdl_dip = dip;
	ndi_event_hdl->ndi_evthdl_iblock_cookie = cookie;
	mutex_init(&ndi_event_hdl->ndi_evthdl_mutex, NULL,
	    MUTEX_DRIVER, (void *)cookie);

	mutex_init(&ndi_event_hdl->ndi_evthdl_cb_mutex, NULL,
	    MUTEX_DRIVER, (void *)cookie);

	*handle = (ndi_event_hdl_t)ndi_event_hdl;

	return (NDI_SUCCESS);
}

/*
 * free the ndi event handle
 */
int
ndi_event_free_hdl(ndi_event_hdl_t handle)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	ndi_event_cookie_t *cookie;
	ndi_event_cookie_t *free;

	ASSERT(handle);

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);
	mutex_enter(&ndi_event_hdl->ndi_evthdl_cb_mutex);

	cookie = ndi_event_hdl->ndi_evthdl_cookie_list;

	/* deallocate all defined cookies */
	while (cookie != NULL) {
		ASSERT(cookie->callback_list == NULL);
		free = cookie;
		cookie = cookie->next_cookie;

		kmem_free(free, sizeof (ndi_event_cookie_t));
	}


	mutex_exit(&ndi_event_hdl->ndi_evthdl_cb_mutex);
	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

	/* destroy mutexes */
	mutex_destroy(&ndi_event_hdl->ndi_evthdl_mutex);
	mutex_destroy(&ndi_event_hdl->ndi_evthdl_cb_mutex);

	/* free event handle */
	kmem_free(ndi_event_hdl, sizeof (struct ndi_event_hdl));

	return (NDI_SUCCESS);
}


/*
 * ndi_event_bind_set() adds a set of events to the NDI event
 * handle.
 *
 * Events generated by high level interrupts should not
 * be mixed in the same event set with events generated by
 * normal interrupts or kernel events.
 *
 * This function can be called multiple times to bind
 * additional sets to the event handle.
 * However, events generated by high level interrupts cannot
 * be bound to a handle that already has bound events generated
 * by normal interrupts or from kernel context and vice versa.
 */
int
ndi_event_bind_set(ndi_event_hdl_t handle,
	ndi_event_set_t		*ndi_events,
	uint_t			flag)
{
	struct ndi_event_hdl	*ndi_event_hdl;
	ndi_event_cookie_t	*next, *prev, *new_cookie;
	uint_t			i, len;
	uint_t			dup = 0;
	uint_t			high_plevels, other_plevels;
	ndi_event_definition_t *ndi_event_defs;

	int km_flag = ((flag & NDI_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP);

	ASSERT(handle);
	ASSERT(ndi_events);

	/*
	 * binding must be performed during attach/detach
	 */
	if (!DEVI_IS_ATTACHING(handle->ndi_evthdl_dip) &&
	    !DEVI_IS_DETACHING(handle->ndi_evthdl_dip)) {
		cmn_err(CE_WARN, "ndi_event_bind_set must be called within "
		    "attach or detach");
		return (NDI_FAILURE);
	}

	/*
	 * if it is not the correct version or the event set is
	 * empty, bail out
	 */
	if (ndi_events->ndi_events_version != NDI_EVENTS_REV1)
		return (NDI_FAILURE);

	ndi_event_hdl	= (struct ndi_event_hdl *)handle;
	ndi_event_defs = ndi_events->ndi_event_defs;
	high_plevels	= other_plevels = 0;

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	/* check for mixing events at high level with the other types */
	for (i = 0; i < ndi_events->ndi_n_events; i++) {
		if (ndi_event_defs[i].ndi_event_plevel == EPL_HIGHLEVEL) {
			high_plevels++;
		} else {
			other_plevels++;
		}
	}

	/*
	 * bail out if high level events are mixed with other types in this
	 * event set or the set is incompatible with the set in the handle
	 */
	if ((high_plevels && other_plevels) ||
	    (other_plevels && ndi_event_hdl->ndi_evthdl_high_plevels) ||
	    (high_plevels && ndi_event_hdl->ndi_evthdl_other_plevels)) {
		mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

		return (NDI_FAILURE);
	}

	/*
	 * check for duplicate events in both the existing handle
	 * and the event set, add events if not duplicates
	 */
	next = ndi_event_hdl->ndi_evthdl_cookie_list;
	for (i = 0; i < ndi_events->ndi_n_events; i++) {
		while (next != NULL) {
			len = strlen(NDI_EVENT_NAME(next)) + 1;
			if (strncmp(NDI_EVENT_NAME(next),
			    ndi_event_defs[i].ndi_event_name, len) == 0) {
				dup = 1;
				break;
			}

			prev = next;
			next = next->next_cookie;
		}

		if (dup == 0) {
			new_cookie = kmem_zalloc(sizeof (ndi_event_cookie_t),
			    km_flag);

			if (!new_cookie)
				return (NDI_FAILURE);

			if (ndi_event_hdl->ndi_evthdl_n_events == 0) {
				ndi_event_hdl->ndi_evthdl_cookie_list =
				    new_cookie;
			} else {
				prev->next_cookie = new_cookie;
			}

			ndi_event_hdl->ndi_evthdl_n_events++;

			/*
			 * set up new cookie
			 */
			new_cookie->definition = &ndi_event_defs[i];
			new_cookie->ddip = ndi_event_hdl->ndi_evthdl_dip;

		} else {
			/*
			 * event not added, must correct plevel numbers
			 */
			if (ndi_event_defs[i].ndi_event_plevel ==
			    EPL_HIGHLEVEL) {
				high_plevels--;
			} else {
				other_plevels--;
			}
		}

		dup = 0;
		next = ndi_event_hdl->ndi_evthdl_cookie_list;
		prev = NULL;

	}

	ndi_event_hdl->ndi_evthdl_high_plevels	+= high_plevels;
	ndi_event_hdl->ndi_evthdl_other_plevels += other_plevels;

	ASSERT((ndi_event_hdl->ndi_evthdl_high_plevels == 0) ||
	    (ndi_event_hdl->ndi_evthdl_other_plevels == 0));

#ifdef NDI_EVENT_DEBUG
	if (ndi_event_debug) {
		ndi_event_dump_hdl(ndi_event_hdl, "ndi_event_bind_set");
	}
#endif /* NDI_EVENT_DEBUG */

	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

	return (NDI_SUCCESS);
}

/*
 * ndi_event_unbind_set() unbinds a set of events, previously
 * bound using ndi_event_bind_set(), from the NDI event
 * handle.
 *
 * This routine will unbind all events in the event set.  If an event,
 * specified in the event set, is not found in the handle, this
 * routine will proceed onto the next member of the set as if the event
 * was never specified.
 *
 * The event set may be a subset of the set of events that
 * was previously bound to the handle. For example, events
 * can be individually unbound.
 *
 * An event cannot be unbound if callbacks are still
 * registered against the event.
 */
/*ARGSUSED*/
int
ndi_event_unbind_set(ndi_event_hdl_t   handle, ndi_event_set_t	*ndi_events,
    uint_t flag)
{
	ndi_event_definition_t	*ndi_event_defs;
	int			len;
	uint_t			i;
	int			rval;
	ndi_event_cookie_t *cookie_list;
	ndi_event_cookie_t *prev = NULL;

	ASSERT(ndi_events);
	ASSERT(handle);

	/*
	 * binding must be performed during attach/detac
	 */
	if (!DEVI_IS_ATTACHING(handle->ndi_evthdl_dip) &&
	    !DEVI_IS_DETACHING(handle->ndi_evthdl_dip)) {
		cmn_err(CE_WARN, "ndi_event_bind_set must be called within "
		    "attach or detach");
		return (NDI_FAILURE);
	}

	/* bail out if ndi_event_set is outdated */
	if (ndi_events->ndi_events_version != NDI_EVENTS_REV1) {
		return (NDI_FAILURE);
	}

	ASSERT(ndi_events->ndi_event_defs);

	ndi_event_defs = ndi_events->ndi_event_defs;

	mutex_enter(&handle->ndi_evthdl_mutex);
	mutex_enter(&handle->ndi_evthdl_cb_mutex);

	/*
	 * Verify that all events in the event set are eligible
	 * for unbinding(ie. there are no outstanding callbacks).
	 * If any one of the events are ineligible, fail entire
	 * operation.
	 */

	for (i = 0; i < ndi_events->ndi_n_events; i++) {
		cookie_list = handle->ndi_evthdl_cookie_list;
		while (cookie_list != NULL) {
			len = strlen(NDI_EVENT_NAME(cookie_list)) + 1;
			if (strncmp(NDI_EVENT_NAME(cookie_list),
			    ndi_event_defs[i].ndi_event_name, len) == 0) {

				ASSERT(cookie_list->callback_list == NULL);
				if (cookie_list->callback_list) {
					rval = NDI_FAILURE;
					goto done;
				}
				break;
			} else {
				cookie_list = cookie_list->next_cookie;
			}
		}
	}

	/*
	 * remove all events found within the handle
	 * If an event is not found, this function will proceed as if the event
	 * was never specified.
	 */

	for (i = 0; i < ndi_events->ndi_n_events; i++) {
		cookie_list = handle->ndi_evthdl_cookie_list;
		prev = NULL;
		while (cookie_list != NULL) {
			len = strlen(NDI_EVENT_NAME(cookie_list)) + 1;
			if (strncmp(NDI_EVENT_NAME(cookie_list),
			    ndi_event_defs[i].ndi_event_name, len) == 0) {

				/*
				 * can not unbind an event definition with
				 * outstanding callbacks
				 */
				if (cookie_list->callback_list) {
					rval = NDI_FAILURE;
					goto done;
				}

				/* remove this cookie from the list */
				if (prev != NULL) {
					prev->next_cookie =
					    cookie_list->next_cookie;
				} else {
					handle->ndi_evthdl_cookie_list =
					    cookie_list->next_cookie;
				}

				/* adjust plevel counts */
				if (NDI_EVENT_PLEVEL(cookie_list) ==
				    EPL_HIGHLEVEL) {
					handle->ndi_evthdl_high_plevels--;
				} else {
					handle->ndi_evthdl_other_plevels--;
				}

				/* adjust cookie count */
				handle->ndi_evthdl_n_events--;

				/* free the cookie */
				kmem_free(cookie_list,
				    sizeof (ndi_event_cookie_t));

				cookie_list = handle->ndi_evthdl_cookie_list;
				break;

			} else {
				prev = cookie_list;
				cookie_list = cookie_list->next_cookie;
			}

		}

	}

#ifdef NDI_EVENT_DEBUG
	if (ndi_event_debug) {
		ndi_event_dump_hdl(handle, "ndi_event_unbind_set");
	}
#endif /* NDI_EVENT_DEBUG */

	rval = NDI_SUCCESS;

done:
	mutex_exit(&handle->ndi_evthdl_cb_mutex);
	mutex_exit(&handle->ndi_evthdl_mutex);

	return (rval);
}

/*
 * ndi_event_retrieve_cookie():
 * Return an event cookie for eventname if this nexus driver
 * has defined the named event. The event cookie returned
 * by this function is used to register callback handlers
 * for the event.
 *
 * ndi_event_retrieve_cookie() is intended to be used in the
 * nexus driver's bus_get_eventcookie busop routine.
 *
 * If the event is not defined by this bus nexus driver, and flag
 * does not include NDI_EVENT_NOPASS, then ndi_event_retrieve_cookie()
 * will pass the request up the device tree hierarchy by calling
 * ndi_busop_get_eventcookie(9N).
 * If the event is not defined by this bus nexus driver, and flag
 * does include NDI_EVENT_NOPASS, ndi_event_retrieve_cookie()
 * will return NDI_FAILURE.  The caller may then determine what further
 * action to take, such as using a different handle, passing the
 * request up the device tree using ndi_busop_get_eventcookie(9N),
 * or returning the failure to the caller, thus blocking the
 * progress of the request up the tree.
 */
int
ndi_event_retrieve_cookie(ndi_event_hdl_t handle,
	dev_info_t		*rdip,
	char			*eventname,
	ddi_eventcookie_t	*cookiep,
	uint_t			flag)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	int		len;
	ndi_event_cookie_t *cookie_list;

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	cookie_list = ndi_event_hdl->ndi_evthdl_cookie_list;
	/*
	 * search the cookie list for the event name and return
	 * cookie if found.
	 */
	while (cookie_list != NULL) {

		len = strlen(NDI_EVENT_NAME(cookie_list)) + 1;
		if (strncmp(NDI_EVENT_NAME(cookie_list), eventname,
		    len) == 0) {
			*cookiep = (ddi_eventcookie_t)cookie_list;

			mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
			return (NDI_SUCCESS);
		}

		cookie_list = cookie_list->next_cookie;
	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
	/*
	 * event was not found, pass up or return failure
	 */
	if ((flag & NDI_EVENT_NOPASS) == 0) {
		return (ndi_busop_get_eventcookie(
		    ndi_event_hdl->ndi_evthdl_dip, rdip, eventname, cookiep));
	} else {
		return (NDI_FAILURE);
	}
}

/*
 * check whether this nexus defined this event and look up attributes
 */
static int
ndi_event_is_defined(ndi_event_hdl_t handle,
	ddi_eventcookie_t cookie, int *attributes)
{

	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	ndi_event_cookie_t *cookie_list;

	ASSERT(mutex_owned(&handle->ndi_evthdl_mutex));

	cookie_list = ndi_event_hdl->ndi_evthdl_cookie_list;
	while (cookie_list != NULL) {
		if (cookie_list == NDI_EVENT(cookie)) {
			if (attributes)
				*attributes =
				    NDI_EVENT_ATTRIBUTES(cookie_list);

			return (NDI_SUCCESS);
		}

		cookie_list = cookie_list->next_cookie;
	}

	return (NDI_FAILURE);
}

/*
 * ndi_event_add_callback(): adds an event callback registration
 * to the event cookie defining this event.
 *
 * Refer also to bus_add_eventcall(9n) and ndi_busop_add_eventcall(9n).
 *
 * ndi_event_add_callback(9n) is intended to be used in
 * the nexus driver's bus_add_eventcall(9n) busop function.
 *
 * If the event is not defined by this bus nexus driver,
 * ndi_event_add_callback() will return NDI_FAILURE.
 */
int
ndi_event_add_callback(ndi_event_hdl_t handle, dev_info_t *child_dip,
	ddi_eventcookie_t cookie,
	void		(*event_callback)(dev_info_t *,
			ddi_eventcookie_t, void *arg, void *impldata),
	void		*arg,
	uint_t		flag,
	ddi_callback_id_t *cb_id)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	int km_flag = ((flag & NDI_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP);
	ndi_event_callbacks_t *cb;

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	/*
	 * if the event was not bound to this handle, return failure
	 */
	if (ndi_event_is_defined(handle, cookie, NULL) != NDI_SUCCESS) {

		mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
		return (NDI_FAILURE);

	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

	/*
	 * allocate space for a callback structure
	 */
	cb = kmem_zalloc(sizeof (ndi_event_callbacks_t), km_flag);
	if (cb == NULL) {
		return (NDI_FAILURE);
	}

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	/* initialize callback structure */
	cb->ndi_evtcb_dip	= child_dip;
	cb->ndi_evtcb_callback	= event_callback;
	cb->ndi_evtcb_arg	= arg;
	cb->ndi_evtcb_cookie	= cookie;
	cb->devname		= (char *)ddi_driver_name(child_dip);

	*cb_id = (ddi_callback_id_t)cb;
	mutex_enter(&ndi_event_hdl->ndi_evthdl_cb_mutex);

	/* add this callback structure to the list */
	if (NDI_EVENT(cookie)->callback_list) {
		cb->ndi_evtcb_next = NDI_EVENT(cookie)->callback_list;
		NDI_EVENT(cookie)->callback_list->ndi_evtcb_prev = cb;
		NDI_EVENT(cookie)->callback_list = cb;
	} else {
		NDI_EVENT(cookie)->callback_list = cb;
	}
#ifdef NDI_EVENT_DEBUG
	if (ndi_event_debug) {
		ndi_event_dump_hdl(ndi_event_hdl, "ndi_event_add_callback");
	}
#endif /* NDI_EVENT_DEBUG */

	mutex_exit(&ndi_event_hdl->ndi_evthdl_cb_mutex);
	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

	return (NDI_SUCCESS);
}

/*
 * ndi_event_remove_callback():
 *
 * ndi_event_remove_callback() removes a callback that was
 * previously registered using ndi_event_add_callback(9N).
 * Refer also to bus_remove_eventcall(9n) and
 * ndi_busop_remove_eventcall(9n).
 * ndi_event_remove_callback(9n) is intended to be used in
 * the nexus driver's bus_remove_eventcall (9n) busop function.
 * If the event is not defined by this bus nexus driver,
 * ndi_event_remove_callback() will return NDI_FAILURE.
 */
static void do_ndi_event_remove_callback(struct ndi_event_hdl *ndi_event_hdl,
	ddi_callback_id_t cb_id);

int
ndi_event_remove_callback(ndi_event_hdl_t handle, ddi_callback_id_t cb_id)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;

	ASSERT(cb_id);

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);
	mutex_enter(&ndi_event_hdl->ndi_evthdl_cb_mutex);

	do_ndi_event_remove_callback(ndi_event_hdl, cb_id);

	mutex_exit(&ndi_event_hdl->ndi_evthdl_cb_mutex);
	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

	return (NDI_SUCCESS);
}

/*ARGSUSED*/
static void
do_ndi_event_remove_callback(struct ndi_event_hdl *ndi_event_hdl,
    ddi_callback_id_t cb_id)
{
	ndi_event_callbacks_t *cb = (ndi_event_callbacks_t *)cb_id;
	ASSERT(cb);

	ASSERT(mutex_owned(&ndi_event_hdl->ndi_evthdl_mutex));
	ASSERT(mutex_owned(&ndi_event_hdl->ndi_evthdl_cb_mutex));

	/* remove from callback linked list */
	if (cb->ndi_evtcb_prev) {
		cb->ndi_evtcb_prev->ndi_evtcb_next = cb->ndi_evtcb_next;
	}

	if (cb->ndi_evtcb_next) {
		cb->ndi_evtcb_next->ndi_evtcb_prev = cb->ndi_evtcb_prev;
	}

	if (NDI_EVENT(cb->ndi_evtcb_cookie)->callback_list == cb) {
		NDI_EVENT(cb->ndi_evtcb_cookie)->callback_list =
		    cb->ndi_evtcb_next;
	}

	kmem_free(cb, sizeof (ndi_event_callbacks_t));
}

/*
 * ndi_event_run_callbacks() performs event callbacks for the event
 * specified by cookie, if this is among those bound to the
 * supplied handle.
 * If the event is among those bound to the handle, none,
 * some, or all of the handlers registered for the event
 * will be called, according to the delivery attributes of
 * the event.
 * If the event attributes include NDI_EVENT_POST_TO_ALL
 * (the default), all the handlers for the event will be
 * called in an unspecified order.
 * If the event attributes include NDI_EVENT_POST_TO_TGT, only
 * the handlers (if any) registered by the driver identified by
 * rdip will be called.
 * If the event identified by cookie is not bound to the handle,
 * NDI_FAILURE will be returned.
 */
int
ndi_event_run_callbacks(ndi_event_hdl_t handle, dev_info_t *child_dip,
	ddi_eventcookie_t cookie, void *bus_impldata)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	ndi_event_callbacks_t *next, *cb;
	int attributes;

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	/* if this is not our event, fail */
	if (ndi_event_is_defined(handle, cookie, &attributes) !=
	    NDI_SUCCESS) {

		mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
		return (NDI_FAILURE);
	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

#ifdef NDI_EVENT_DEBUG
	if (ndi_event_debug) {
		cmn_err(CE_CONT, "ndi_event_run_callbacks:\n\t"
		    "producer dip=%p (%s%d): cookie = %p, name = %s\n",
		    (void *)ndi_event_hdl->ndi_evthdl_dip,
		    ddi_node_name(ndi_event_hdl->ndi_evthdl_dip),
		    ddi_get_instance(ndi_event_hdl->ndi_evthdl_dip),
		    (void *)cookie,
		    ndi_event_cookie_to_name(handle, cookie));
	}
#endif /* #ifdef NDI_EVENT_DEBUG */


	/*
	 * The callback handlers may call conversion functions.  The conversion
	 * functions may hold the ndi_evthdl_mutex during execution.  Thus, to
	 * avoid a recursive mutex problem, only the ndi_evthdl_cb_mutex is
	 * held.  The ndi_evthdl_mutex is not held when running the callbacks.
	 */
	mutex_enter(&ndi_event_hdl->ndi_evthdl_cb_mutex);

	/* perform callbacks */
	next = NDI_EVENT(cookie)->callback_list;
	while (next != NULL) {

		cb = next;
		next = next->ndi_evtcb_next;

		ASSERT(cb->ndi_evtcb_cookie == cookie);

		if (attributes == NDI_EVENT_POST_TO_TGT &&
		    child_dip != cb->ndi_evtcb_dip) {
			continue;
		}

		cb->ndi_evtcb_callback(cb->ndi_evtcb_dip, cb->ndi_evtcb_cookie,
		    cb->ndi_evtcb_arg, bus_impldata);

#ifdef NDI_EVENT_DEBUG
		if (ndi_event_debug) {
			cmn_err(CE_CONT,
			    "\t\tconsumer dip=%p (%s%d)\n",
			    (void *)cb->ndi_evtcb_dip,
			    ddi_node_name(cb->ndi_evtcb_dip),
			    ddi_get_instance(cb->ndi_evtcb_dip));
		}
#endif

	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_cb_mutex);

#ifdef NDI_EVENT_DEBUG
	if (ndi_event_debug) {
		mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);
		ndi_event_dump_hdl(ndi_event_hdl, "ndi_event_run_callbacks");
		mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
	}
#endif /* NDI_EVENT_DEBUG */

	return (NDI_SUCCESS);
}


/*
 * perform one callback for a specified cookie and just one target
 */
int
ndi_event_do_callback(ndi_event_hdl_t handle, dev_info_t *child_dip,
	ddi_eventcookie_t cookie, void *bus_impldata)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	ndi_event_callbacks_t *next, *cb;
	int attributes;

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	/* if this is not our event, fail */
	if (ndi_event_is_defined(handle, cookie, &attributes) !=
	    NDI_SUCCESS) {

		mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

		return (NDI_FAILURE);
	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

#ifdef NDI_EVENT_DEBUG
	if (ndi_event_debug) {
		cmn_err(CE_CONT, "ndi_event_run_callbacks:\n\t"
		    "producer dip=%p (%s%d): cookie = %p, name = %s\n",
		    (void *)ndi_event_hdl->ndi_evthdl_dip,
		    ddi_node_name(ndi_event_hdl->ndi_evthdl_dip),
		    ddi_get_instance(ndi_event_hdl->ndi_evthdl_dip),
		    (void *)cookie,
		    ndi_event_cookie_to_name(handle, cookie));
	}
#endif


	/*
	 * we only grab the cb mutex because the callback handlers
	 * may call the conversion functions which would cause a recursive
	 * mutex problem
	 */
	mutex_enter(&ndi_event_hdl->ndi_evthdl_cb_mutex);

	/* perform callbacks */
	for (next = NDI_EVENT(cookie)->callback_list; next != NULL; ) {
		cb = next;
		next = next->ndi_evtcb_next;

		if (cb->ndi_evtcb_dip == child_dip) {
			cb->ndi_evtcb_callback(cb->ndi_evtcb_dip,
			    cb->ndi_evtcb_cookie, cb->ndi_evtcb_arg,
			    bus_impldata);

#ifdef NDI_EVENT_DEBUG
			if (ndi_event_debug) {
				cmn_err(CE_CONT,
				    "\t\tconsumer dip=%p (%s%d)\n",
				    (void *)cb->ndi_evtcb_dip,
				    ddi_node_name(cb->ndi_evtcb_dip),
				    ddi_get_instance(cb->ndi_evtcb_dip));
			}
#endif
			break;
		}
	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_cb_mutex);

#ifdef NDI_EVENT_DEBUG
	if (ndi_event_debug) {
		mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);
		ndi_event_dump_hdl(ndi_event_hdl, "ndi_event_run_callbacks");
		mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
	}
#endif /* NDI_EVENT_DEBUG */

	return (NDI_SUCCESS);
}


/*
 * ndi_event_tag_to_cookie: utility function to find an event cookie
 * given an event tag
 */
ddi_eventcookie_t
ndi_event_tag_to_cookie(ndi_event_hdl_t handle, int event_tag)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	ndi_event_cookie_t *list;

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	list = ndi_event_hdl->ndi_evthdl_cookie_list;
	while (list != NULL) {
		if (NDI_EVENT_TAG(list) == event_tag) {
			mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
			return ((ddi_eventcookie_t)list);
		}

		list = list->next_cookie;
	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
	return (NULL);
}

/*
 * ndi_event_cookie_to_tag: utility function to find a event tag
 * given an event_cookie
 */
int
ndi_event_cookie_to_tag(ndi_event_hdl_t handle, ddi_eventcookie_t cookie)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	ndi_event_cookie_t *list;

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	list = ndi_event_hdl->ndi_evthdl_cookie_list;

	while (list != NULL) {
		if ((ddi_eventcookie_t)list == cookie) {
			mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
			return (NDI_EVENT_TAG(list));
		}

		list = list->next_cookie;
	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
	return (NDI_FAILURE);

}

/*
 * ndi_event_cookie_to_name: utility function to find an event name
 * given an event_cookie
 */
char *
ndi_event_cookie_to_name(ndi_event_hdl_t handle, ddi_eventcookie_t cookie)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	ndi_event_cookie_t *list;

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	list = ndi_event_hdl->ndi_evthdl_cookie_list;

	while (list != NULL) {
		if (list == NDI_EVENT(cookie)) {
			mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
			return (NDI_EVENT_NAME(list));
		}

		list = list->next_cookie;
	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
	return (NULL);
}

/*
 * ndi_event_tag_to_name: utility function to find an event name
 * given an event tag
 */
char *
ndi_event_tag_to_name(ndi_event_hdl_t handle, int event_tag)
{
	struct ndi_event_hdl *ndi_event_hdl = (struct ndi_event_hdl *)handle;
	ndi_event_cookie_t *list;

	mutex_enter(&ndi_event_hdl->ndi_evthdl_mutex);

	list = ndi_event_hdl->ndi_evthdl_cookie_list;

	while (list) {
		if (NDI_EVENT_TAG(list) == event_tag) {
			mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);
			return (NDI_EVENT_NAME(list));
		}

		list = list->next_cookie;
	}

	mutex_exit(&ndi_event_hdl->ndi_evthdl_mutex);

	return (NULL);
}

#ifdef NDI_EVENT_DEBUG
void
ndi_event_dump_hdl(struct ndi_event_hdl *hdl, char *location)
{


	ndi_event_callbacks_t *next;
	ndi_event_cookie_t *list;

	ASSERT(mutex_owned(&hdl->ndi_evthdl_mutex));
	list = hdl->ndi_evthdl_cookie_list;

	cmn_err(CE_CONT, "%s: event handle (%p): dip = %p (%s%d)\n",
	    location, (void *)hdl, (void *)hdl->ndi_evthdl_dip,
	    ddi_node_name(hdl->ndi_evthdl_dip),
	    ddi_get_instance(hdl->ndi_evthdl_dip));
	cmn_err(CE_CONT, "\thigh=%d other=%d n=%d\n",
	    hdl->ndi_evthdl_high_plevels, hdl->ndi_evthdl_other_plevels,
	    hdl->ndi_evthdl_n_events);

	cmn_err(CE_CONT, "\tevent cookies:\n");
	while (list) {
		cmn_err(CE_CONT, "\t\ttag=%d name=%s p=%d a=%x dd=%p\n",
		    NDI_EVENT_TAG(list), NDI_EVENT_NAME(list),
		    NDI_EVENT_PLEVEL(list), NDI_EVENT_ATTRIBUTES(list),
		    (void *)NDI_EVENT_DDIP(list));
		cmn_err(CE_CONT, "\t\tcallbacks:\n");
		for (next = list->callback_list; next != NULL;
		    next = next->ndi_evtcb_next) {
			cmn_err(CE_CONT,
			    "\t\t  dip=%p (%s%d) cookie=%p arg=%p\n",
			    (void*)next->ndi_evtcb_dip,
			    ddi_driver_name(next->ndi_evtcb_dip),
			    ddi_get_instance(next->ndi_evtcb_dip),
			    (void *)next->ndi_evtcb_cookie,
			    next->ndi_evtcb_arg);
		}

		list = list->next_cookie;
	}

	cmn_err(CE_CONT, "\n");
}
#endif

int
ndi_dev_is_prom_node(dev_info_t *dip)
{
	return (DEVI(dip)->devi_node_class == DDI_NC_PROM);
}

int
ndi_dev_is_pseudo_node(dev_info_t *dip)
{
	/*
	 * NOTE: this does NOT mean the pseudo branch of the device tree,
	 * it means the node was created by software (DEVI_SID_NODEID ||
	 * DEVI_PSEUDO_NODEID || DEVI_SID_HIDDEN_NODEID) instead of being
	 * generated from a PROM node.
	 */
	return (DEVI(dip)->devi_node_class == DDI_NC_PSEUDO);
}

int
ndi_dev_is_persistent_node(dev_info_t *dip)
{
	return ((DEVI(dip)->devi_node_attributes & DDI_PERSISTENT) != 0);
}

int
ndi_dev_is_hidden_node(dev_info_t *dip)
{
	return ((DEVI(dip)->devi_node_attributes & DDI_HIDDEN_NODE) != 0);
}

int
ndi_dev_is_hotplug_node(dev_info_t *dip)
{
	return ((DEVI(dip)->devi_node_attributes & DDI_HOTPLUG_NODE) != 0);
}

void
ndi_devi_set_hidden(dev_info_t *dip)
{
	DEVI(dip)->devi_node_attributes |= DDI_HIDDEN_NODE;
}

void
ndi_devi_clr_hidden(dev_info_t *dip)
{
	DEVI(dip)->devi_node_attributes &= ~DDI_HIDDEN_NODE;
}

int
i_ndi_dev_is_auto_assigned_node(dev_info_t *dip)
{
	return ((DEVI(dip)->devi_node_attributes &
	    DDI_AUTO_ASSIGNED_NODEID) != 0);
}

void
i_ndi_set_node_class(dev_info_t *dip, ddi_node_class_t c)
{
	DEVI(dip)->devi_node_class = c;
}

ddi_node_class_t
i_ndi_get_node_class(dev_info_t *dip)
{
	return (DEVI(dip)->devi_node_class);
}

void
i_ndi_set_node_attributes(dev_info_t *dip, int p)
{
	DEVI(dip)->devi_node_attributes = p;
}

int
i_ndi_get_node_attributes(dev_info_t *dip)
{
	return (DEVI(dip)->devi_node_attributes);
}

void
i_ndi_set_nodeid(dev_info_t *dip, int n)
{
	DEVI(dip)->devi_nodeid = n;
}

void
ndi_set_acc_fault(ddi_acc_handle_t ah)
{
	i_ddi_acc_set_fault(ah);
}

void
ndi_clr_acc_fault(ddi_acc_handle_t ah)
{
	i_ddi_acc_clr_fault(ah);
}

void
ndi_set_dma_fault(ddi_dma_handle_t dh)
{
	i_ddi_dma_set_fault(dh);
}

void
ndi_clr_dma_fault(ddi_dma_handle_t dh)
{
	i_ddi_dma_clr_fault(dh);
}

/*
 *  The default fault-handler, called when the event posted by
 *  ddi_dev_report_fault() reaches rootnex.
 */
static void
i_ddi_fault_handler(dev_info_t *dip, struct ddi_fault_event_data *fedp)
{
	ASSERT(fedp);

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (!DEVI_IS_DEVICE_OFFLINE(dip)) {
		switch (fedp->f_impact) {
		case DDI_SERVICE_LOST:
			DEVI_SET_DEVICE_DOWN(dip);
			break;

		case DDI_SERVICE_DEGRADED:
			DEVI_SET_DEVICE_DEGRADED(dip);
			break;

		case DDI_SERVICE_UNAFFECTED:
		default:
			break;

		case DDI_SERVICE_RESTORED:
			DEVI_SET_DEVICE_UP(dip);
			break;
		}
	}
	mutex_exit(&(DEVI(dip)->devi_lock));
}

/*
 * The default fault-logger, called when the event posted by
 * ddi_dev_report_fault() reaches rootnex.
 */
/*ARGSUSED*/
static void
i_ddi_fault_logger(dev_info_t *rdip, struct ddi_fault_event_data *fedp)
{
	ddi_devstate_t newstate;
	const char *action;
	const char *servstate;
	const char *location;
	int bad;
	int changed;
	int level;
	int still;

	ASSERT(fedp);

	bad = 0;
	switch (fedp->f_location) {
	case DDI_DATAPATH_FAULT:
		location = "in datapath to";
		break;
	case DDI_DEVICE_FAULT:
		location = "in";
		break;
	case DDI_EXTERNAL_FAULT:
		location = "external to";
		break;
	default:
		location = "somewhere near";
		bad = 1;
		break;
	}

	newstate = ddi_get_devstate(fedp->f_dip);
	switch (newstate) {
	case DDI_DEVSTATE_OFFLINE:
		servstate = "unavailable";
		break;
	case DDI_DEVSTATE_DOWN:
		servstate = "unavailable";
		break;
	case DDI_DEVSTATE_QUIESCED:
		servstate = "suspended";
		break;
	case DDI_DEVSTATE_DEGRADED:
		servstate = "degraded";
		break;
	default:
		servstate = "available";
		break;
	}

	changed = (newstate != fedp->f_oldstate);
	level = (newstate < fedp->f_oldstate) ? CE_WARN : CE_NOTE;
	switch (fedp->f_impact) {
	case DDI_SERVICE_LOST:
	case DDI_SERVICE_DEGRADED:
	case DDI_SERVICE_UNAFFECTED:
		/* fault detected; service [still] <servstate> */
		action = "fault detected";
		still = !changed;
		break;

	case DDI_SERVICE_RESTORED:
		if (newstate != DDI_DEVSTATE_UP) {
			/* fault cleared; service still <servstate> */
			action = "fault cleared";
			still = 1;
		} else if (changed) {
			/* fault cleared; service <servstate> */
			action = "fault cleared";
			still = 0;
		} else {
			/* no fault; service <servstate> */
			action = "no fault";
			still = 0;
		}
		break;

	default:
		bad = 1;
		break;
	}

	cmn_err(level, "!%s%d: %s %s device; service %s%s"+(bad|changed),
	    ddi_driver_name(fedp->f_dip), ddi_get_instance(fedp->f_dip),
	    bad ? "invalid report of fault" : action,
	    location, still ? "still " : "", servstate);

	cmn_err(level, "!%s%d: %s"+(bad|changed),
	    ddi_driver_name(fedp->f_dip), ddi_get_instance(fedp->f_dip),
	    fedp->f_message);
}

/*
 * Platform-settable pointers to fault handler and logger functions.
 * These are called by the default rootnex event-posting code when
 * a fault event reaches rootnex.
 */
void (*plat_fault_handler)(dev_info_t *, struct ddi_fault_event_data *) =
	i_ddi_fault_handler;
void (*plat_fault_logger)(dev_info_t *, struct ddi_fault_event_data *) =
	i_ddi_fault_logger;

/*
 * Rootnex event definitions ...
 */
enum rootnex_event_tags {
	ROOTNEX_FAULT_EVENT
};
static ndi_event_hdl_t rootnex_event_hdl;
static ndi_event_definition_t rootnex_event_set[] = {
	{
		ROOTNEX_FAULT_EVENT,
		DDI_DEVI_FAULT_EVENT,
		EPL_INTERRUPT,
		NDI_EVENT_POST_TO_ALL
	}
};
static ndi_event_set_t rootnex_events = {
	NDI_EVENTS_REV1,
	sizeof (rootnex_event_set) / sizeof (rootnex_event_set[0]),
	rootnex_event_set
};

/*
 * Initialize rootnex event handle
 */
void
i_ddi_rootnex_init_events(dev_info_t *dip)
{
	if (ndi_event_alloc_hdl(dip, (ddi_iblock_cookie_t)(LOCK_LEVEL-1),
	    &rootnex_event_hdl, NDI_SLEEP) == NDI_SUCCESS) {
		if (ndi_event_bind_set(rootnex_event_hdl,
		    &rootnex_events, NDI_SLEEP) != NDI_SUCCESS) {
			(void) ndi_event_free_hdl(rootnex_event_hdl);
			rootnex_event_hdl = NULL;
		}
	}
}

/*
 *      Event-handling functions for rootnex
 *      These provide the standard implementation of fault handling
 */
/*ARGSUSED*/
int
i_ddi_rootnex_get_eventcookie(dev_info_t *dip, dev_info_t *rdip,
	char *eventname, ddi_eventcookie_t *cookiep)
{
	if (rootnex_event_hdl == NULL)
		return (NDI_FAILURE);
	return (ndi_event_retrieve_cookie(rootnex_event_hdl, rdip, eventname,
	    cookiep, NDI_EVENT_NOPASS));
}

/*ARGSUSED*/
int
i_ddi_rootnex_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
	ddi_eventcookie_t eventid, void (*handler)(dev_info_t *dip,
	ddi_eventcookie_t event, void *arg, void *impl_data), void *arg,
	ddi_callback_id_t *cb_id)
{
	if (rootnex_event_hdl == NULL)
		return (NDI_FAILURE);
	return (ndi_event_add_callback(rootnex_event_hdl, rdip,
	    eventid, handler, arg, NDI_SLEEP, cb_id));
}

/*ARGSUSED*/
int
i_ddi_rootnex_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{
	if (rootnex_event_hdl == NULL)
		return (NDI_FAILURE);

	return (ndi_event_remove_callback(rootnex_event_hdl, cb_id));
}

/*ARGSUSED*/
int
i_ddi_rootnex_post_event(dev_info_t *dip, dev_info_t *rdip,
	ddi_eventcookie_t eventid, void *impl_data)
{
	int tag;

	if (rootnex_event_hdl == NULL)
		return (NDI_FAILURE);

	tag = ndi_event_cookie_to_tag(rootnex_event_hdl, eventid);
	if (tag == ROOTNEX_FAULT_EVENT) {
		(*plat_fault_handler)(rdip, impl_data);
		(*plat_fault_logger)(rdip, impl_data);
	}
	return (ndi_event_run_callbacks(rootnex_event_hdl, rdip,
	    eventid, impl_data));
}

/*
 * ndi_set_bus_private/ndi_get_bus_private:
 * Get/set device bus private data in devinfo.
 */
void
ndi_set_bus_private(dev_info_t *dip, boolean_t up, uint32_t port_type,
    void *data)
{
	if (up) {
		DEVI(dip)->devi_bus.port_up.info.port.type = port_type;
		DEVI(dip)->devi_bus.port_up.priv_p = data;
	} else {
		DEVI(dip)->devi_bus.port_down.info.port.type = port_type;
		DEVI(dip)->devi_bus.port_down.priv_p = data;
	}
}

void *
ndi_get_bus_private(dev_info_t *dip, boolean_t up)
{
	if (up)
		return (DEVI(dip)->devi_bus.port_up.priv_p);
	else
		return (DEVI(dip)->devi_bus.port_down.priv_p);
}

boolean_t
ndi_port_type(dev_info_t *dip, boolean_t up, uint32_t port_type)
{
	if (up) {
		return ((DEVI(dip)->devi_bus.port_up.info.port.type) ==
		    port_type);
	} else {
		return ((DEVI(dip)->devi_bus.port_down.info.port.type) ==
		    port_type);
	}
}

/* Interfaces for 'self' to set/get a child's flavor */
void
ndi_flavor_set(dev_info_t *child, ndi_flavor_t child_flavor)
{
	DEVI(child)->devi_flavor = child_flavor;
}

ndi_flavor_t
ndi_flavor_get(dev_info_t *child)
{
	return (DEVI(child)->devi_flavor);
}

/*
 * Interfaces to maintain flavor-specific private data of flavored
 * children of self.
 *
 * The flavor count always includes the default (0) vanilla flavor,
 * but storage for the vanilla flavor data pointer is in the same
 * place that ddi_[sg]et_driver_private uses, so the flavorv
 * storage is just for flavors 1..{nflavors-1}.
 */
void
ndi_flavorv_alloc(dev_info_t *self, int nflavors)
{
	ASSERT(nflavors > 0 && (DEVI(self)->devi_flavorv == NULL ||
	    nflavors == DEVI(self)->devi_flavorv_n));
	if (nflavors <= 1 || (DEVI(self)->devi_flavorv)) {
		return;
	}
	DEVI(self)->devi_flavorv =
	    kmem_zalloc((nflavors - 1) * sizeof (void *), KM_SLEEP);
	DEVI(self)->devi_flavorv_n = nflavors;
}

void
ndi_flavorv_set(dev_info_t *self, ndi_flavor_t child_flavor, void *v)
{
	if (child_flavor == NDI_FLAVOR_VANILLA) {
		ddi_set_driver_private(self, v);
	} else {
		ASSERT(child_flavor < DEVI(self)->devi_flavorv_n &&
		    DEVI(self)->devi_flavorv != NULL);
		if (child_flavor > DEVI(self)->devi_flavorv_n ||
		    DEVI(self)->devi_flavorv == NULL) {
			return;
		}
		DEVI(self)->devi_flavorv[child_flavor - 1] = v;
	}
}

void	*
ndi_flavorv_get(dev_info_t *self, ndi_flavor_t child_flavor)
{
	if (child_flavor == NDI_FLAVOR_VANILLA) {
		return (ddi_get_driver_private(self));
	} else {
		ASSERT(child_flavor < DEVI(self)->devi_flavorv_n &&
		    DEVI(self)->devi_flavorv != NULL);
		if (child_flavor > DEVI(self)->devi_flavorv_n ||
		    DEVI(self)->devi_flavorv == NULL) {
			return (NULL);
		}
		return (DEVI(self)->devi_flavorv[child_flavor - 1]);
	}
}
